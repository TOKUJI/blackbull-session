"""Signed-cookie session extension for BlackBull (HMAC-SHA256).

See the package README for a high-level description and the design
trade-offs.  This module contains:

* ``SessionExtension`` — the public extension class following BlackBull's
  ``init_app(app)`` convention.  ``SessionExtension(app, secret=...)``
  registers the session middleware on the application and the live
  instance at ``app.extensions['session']``.
* ``_SessionDict`` — internal ``dict`` subclass that flips a flag when
  mutated so the middleware knows whether to emit ``Set-Cookie``.

Wire format (Base64URL-encoded payload + "." + hex MAC)::

    <urlsafe-b64-no-padding(json-bytes)>.<hex-hmac-sha256(json-bytes)>

The cookie is dispatched on every response that touched
``scope['session']`` in a way that modified it (see ``_SessionDict``);
unmodified sessions trigger no ``Set-Cookie`` header, so a 304 /
cache-friendly response stays cache-friendly.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time

from blackbull.asgi import ASGIEvent
from blackbull.middleware import as_middleware

logger = logging.getLogger(__name__)


class _SessionDict(dict):
    """``dict`` subclass that flips a flag the moment it's mutated.

    The session middleware uses ``_modified`` to decide whether to emit
    ``Set-Cookie`` on the response; an untouched session — even one we
    successfully read off the request — leaves the response alone.
    """
    __slots__ = ('_modified',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._modified = False

    def __setitem__(self, key, value):
        self._modified = True
        super().__setitem__(key, value)

    def __delitem__(self, key):
        self._modified = True
        super().__delitem__(key)

    def clear(self):
        if self:
            self._modified = True
        super().clear()

    def pop(self, key, *default):
        if key in self:
            self._modified = True
        return super().pop(key, *default)

    def popitem(self):
        self._modified = True
        return super().popitem()

    def update(self, *args, **kwargs):
        before = dict(self)
        super().update(*args, **kwargs)
        if self != before:
            self._modified = True

    def setdefault(self, key, default=None):
        if key not in self:
            self._modified = True
        return super().setdefault(key, default)


# RFC 6265 §4.1.2 — SameSite values.  Python ``None`` means we don't emit
# the attribute at all (modern browsers default to ``Lax`` anyway).
_VALID_SAMESITE = ('Strict', 'Lax', 'None')


@as_middleware
class SessionExtension:
    """Signed-cookie session extension for a BlackBull app.

    Two construction styles are supported, following the framework's
    ``init_app(app)`` extension convention:

    >>> # Eager — wire on construction.
    >>> SessionExtension(app, secret=b'...')

    >>> # Deferred — useful when the app is configured elsewhere.
    >>> ext = SessionExtension(secret=b'...')
    >>> ext.init_app(app)

    After ``init_app``:

    * ``app.extensions['session']`` is *self* — collaborators can read
      the configured ``cookie_name``/``max_age``/etc. from it.
    * The middleware is registered via ``app.use(self)``; the extension
      instance is itself the ASGI middleware callable.

    Parameters
    ----------
    app:
        Optional BlackBull app for eager wiring.  When provided,
        ``init_app(app)`` is called from the constructor.
    secret:
        The HMAC key (``bytes`` or ``str``).  When omitted,
        ``BB_SESSION_SECRET`` is read from the environment.  A
        missing / empty secret raises at construction — no insecure
        default.
    cookie_name:
        Name of the cookie carrying the session payload.  Default
        ``'session'``.
    max_age:
        Cookie ``Max-Age`` in seconds.  When set, the cookie is signed
        with a server-side timestamp; values older than ``max_age``
        seconds are treated as expired (empty session).  ``None`` means
        a session cookie that lives only as long as the browser is open.
    secure:
        Set the ``Secure`` attribute so the cookie is only sent over
        HTTPS.  Default ``True``; set ``False`` for local-only dev.
    httponly:
        Set the ``HttpOnly`` attribute (JavaScript can't read the
        cookie).  Default ``True``.
    samesite:
        ``'Strict'`` / ``'Lax'`` / ``'None'`` (RFC strings) or Python
        ``None`` to omit the attribute.  Default ``'Lax'``.
    path:
        Cookie ``Path``.  Default ``/``.
    """
    #: Key under which the extension registers itself in
    #: ``app.extensions``.  Follows the ``blackbull-<name>`` →
    #: ``<name>`` convention; not configurable to avoid a
    #: collision-bypass loophole.
    extension_key: str = 'session'

    # 4 KiB is the practical browser cap on a single cookie; we warn
    # (don't reject) above this so a slowly-growing session doesn't fail
    # silently in production.
    _COOKIE_WARN_SIZE = 4000

    def __init__(
        self,
        app: object | None = None,
        secret: bytes | str | None = None,
        *,
        cookie_name: str = 'session',
        max_age: int | None = None,
        secure: bool = True,
        httponly: bool = True,
        samesite: str | None = 'Lax',
        path: str = '/',
    ):
        if secret is None:
            secret = os.environ.get('BB_SESSION_SECRET')
        if not secret:
            raise RuntimeError(
                'SessionExtension requires a secret.  Either pass '
                'secret=... to the constructor or set the BB_SESSION_SECRET '
                'environment variable.  Generate one with e.g. '
                '``python -c "import secrets; print(secrets.token_urlsafe(32))"``.'
            )
        if samesite is not None and samesite not in _VALID_SAMESITE:
            raise ValueError(
                f'samesite must be one of {_VALID_SAMESITE} or None; '
                f'got {samesite!r}')
        self._secret = secret if isinstance(secret, bytes) else secret.encode()
        self._cookie_name = cookie_name
        self._cookie_name_b = cookie_name.encode()
        self._max_age = max_age
        self._secure = secure
        self._httponly = httponly
        self._samesite = samesite
        self._path = path
        if app is not None:
            self.init_app(app)

    def init_app(self, app) -> None:
        """Wire the session middleware onto *app* through the public API."""
        existing = app.extensions.get(self.extension_key)
        if existing is not None and existing is not self:
            existing_origin = type(existing).__module__
            raise RuntimeError(
                f"app.extensions[{self.extension_key!r}] is already registered "
                f"by {existing_origin}. Cannot initialise "
                f"{type(self).__module__}.{type(self).__name__}.")
        app.use(self)
        app.extensions[self.extension_key] = self

    # ----- middleware --------------------------------------------------

    async def __call__(self, scope, receive, send, call_next):
        if scope.get('type') not in ('http', 'websocket'):
            await call_next(scope, receive, send)
            return

        session = _SessionDict(self._load(scope))
        scope['session'] = session

        # WebSocket scopes get a read-only session view — there's no
        # response.start to mutate.
        if scope.get('type') == 'websocket':
            await call_next(scope, receive, send)
            return

        async def wrapped_send(event):
            # The ``@as_middleware`` class decorator normalises
            # ``call_next`` so any Response / JSONResponse from the
            # handler arrives here as a plain dict event.
            if (event.get('type') == ASGIEvent.HTTP_RESPONSE_START
                    and session._modified):
                headers = list(event.get('headers', []))
                cookie = self._make_cookie(session)
                if len(cookie) > self._COOKIE_WARN_SIZE:
                    logger.warning(
                        'session cookie is %d bytes — most browsers cap at '
                        '~4 KiB.  Consider moving large state to a server-side '
                        'store.', len(cookie))
                headers.append((b'set-cookie', cookie))
                event = {**event, 'headers': headers}
            await send(event)

        await call_next(scope, receive, wrapped_send)

    # ----- read --------------------------------------------------------

    def _load(self, scope) -> dict:
        cookie_header = self._cookie_header(scope)
        if not cookie_header:
            return {}
        cookies = _parse_cookie_header(cookie_header)
        raw = cookies.get(self._cookie_name_b)
        if raw is None:
            return {}
        return self._decode(raw)

    @staticmethod
    def _cookie_header(scope) -> bytes:
        for name, value in scope.get('headers', []):
            if name.lower() == b'cookie':
                return value
        return b''

    def _decode(self, raw: bytes) -> dict:
        """Verify the HMAC and decode the JSON payload.  Empty dict on any failure."""
        payload_b64, sep, mac_hex = raw.partition(b'.')
        if not sep or not payload_b64 or not mac_hex:
            return {}
        try:
            # Re-add base64 padding (stripped on encode) and decode.
            pad = b'=' * (-len(payload_b64) % 4)
            payload = base64.urlsafe_b64decode(payload_b64 + pad)
        except (ValueError, _binascii_error_class()):
            return {}
        expected = hmac.new(self._secret, payload, hashlib.sha256).hexdigest().encode()
        # Constant-time comparison so we don't leak length / prefix info.
        if not hmac.compare_digest(expected, mac_hex):
            return {}
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        if self._max_age is not None:
            ts = data.pop('_ts', None)
            if not isinstance(ts, (int, float)) or time.time() - ts > self._max_age:
                return {}
        return data

    # ----- write -------------------------------------------------------

    def _encode(self, session: dict) -> bytes:
        data = dict(session)
        if self._max_age is not None:
            data['_ts'] = int(time.time())
        payload = json.dumps(data, separators=(',', ':'), sort_keys=True).encode()
        mac = hmac.new(self._secret, payload, hashlib.sha256).hexdigest().encode()
        payload_b64 = base64.urlsafe_b64encode(payload).rstrip(b'=')
        return payload_b64 + b'.' + mac

    def _make_cookie(self, session: dict) -> bytes:
        """Build the ``Set-Cookie`` value, including all attribute flags."""
        if session:
            value = self._encode(session)
        else:
            # An emptied session → tell the browser to drop the cookie.
            # Max-Age=0 + Expires in the past = robust deletion across browsers.
            value = b''
        parts = [self._cookie_name_b + b'=' + value]
        parts.append(b'Path=' + self._path.encode())
        if not session:
            parts.append(b'Max-Age=0')
        elif self._max_age is not None:
            parts.append(b'Max-Age=' + str(self._max_age).encode())
        if self._secure:
            parts.append(b'Secure')
        if self._httponly:
            parts.append(b'HttpOnly')
        if self._samesite is not None:
            parts.append(b'SameSite=' + self._samesite.encode())
        return b'; '.join(parts)


# ---------------------------------------------------------------------------
# Cookie header parsing (RFC 6265 §4.2.1 — tolerant of real-world clients)
# ---------------------------------------------------------------------------

def _parse_cookie_header(header: bytes) -> dict[bytes, bytes]:
    """Decode a ``Cookie:`` request header into ``{name: value}`` pairs."""
    out: dict[bytes, bytes] = {}
    for piece in header.split(b';'):
        piece = piece.strip()
        if not piece or b'=' not in piece:
            continue
        name, _, value = piece.partition(b'=')
        name = name.strip()
        if name not in out:
            out[name] = value.strip()
    return out


def _binascii_error_class():
    """Return ``binascii.Error`` lazily — avoids a top-level import."""
    import binascii  # noqa: PLC0415
    return binascii.Error
