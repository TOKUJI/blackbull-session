# blackbull-session

Signed-cookie session extension for the [BlackBull](https://github.com/TOKUJI/BlackBull) ASGI framework.

> ⚠ **Early Alpha — API may break between MINOR versions.**

[![PyPI](https://img.shields.io/pypi/v/blackbull-session.svg)](https://pypi.org/project/blackbull-session/)
[![Python](https://img.shields.io/pypi/pyversions/blackbull-session.svg)](https://pypi.org/project/blackbull-session/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## What this is

A session layer for BlackBull apps.  The entire session payload lives in the cookie sent to the client; the server keeps no per-session state.  Every value the client could otherwise tamper with is HMAC-signed by a secret the server alone knows, so:

- a client that modifies the cookie sees the next request treated as a fresh empty session (signature check fails),
- the server never reads, writes, or replays anything else — no DB hit, no Redis round-trip, no in-process dict to keep consistent across workers,
- sessions survive worker restarts / horizontal scaling for free (any worker that knows the secret can validate any cookie).

The trade-offs compared with server-side session stores:

- Cookie size is bounded (browsers cap to ~4 KiB, often less in practice).  Sessions storing large objects don't fit.
- No server-side invalidation: revoking a cookie before it expires requires either rotating the secret (kills every session) or a separate revocation list.  Acceptable for many apps; if you need fine-grained revocation, pick a server-side session store instead.

## Install

```bash
pip install blackbull-session
```

## Use

```python
import os
from blackbull import BlackBull
from blackbull_session import SessionExtension

app = BlackBull()

# Eager — wire on construction.
SessionExtension(app, secret=os.environ['BB_SESSION_SECRET'])

# Or deferred — useful when the app is configured elsewhere.
session = SessionExtension(secret=os.environ['BB_SESSION_SECRET'])
session.init_app(app)

@app.route(path='/')
async def index(scope, receive, send):
    user = scope['session'].get('user')
    scope['session']['hits'] = scope['session'].get('hits', 0) + 1
    await send(...)
```

After `init_app(app)`, the live extension is reachable at `app.extensions['session']`.

## Configuration

| Parameter | Default | Notes |
|---|---|---|
| `secret` | reads `BB_SESSION_SECRET` | Required.  HMAC-SHA256 key (`bytes` or `str`).  Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. |
| `cookie_name` | `'session'` | Cookie name carrying the payload. |
| `max_age` | `None` | When set (seconds), the cookie is signed with a server-side timestamp; older payloads are treated as expired.  `None` means a session cookie that lives only as long as the browser is open. |
| `secure` | `True` | `Secure` attribute — cookie sent only over HTTPS. |
| `httponly` | `True` | `HttpOnly` attribute — JavaScript can't read the cookie. |
| `samesite` | `'Lax'` | `Strict` / `Lax` / `None` (string), or Python `None` to omit the attribute entirely. |
| `path` | `'/'` | Cookie `Path` attribute. |

## How it fits

`blackbull-session` is a reference third-party extension that follows the [`init_app(app)` convention](https://github.com/TOKUJI/BlackBull/blob/master/docs/guide/extensions.md) — the same convention BlackBull's own in-tree `OpenAPIExtension` uses.  It exists partly to validate that the convention works for external packages without modifications.

## License

[Apache License 2.0](LICENSE) — © TOKUJI.
