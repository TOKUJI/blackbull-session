"""Smoke tests for ``blackbull_session.SessionExtension``.

These exercise the extension contract (init_app, app.extensions
registration, collision check) and a round-trip of the cookie wire
format.  Full middleware coverage lives in the BlackBull repo's
integration suite while the deprecation shim is still in place; it
will be ported here once the shim is removed.
"""
from __future__ import annotations

import pytest

from blackbull import BlackBull
from blackbull_session import SessionExtension


SECRET = b'unit-test-secret-not-for-production-use'


def test_extension_key_is_session():
    assert SessionExtension.extension_key == 'session'


def test_missing_secret_raises(monkeypatch):
    monkeypatch.delenv('BB_SESSION_SECRET', raising=False)
    with pytest.raises(RuntimeError, match='requires a secret'):
        SessionExtension()


def test_invalid_samesite_raises():
    with pytest.raises(ValueError, match='samesite must be'):
        SessionExtension(secret=SECRET, samesite='wrong')


def test_deferred_init_app_registers_under_session_key():
    app = BlackBull()
    ext = SessionExtension(secret=SECRET)
    assert 'session' not in app.extensions
    ext.init_app(app)
    assert app.extensions['session'] is ext


def test_eager_construction_registers_at_init():
    app = BlackBull()
    ext = SessionExtension(app, secret=SECRET)
    assert app.extensions['session'] is ext


def test_second_init_app_on_same_instance_is_idempotent():
    app = BlackBull()
    ext = SessionExtension(app, secret=SECRET)
    # Calling init_app twice on the *same* instance should not raise —
    # it's the same registration.
    ext.init_app(app)
    assert app.extensions['session'] is ext


def test_collision_with_different_instance_raises():
    app = BlackBull()
    SessionExtension(app, secret=SECRET)
    second = SessionExtension(secret=SECRET)
    with pytest.raises(RuntimeError, match=r"app.extensions\['session'\]"):
        second.init_app(app)


def test_cookie_roundtrip_signed_payload():
    """Encode then decode — values survive the wire format."""
    ext = SessionExtension(secret=SECRET)
    cookie = ext._encode({'user': 'alice', 'count': 3})
    decoded = ext._decode(cookie)
    assert decoded == {'user': 'alice', 'count': 3}


def test_cookie_with_tampered_payload_returns_empty():
    """Bit-flipped payload → empty dict (signature check fails)."""
    ext = SessionExtension(secret=SECRET)
    cookie = ext._encode({'user': 'alice'})
    # Flip a byte in the payload portion.
    payload, dot, mac = cookie.partition(b'.')
    tampered = payload[:-1] + bytes([payload[-1] ^ 0x01]) + dot + mac
    assert ext._decode(tampered) == {}


def test_cookie_with_wrong_secret_returns_empty():
    """Different secret → empty dict."""
    a = SessionExtension(secret=SECRET)
    b = SessionExtension(secret=b'a-different-secret-also-not-for-prod')
    cookie = a._encode({'user': 'alice'})
    assert b._decode(cookie) == {}


def test_max_age_expires_old_payload():
    """A payload older than max_age is rejected."""
    ext = SessionExtension(secret=SECRET, max_age=1)
    cookie = ext._encode({'user': 'alice'})
    # Wait briefly past max_age.
    import time as _time
    _time.sleep(1.1)
    assert ext._decode(cookie) == {}


def test_set_cookie_attributes_include_secure_httponly_samesite():
    ext = SessionExtension(secret=SECRET)
    cookie = ext._make_cookie({'a': 1})
    assert b'Secure' in cookie
    assert b'HttpOnly' in cookie
    assert b'SameSite=Lax' in cookie
    assert b'Path=/' in cookie


def test_secure_false_omits_secure_flag():
    ext = SessionExtension(secret=SECRET, secure=False)
    cookie = ext._make_cookie({'a': 1})
    assert b'Secure' not in cookie


def test_empty_session_emits_deletion_cookie():
    ext = SessionExtension(secret=SECRET)
    cookie = ext._make_cookie({})
    assert b'Max-Age=0' in cookie
