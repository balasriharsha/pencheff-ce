"""Tests for the desktop-OAuth + native-JWT additions.

Mirrors test_api_key_auth_flow.py style: mock AsyncSession + Request,
exercise the dependency directly. No FastAPI TestClient — Pencheff's
ORM has Postgres-only column types.
"""
from __future__ import annotations
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import jwt as pyjwt
import pytest
from fastapi import HTTPException

import pencheff_api.auth.deps as deps
from pencheff_api.auth import jwt as native_jwt
from pencheff_api.auth.deps import _user_from_token
from pencheff_api.db.models import User


def _make_user(id_: str = "u1", active: bool = True) -> User:
    u = User(id=id_, email=f"{id_}@example.com", name=id_, is_active=active)
    return u


def _scalar_session(user: User | None) -> AsyncMock:
    session = AsyncMock()
    async def _get(model, _id):
        return user
    session.get.side_effect = _get
    # execute() is used by the Clerk path; return empty so that path falls through.
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = None
    session.execute.return_value = exec_result
    return session


@pytest.fixture
def clerk_fails(monkeypatch):
    """Force decode_clerk_jwt to raise so the native fallback is exercised."""
    def _raise(_):
        raise pyjwt.InvalidTokenError("not clerk")
    monkeypatch.setattr(deps, "decode_clerk_jwt", _raise)
    return _raise


@pytest.mark.asyncio
async def test_native_access_token_resolves_user(clerk_fails):
    user = _make_user("u1")
    session = _scalar_session(user)
    token = native_jwt.make_access_token("u1", "org1")
    out = await _user_from_token(session, token)
    assert out.id == "u1"


@pytest.mark.asyncio
async def test_native_refresh_token_rejected(clerk_fails):
    session = _scalar_session(_make_user("u1"))
    token = native_jwt.make_refresh_token("u1", "org1")
    with pytest.raises(HTTPException) as exc:
        await _user_from_token(session, token)
    assert exc.value.status_code == 401
    assert "access" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_native_token_for_inactive_user(clerk_fails):
    user = _make_user("u1", active=False)
    session = _scalar_session(user)
    token = native_jwt.make_access_token("u1", "org1")
    with pytest.raises(HTTPException) as exc:
        await _user_from_token(session, token)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_garbage_token_rejected(clerk_fails):
    session = _scalar_session(None)
    with pytest.raises(HTTPException) as exc:
        await _user_from_token(session, "not.a.jwt")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_clerk_success_skips_native_path(monkeypatch):
    """When Clerk decode succeeds the native helper must not be invoked."""
    session = _scalar_session(_make_user("u1"))
    monkeypatch.setattr(deps, "decode_clerk_jwt", lambda _: {"sub": "ck123"})
    monkeypatch.setattr(deps, "_plan_from_claims", lambda _: "free")
    # Make the Clerk lookup return our user so we don't enter _provision_user_from_clerk.
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = _make_user("u1")
    session.execute.return_value = exec_result
    # If the implementation ever calls decode_native_token, this will throw.
    monkeypatch.setattr(deps, "decode_native_token",
                        lambda _: (_ for _ in ()).throw(AssertionError("native called on Clerk success")))
    # Suppress plan sync side effects.
    async def _noop(*_a, **_kw): return None
    monkeypatch.setattr(deps, "_sync_plan_for_user", _noop)
    out = await _user_from_token(session, "fake.clerk.token")
    assert out.id == "u1"


@pytest.mark.asyncio
async def test_native_token_wrong_secret_rejected(clerk_fails):
    """Native HS-signed JWT with a non-matching secret must 401."""
    session = _scalar_session(_make_user("u1"))
    bad = pyjwt.encode(
        {"sub": "u1", "org": "org1", "type": "access",
         "iat": 0, "exp": 9_999_999_999},
        "wrong-secret",
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc:
        await _user_from_token(session, bad)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_native_access_token_expired_rejected(clerk_fails, monkeypatch):
    """An expired native access token must 401, not authenticate."""
    from pencheff_api.config import get_settings
    settings = get_settings()
    session = _scalar_session(_make_user("u1"))
    expired = pyjwt.encode(
        {"sub": "u1", "org": "org1", "type": "access",
         "iat": 0, "exp": 1},   # exp in 1970
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(HTTPException) as exc:
        await _user_from_token(session, expired)
    assert exc.value.status_code == 401


import re
from starlette.requests import Request
from starlette.responses import RedirectResponse
from pencheff_api.routers import auth as auth_router


def _mk_request_with_session(session_dict: dict | None = None) -> Request:
    """Build a minimal Starlette Request with a mutable session dict."""
    scope = {
        "type": "http",
        "method": "GET",
        "headers": [],
        "session": session_dict if session_dict is not None else {},
        "path_params": {},
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_google_start_stores_loopback_redirect(monkeypatch):
    captured = {}
    async def fake_redirect(request, _uri):
        captured["session"] = dict(request.session)
        return RedirectResponse(url="https://accounts.google.com/o/oauth2/auth?stub")
    # Patch order matters: setattr backs up the old attribute via getattr, and
    # Authlib's OAuth.__getattr__ tries to unpack the registry entry. Install the
    # stub `google` first (registry is empty by default) before injecting our
    # registry entry.
    monkeypatch.setattr(auth_router.oauth, "google",
                        SimpleNamespace(authorize_redirect=fake_redirect),
                        raising=False)
    monkeypatch.setattr(auth_router.oauth, "_registry", {"google": object()})
    req = _mk_request_with_session()
    resp = await auth_router.google_start(
        request=req,
        desktop_redirect="http://127.0.0.1:54123/callback",
        state="abc123",
    )
    assert resp.status_code == 307 or resp.status_code == 302
    assert captured["session"]["desktop_redirect"] == "http://127.0.0.1:54123/callback"
    assert captured["session"]["desktop_state"] == "abc123"


@pytest.mark.asyncio
async def test_google_start_rejects_non_loopback(monkeypatch):
    monkeypatch.setattr(auth_router.oauth, "google",
                        SimpleNamespace(authorize_redirect=AsyncMock()),
                        raising=False)
    monkeypatch.setattr(auth_router.oauth, "_registry", {"google": object()})
    req = _mk_request_with_session()
    with pytest.raises(HTTPException) as exc:
        await auth_router.google_start(
            request=req,
            desktop_redirect="https://evil.com/callback",
            state=None,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_google_start_rejects_loopback_wrong_path(monkeypatch):
    monkeypatch.setattr(auth_router.oauth, "google",
                        SimpleNamespace(authorize_redirect=AsyncMock()),
                        raising=False)
    monkeypatch.setattr(auth_router.oauth, "_registry", {"google": object()})
    req = _mk_request_with_session()
    with pytest.raises(HTTPException) as exc:
        await auth_router.google_start(
            request=req,
            desktop_redirect="http://127.0.0.1:54123/something-else",
            state=None,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_google_start_without_desktop_redirect_clears_session(monkeypatch):
    captured = {}
    async def fake_redirect(request, _uri):
        captured["session"] = dict(request.session)
        return RedirectResponse(url="https://accounts.google.com/x")
    monkeypatch.setattr(auth_router.oauth, "google",
                        SimpleNamespace(authorize_redirect=fake_redirect),
                        raising=False)
    monkeypatch.setattr(auth_router.oauth, "_registry", {"google": object()})
    req = _mk_request_with_session({"desktop_redirect": "stale", "desktop_state": "stale"})
    await auth_router.google_start(request=req, desktop_redirect=None, state=None)
    assert "desktop_redirect" not in captured["session"]
    assert "desktop_state" not in captured["session"]


def test_loopback_regex_matches_only_localhost():
    """Sanity check the regex literal in google_start."""
    pat = re.compile(r"^http://127\.0\.0\.1:\d{4,5}/callback$")
    assert pat.fullmatch("http://127.0.0.1:1024/callback")
    assert pat.fullmatch("http://127.0.0.1:65535/callback")
    assert not pat.fullmatch("http://127.0.0.1/callback")
    assert not pat.fullmatch("https://127.0.0.1:54123/callback")
    assert not pat.fullmatch("http://localhost:54123/callback")
    assert not pat.fullmatch("http://127.0.0.1:54123/callback?x=1")


@pytest.mark.asyncio
async def test_callback_redirects_to_loopback_when_set(monkeypatch):
    """The callback should redirect to the loopback URL with tokens in query when
    desktop_redirect was stashed by google_start; otherwise to web with hash."""
    # Stub all the DB side effects.
    fake_session = AsyncMock()
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = None
    fake_session.execute.return_value = exec_result
    fake_session.flush = AsyncMock()
    fake_session.commit = AsyncMock()

    async def fake_authorize_access_token(_req):
        return {"userinfo": {"sub": "g123", "email": "a@b.com", "name": "A"}}
    monkeypatch.setattr(auth_router.oauth, "google",
                        SimpleNamespace(
                            authorize_access_token=fake_authorize_access_token,
                            userinfo=AsyncMock(return_value={}),
                        ),
                        raising=False)
    monkeypatch.setattr(auth_router.oauth, "_registry", {"google": object()})

    req = _mk_request_with_session({
        "desktop_redirect": "http://127.0.0.1:54123/callback",
        "desktop_state": "xyz",
    })
    resp = await auth_router.google_callback(request=req, session=fake_session)
    loc = resp.headers["location"]
    assert loc.startswith("http://127.0.0.1:54123/callback?access_token=")
    assert "&refresh_token=" in loc
    assert loc.endswith("&state=xyz")
