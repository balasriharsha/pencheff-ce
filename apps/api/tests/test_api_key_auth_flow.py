"""Integration tests for the PENCHEFF_API_KEY auth dependency layer.

These tests exercise ``verify_api_key``, ``require_scope``, and
``session_only`` directly with a mocked AsyncSession + Request. They do
NOT spin up a full FastAPI test DB — Pencheff's ORM uses Postgres-only
column types (UUID, JSONB, ARRAY) that SQLite cannot satisfy. The
smaller surface still catches the security-critical regressions:

- revoked / expired / cross-org / detached-membership keys → 401
- valid key without required scope → 403
- session_only rejects API-keyed callers → 403
- workspace-pinned key + mismatched X-Workspace-Id header → 403
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from pencheff_api.auth.api_key import (
    KEY_PREFIX_SENTINEL,
    PREFIX_LEN,
    generate_key,
    hash_key,
    verify_api_key,
)
from pencheff_api.auth.deps import (
    _resolve_active_workspace,
    require_scope,
    session_only,
)
from pencheff_api.db.models import ApiKey, OrgMember, User, Workspace


# ─── helpers ────────────────────────────────────────────────────────────


def _make_user(*, id_: str = "u1", active: bool = True) -> User:
    u = User(
        id=id_,
        email=f"{id_}@example.test",
        name="Test User",
        is_active=active,
    )
    return u


def _make_member(*, user_id: str = "u1", org_id: str = "org1") -> OrgMember:
    return OrgMember(id="m1", user_id=user_id, org_id=org_id, role="member")


def _make_workspace(*, id_: str = "ws1", org_id: str = "org1") -> Workspace:
    return Workspace(id=id_, org_id=org_id, name="ws", slug="ws")


def _make_key(
    *,
    user_id: str = "u1",
    org_id: str = "org1",
    workspace_id: str | None = None,
    scopes: list[str] | None = None,
    revoked: bool = False,
    expired: bool = False,
) -> tuple[ApiKey, str]:
    full, prefix, digest = generate_key()
    now = datetime.now(timezone.utc)
    row = ApiKey(
        id="ak1",
        user_id=user_id,
        org_id=org_id,
        workspace_id=workspace_id,
        name="test-key",
        prefix=prefix,
        key_hash=digest,
        scopes=scopes or ["scans:read"],
        expires_at=(now - timedelta(days=1)) if expired else None,
        last_used_at=None,
        revoked_at=now if revoked else None,
        created_at=now,
    )
    return row, full


def _scalar_session(
    *,
    api_key: ApiKey | None,
    member: OrgMember | None = None,
    workspace: Workspace | None = None,
    user: User | None = None,
) -> MagicMock:
    """Build an AsyncSession mock returning the given rows from the
    queries ``verify_api_key`` issues, in order:

    1. SELECT ApiKey WHERE prefix = :p     → api_key
    2. session.get(User, ...)              → user
    3. SELECT OrgMember WHERE ...          → member
    4. session.get(Workspace, ...)         → workspace (only when key.workspace_id)
    """
    session = MagicMock()

    # session.execute(stmt) returns an object with .scalar_one_or_none(),
    # called twice in order: api_key lookup, then member lookup.
    execute_returns = [
        SimpleNamespace(scalar_one_or_none=lambda r=api_key: r),
        SimpleNamespace(scalar_one_or_none=lambda r=member: r),
    ]
    session.execute = AsyncMock(side_effect=execute_returns)

    # session.get(User, id) and session.get(Workspace, id).
    async def _get(model, _id):
        if model is User:
            return user
        if model is Workspace:
            return workspace
        return None

    session.get = AsyncMock(side_effect=_get)
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    return session


# ─── verify_api_key ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_rejects_unknown_prefix():
    full = f"{KEY_PREFIX_SENTINEL}xxxxxxxxxxxxxxxxxxxxxxxxxx"
    session = _scalar_session(api_key=None)
    with pytest.raises(HTTPException) as ei:
        await verify_api_key(session, full)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_rejects_token_that_does_not_look_like_key():
    session = MagicMock()
    with pytest.raises(HTTPException) as ei:
        await verify_api_key(session, "eyJalg.payload.sig")
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_rejects_wrong_hash():
    """A known prefix paired with the wrong full token must 401 — no
    timing-side-channel leaked, no message disclosure."""
    row, _correct_full = _make_key()
    # Tamper with the secret part — same prefix, different body.
    bad_full = f"{KEY_PREFIX_SENTINEL}{row.prefix}{'A' * 40}"
    assert hash_key(bad_full) != row.key_hash
    session = _scalar_session(api_key=row, user=_make_user(), member=_make_member())
    with pytest.raises(HTTPException) as ei:
        await verify_api_key(session, bad_full)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_rejects_revoked_key():
    row, full = _make_key(revoked=True)
    session = _scalar_session(api_key=row, user=_make_user(), member=_make_member())
    with pytest.raises(HTTPException) as ei:
        await verify_api_key(session, full)
    assert ei.value.status_code == 401
    assert "revoked" in ei.value.detail.lower()


@pytest.mark.asyncio
async def test_verify_rejects_expired_key():
    row, full = _make_key(expired=True)
    session = _scalar_session(api_key=row, user=_make_user(), member=_make_member())
    with pytest.raises(HTTPException) as ei:
        await verify_api_key(session, full)
    assert ei.value.status_code == 401
    assert "expired" in ei.value.detail.lower()


@pytest.mark.asyncio
async def test_verify_rejects_inactive_user():
    row, full = _make_key()
    session = _scalar_session(
        api_key=row, user=_make_user(active=False), member=_make_member()
    )
    with pytest.raises(HTTPException) as ei:
        await verify_api_key(session, full)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_rejects_detached_membership():
    """If the issuing user has been removed from the key's org, the key
    must 401 immediately — no stale-membership cache."""
    row, full = _make_key()
    session = _scalar_session(api_key=row, user=_make_user(), member=None)
    with pytest.raises(HTTPException) as ei:
        await verify_api_key(session, full)
    assert ei.value.status_code == 401
    assert "member" in ei.value.detail.lower()


@pytest.mark.asyncio
async def test_verify_rejects_cross_org_workspace():
    """If a key's workspace_id no longer belongs to the key's org (which
    would imply org-administrative tampering or a workspace move), the
    key must be invalidated."""
    row, full = _make_key(workspace_id="ws1")
    foreign_ws = _make_workspace(id_="ws1", org_id="another-org")
    session = _scalar_session(
        api_key=row, user=_make_user(), member=_make_member(), workspace=foreign_ws
    )
    with pytest.raises(HTTPException) as ei:
        await verify_api_key(session, full)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_accepts_valid_key_and_updates_last_used():
    row, full = _make_key()
    session = _scalar_session(
        api_key=row, user=_make_user(), member=_make_member(),
    )
    # Pre-condition.
    assert row.last_used_at is None
    api_key, user = await verify_api_key(session, full)
    assert api_key.id == row.id
    assert user.id == "u1"
    # last_used_at is set on success.
    assert api_key.last_used_at is not None
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_debounces_last_used_writes():
    """A second authenticated request inside the debounce window must
    NOT issue another row UPDATE — otherwise a busy CI key would burn a
    write per request."""
    row, full = _make_key()
    # Pretend the previous request just touched it.
    row.last_used_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    pre = row.last_used_at

    session = _scalar_session(
        api_key=row, user=_make_user(), member=_make_member(),
    )
    api_key, _ = await verify_api_key(session, full)
    # Within the debounce window (60 s default) — no commit, timestamp untouched.
    assert api_key.last_used_at == pre
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_verify_writes_last_used_after_debounce_window():
    row, full = _make_key()
    row.last_used_at = datetime.now(timezone.utc) - timedelta(seconds=120)
    pre = row.last_used_at

    session = _scalar_session(
        api_key=row, user=_make_user(), member=_make_member(),
    )
    api_key, _ = await verify_api_key(session, full)
    # Outside the window — write happens, timestamp advances.
    assert api_key.last_used_at > pre
    session.commit.assert_awaited_once()


# ─── require_scope ──────────────────────────────────────────────────────


def _request(*, kind: str, scopes: list[str] | None = None) -> MagicMock:
    req = MagicMock()
    req.state = SimpleNamespace(
        auth_kind=kind,
        api_key_scopes=scopes or [],
    )
    return req


@pytest.mark.asyncio
async def test_require_scope_passes_session_calls_through():
    """Clerk-session callers always pass — their permissions are
    governed by ``require_role``, not scopes."""
    dep = require_scope("scans:write")
    user = _make_user()
    out = await dep(_request(kind="session"), user)
    assert out is user


@pytest.mark.asyncio
async def test_require_scope_403s_api_key_without_scope():
    dep = require_scope("scans:write")
    with pytest.raises(HTTPException) as ei:
        await dep(_request(kind="api_key", scopes=["findings:read"]), _make_user())
    assert ei.value.status_code == 403
    assert "scans:write" in ei.value.detail


@pytest.mark.asyncio
async def test_require_scope_accepts_concrete_match():
    dep = require_scope("scans:write")
    user = _make_user()
    out = await dep(_request(kind="api_key", scopes=["scans:write"]), user)
    assert out is user


@pytest.mark.asyncio
async def test_require_scope_accepts_category_wildcard():
    dep = require_scope("scans:write")
    user = _make_user()
    out = await dep(_request(kind="api_key", scopes=["scans:*"]), user)
    assert out is user


@pytest.mark.asyncio
async def test_require_scope_accepts_full_wildcard():
    dep = require_scope("scans:write")
    user = _make_user()
    out = await dep(_request(kind="api_key", scopes=["*:*"]), user)
    assert out is user


# ─── session_only ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_session_only_passes_session_callers():
    user = _make_user()
    out = await session_only(_request(kind="session"), user)
    assert out is user


@pytest.mark.asyncio
async def test_session_only_403s_api_key_callers():
    """A leaked API key must NOT escalate to /billing/checkout, the
    api-keys CRUD itself, or any other identity-bound concern — even
    when granted ``*:*``."""
    with pytest.raises(HTTPException) as ei:
        await session_only(
            _request(kind="api_key", scopes=["*:*"]),
            _make_user(),
        )
    assert ei.value.status_code == 403
    assert "session" in ei.value.detail.lower()


# ─── workspace pinning ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_workspace_pinned_key_rejects_mismatched_header():
    """A workspace-pinned key with ``X-Workspace-Id: <other>`` must 403."""
    request = MagicMock()
    request.state = SimpleNamespace(
        auth_kind="api_key",
        api_key_org_id="org1",
        api_key_workspace_id="ws1",
    )
    request.headers = {"x-workspace-id": "ws2"}
    request.query_params = {}
    session = MagicMock()
    session.get = AsyncMock(return_value=_make_workspace(id_="ws1", org_id="org1"))

    with pytest.raises(HTTPException) as ei:
        await _resolve_active_workspace(request, _make_user(), session)
    assert ei.value.status_code == 403
    assert "pinned" in ei.value.detail.lower()


@pytest.mark.asyncio
async def test_workspace_pinned_key_accepts_matching_header():
    request = MagicMock()
    request.state = SimpleNamespace(
        auth_kind="api_key",
        api_key_org_id="org1",
        api_key_workspace_id="ws1",
    )
    request.headers = {"x-workspace-id": "ws1"}
    request.query_params = {}
    session = MagicMock()
    session.get = AsyncMock(return_value=_make_workspace(id_="ws1", org_id="org1"))

    ws = await _resolve_active_workspace(request, _make_user(), session)
    assert ws.id == "ws1"


@pytest.mark.asyncio
async def test_workspace_pinned_key_with_no_header_uses_pinned_workspace():
    """No header sent — pinned workspace is used automatically."""
    request = MagicMock()
    request.state = SimpleNamespace(
        auth_kind="api_key",
        api_key_org_id="org1",
        api_key_workspace_id="ws1",
    )
    request.headers = {}
    request.query_params = {}
    session = MagicMock()
    session.get = AsyncMock(return_value=_make_workspace(id_="ws1", org_id="org1"))

    ws = await _resolve_active_workspace(request, _make_user(), session)
    assert ws.id == "ws1"


@pytest.mark.asyncio
async def test_org_scoped_key_requires_workspace_header():
    """Org-scoped key (workspace_id=NULL) must always be paired with a
    header — there's no fallback."""
    request = MagicMock()
    request.state = SimpleNamespace(
        auth_kind="api_key",
        api_key_org_id="org1",
        api_key_workspace_id=None,
    )
    request.headers = {}
    request.query_params = {}
    session = MagicMock()

    with pytest.raises(HTTPException) as ei:
        await _resolve_active_workspace(request, _make_user(), session)
    assert ei.value.status_code == 400


@pytest.mark.asyncio
async def test_org_scoped_key_rejects_workspace_in_other_org():
    """Org-scoped key with a workspace header pointing to another org → 403."""
    request = MagicMock()
    request.state = SimpleNamespace(
        auth_kind="api_key",
        api_key_org_id="org1",
        api_key_workspace_id=None,
    )
    request.headers = {"x-workspace-id": "ws-of-org2"}
    request.query_params = {}
    session = MagicMock()
    session.get = AsyncMock(
        return_value=_make_workspace(id_="ws-of-org2", org_id="org2"),
    )

    with pytest.raises(HTTPException) as ei:
        await _resolve_active_workspace(request, _make_user(), session)
    assert ei.value.status_code == 403
    assert "outside" in ei.value.detail.lower()
