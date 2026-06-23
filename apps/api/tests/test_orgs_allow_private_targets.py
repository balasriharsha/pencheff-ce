# apps/api/tests/test_orgs_allow_private_targets.py
"""Unit tests for the allow_private_targets flip on PATCH /orgs/{id}.

Convention: pure unit tests — no conftest, no HTTP client, no real DB.
We call ``update_org`` directly with hand-built fakes, mirroring the
pattern from test_targets_host_kind.py.

Covered:
- admin flips allow_private_targets True WITH disclosure ack → 200 + audit row
- admin flips allow_private_targets True WITHOUT disclosure ack → 422 (Pydantic)
- non-admin (member role) attempts flip → 403
- admin flips allow_private_targets False, no ack required → 200 + audit row
"""
from __future__ import annotations

import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from pencheff_api.db.models import AuditLog, Org, OrgMember, User
from pencheff_api.routers.orgs import update_org
from pencheff_api.schemas.orgs import OrgOut, OrgUpdate


# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------

_NOW = datetime.datetime.now(datetime.timezone.utc)


def _make_org(*, allow_private_targets: bool = False) -> Org:
    return Org(
        id="org-1",
        name="Test Org",
        plan="free",
        allow_private_targets=allow_private_targets,
        force_deterministic_only=False,
        created_at=_NOW,
    )


def _make_user(*, user_id: str = "user-1") -> User:
    return User(id=user_id, email="tester@example.com")


def _make_member(*, role: str = "admin") -> OrgMember:
    return OrgMember(org_id="org-1", user_id="user-1", role=role)


class _FakeSession:
    """AsyncSession stub that captures add() calls and returns a preset Org."""

    def __init__(self, org: Org) -> None:
        self._org = org
        self.added: list = []

    async def get(self, model_cls, pk):
        if model_cls is Org and pk == self._org.id:
            return self._org
        return None

    def add(self, row) -> None:
        self.added.append(row)

    async def commit(self) -> None:
        pass

    async def refresh(self, obj) -> None:
        pass  # org is already fully populated; no-op is fine


class _FakeClient:
    host = "203.0.113.99"


class _FakeRequest:
    """Minimal Request stub — only exposes .client.host and .headers for audit rows."""

    def __init__(self, host: str = "203.0.113.99", user_agent: str = "pytest/1.0") -> None:
        self.client = _FakeClient()
        self.client.host = host
        self.headers = {"user-agent": user_agent}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_flips_allow_private_true_with_ack() -> None:
    """Admin sends allow_private_targets=True + ack=True → 200, flag set, audit row."""
    org = _make_org(allow_private_targets=False)
    user = _make_user()
    member = _make_member(role="admin")
    session = _FakeSession(org)

    body = OrgUpdate(
        allow_private_targets=True,
        private_targets_disclosure_ack=True,
    )

    result = await update_org(
        org_id="org-1",
        body=body,
        request=_FakeRequest(),
        ctx=(user, member),
        session=session,
    )

    # Flag was flipped on the ORM object.
    assert org.allow_private_targets is True

    # Exactly one audit row was written.
    audit_rows = [r for r in session.added if isinstance(r, AuditLog)]
    assert len(audit_rows) == 1, f"Expected 1 AuditLog row, got {len(audit_rows)}"

    row = audit_rows[0]
    assert row.action == "org.allow_private_targets.flip"
    assert row.meta is not None
    assert row.meta["prior"] is False
    assert row.meta["new"] is True
    assert row.meta["ack_provided"] is True
    # Spec §"API contract" requires actor IP + user-agent on every flip.
    assert row.request_ip == "203.0.113.99"
    assert row.user_agent == "pytest/1.0"


@pytest.mark.asyncio
async def test_admin_flips_allow_private_true_without_ack_returns_422() -> None:
    """Admin sends allow_private_targets=True without ack → Pydantic raises ValueError
    which FastAPI turns into 422.  We verify the schema validator fires directly."""
    with pytest.raises(Exception) as exc_info:
        OrgUpdate(allow_private_targets=True)  # no ack

    # Pydantic v2 wraps model_validator errors in ValidationError.
    err_text = str(exc_info.value)
    assert "private_targets_disclosure_ack" in err_text


@pytest.mark.asyncio
async def test_non_admin_cannot_flip_allow_private() -> None:
    """Non-admin (role=member) is rejected by require_org_role before reaching
    the handler body.  We simulate what require_org_role raises: 403."""
    from fastapi import HTTPException

    # require_org_role raises 403 before the handler runs; we verify that if
    # someone manually calls update_org with a member ctx the handler still
    # returns an OrgOut (authorization is the decorator's job, not the body's).
    # The real 403 test: call require_org_role directly with a member role.
    from pencheff_api.auth.deps import require_org_role

    dep_fn = require_org_role("owner", "admin")

    # Build a fake session that returns a member with role=member.
    from unittest.mock import AsyncMock, patch

    member_orm = OrgMember(org_id="org-1", user_id="user-1", role="member")

    with patch(
        "pencheff_api.auth.deps.get_membership",
        new_callable=AsyncMock,
        return_value=member_orm,
    ):
        user = _make_user()
        fake_session = _FakeSession(_make_org())

        with pytest.raises(HTTPException) as exc_info:
            await dep_fn(
                org_id="org-1",
                user=user,
                session=fake_session,
            )

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_admin_flips_allow_private_false_does_not_require_ack() -> None:
    """Admin sends allow_private_targets=False (no ack needed) → 200 + audit row."""
    org = _make_org(allow_private_targets=True)  # currently True
    user = _make_user()
    member = _make_member(role="admin")
    session = _FakeSession(org)

    body = OrgUpdate(allow_private_targets=False)  # no ack — should be fine

    result = await update_org(
        org_id="org-1",
        body=body,
        request=_FakeRequest(),
        ctx=(user, member),
        session=session,
    )

    # Flag was turned off.
    assert org.allow_private_targets is False

    # Audit row is still written (per spec: "written anyway with new=False").
    audit_rows = [r for r in session.added if isinstance(r, AuditLog)]
    assert len(audit_rows) == 1
    row = audit_rows[0]
    assert row.action == "org.allow_private_targets.flip"
    assert row.meta["prior"] is True
    assert row.meta["new"] is False


def test_org_response_exposes_allow_private_targets() -> None:
    """OrgOut serialises allow_private_targets so the FE can read the toggle state."""
    org = _make_org(allow_private_targets=True)
    # OrgOut requires fields not on Org; supply them explicitly via constructor.
    out = OrgOut(
        id=org.id,
        name=org.name,
        plan=org.plan,
        role="admin",
        created_at=org.created_at,
        ai_enabled=False,
        force_deterministic_only=bool(org.force_deterministic_only),
        allow_private_targets=bool(org.allow_private_targets),
    )
    data = out.model_dump()
    assert "allow_private_targets" in data, "allow_private_targets must be present in OrgOut"
    assert data["allow_private_targets"] is True
