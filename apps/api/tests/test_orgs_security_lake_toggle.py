# apps/api/tests/test_orgs_security_lake_toggle.py
"""Unit tests for the security_lake_enabled toggle on PATCH /orgs/{id}.

Convention: pure unit tests — no conftest, no HTTP client, no real DB.
We call ``update_org`` directly with hand-built fakes, mirroring the
pattern from test_orgs_allow_private_targets.py.

Covered:
- enabling sets security_lake_enabled=True and security_lake_disabled_at=None
- disabling sets security_lake_enabled=False and security_lake_disabled_at is set
- an AuditLog row with action org.security_lake_enabled.toggle is added on each change
- no audit row when the flag value is unchanged
- OrgOut.security_lake_enabled reflects the new value in both directions
"""
from __future__ import annotations

import datetime
from typing import Any

import pytest

from pencheff_api.db.models import AuditLog, Org, OrgMember, User
from pencheff_api.routers.orgs import update_org
from pencheff_api.schemas.orgs import OrgOut, OrgUpdate


# ---------------------------------------------------------------------------
# Helpers / fakes  (mirror test_orgs_allow_private_targets.py exactly)
# ---------------------------------------------------------------------------

_NOW = datetime.datetime.now(datetime.timezone.utc)


def _make_org(*, security_lake_enabled: bool = False) -> Org:
    org = Org(
        id="org-1",
        name="Test Org",
        plan="free",
        allow_private_targets=False,
        force_deterministic_only=False,
        security_lake_enabled=security_lake_enabled,
        created_at=_NOW,
    )
    # security_lake_disabled_at may not be a column kwarg on all migrations;
    # set it after construction to mirror production state.
    org.security_lake_disabled_at = None
    return org


def _make_user(*, user_id: str = "user-1") -> User:
    return User(id=user_id, email="tester@example.com")


def _make_member(*, role: str = "admin") -> OrgMember:
    return OrgMember(org_id="org-1", user_id="user-1", role=role)


class _FakeSession:
    """AsyncSession stub that captures add() calls and returns a preset Org."""

    def __init__(self, org: Org) -> None:
        self._org = org
        self.added: list = []

    async def get(self, model_cls: Any, pk: Any) -> Any:
        if model_cls is Org and pk == self._org.id:
            return self._org
        return None

    def add(self, row: Any) -> None:
        self.added.append(row)

    async def commit(self) -> None:
        pass

    async def refresh(self, obj: Any) -> None:
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
async def test_enable_security_lake_sets_flag_and_clears_disabled_at() -> None:
    """Enabling the lake sets security_lake_enabled=True and clears disabled_at."""
    org = _make_org(security_lake_enabled=False)
    org.security_lake_disabled_at = _NOW  # simulate previously disabled
    user = _make_user()
    member = _make_member(role="admin")
    session = _FakeSession(org)

    result = await update_org(
        org_id="org-1",
        body=OrgUpdate(security_lake_enabled=True),
        request=_FakeRequest(),
        ctx=(user, member),
        session=session,
    )

    # Flag flipped on the ORM object.
    assert org.security_lake_enabled is True
    # Purge clock must be cleared on enable.
    assert org.security_lake_disabled_at is None

    # Exactly one audit row with the correct action.
    audit_rows = [r for r in session.added if isinstance(r, AuditLog)]
    assert len(audit_rows) == 1, f"Expected 1 AuditLog row, got {len(audit_rows)}"
    row = audit_rows[0]
    assert row.action == "org.security_lake_enabled.toggle"
    assert row.meta is not None
    assert row.meta["before"] is False
    assert row.meta["after"] is True

    # OrgOut reflects the new value.
    assert isinstance(result, OrgOut)
    assert result.security_lake_enabled is True


@pytest.mark.asyncio
async def test_disable_security_lake_sets_flag_and_starts_purge_clock() -> None:
    """Disabling the lake sets security_lake_enabled=False and records disabled_at."""
    org = _make_org(security_lake_enabled=True)
    org.security_lake_disabled_at = None
    user = _make_user()
    member = _make_member(role="admin")
    session = _FakeSession(org)

    result = await update_org(
        org_id="org-1",
        body=OrgUpdate(security_lake_enabled=False),
        request=_FakeRequest(),
        ctx=(user, member),
        session=session,
    )

    # Flag flipped off.
    assert org.security_lake_enabled is False
    # Purge clock must be set (the disabled_at column tracks when cleanup is due).
    assert org.security_lake_disabled_at is not None
    assert isinstance(org.security_lake_disabled_at, datetime.datetime)

    # One audit row.
    audit_rows = [r for r in session.added if isinstance(r, AuditLog)]
    assert len(audit_rows) == 1
    row = audit_rows[0]
    assert row.action == "org.security_lake_enabled.toggle"
    assert row.meta["before"] is True
    assert row.meta["after"] is False

    # OrgOut reflects the new value.
    assert isinstance(result, OrgOut)
    assert result.security_lake_enabled is False


@pytest.mark.asyncio
async def test_no_op_toggle_writes_no_audit_row() -> None:
    """Sending the same value as the current state must not write an audit row."""
    org = _make_org(security_lake_enabled=True)
    user = _make_user()
    member = _make_member(role="admin")
    session = _FakeSession(org)

    result = await update_org(
        org_id="org-1",
        body=OrgUpdate(security_lake_enabled=True),  # already True → no-op
        request=_FakeRequest(),
        ctx=(user, member),
        session=session,
    )

    audit_rows = [r for r in session.added if isinstance(r, AuditLog)]
    assert len(audit_rows) == 0, "No audit row on a no-op toggle"

    # Flag unchanged.
    assert org.security_lake_enabled is True
    assert result.security_lake_enabled is True


def test_org_out_exposes_security_lake_enabled() -> None:
    """OrgOut serialises security_lake_enabled so the FE can read the toggle state."""
    org = _make_org(security_lake_enabled=True)
    out = OrgOut(
        id=org.id,
        name=org.name,
        plan=org.plan,
        role="admin",
        created_at=org.created_at,
        ai_enabled=False,
        force_deterministic_only=False,
        allow_private_targets=False,
        security_lake_enabled=True,
    )
    data = out.model_dump()
    assert "security_lake_enabled" in data, "security_lake_enabled must be present in OrgOut"
    assert data["security_lake_enabled"] is True
