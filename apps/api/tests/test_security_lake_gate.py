from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from pencheff_api.routers.security_lake import require_security_lake_enabled


class _FakeSession:
    def __init__(self, org): self._org = org
    async def get(self, model, pk): return self._org


def test_gate_allows_when_enabled():
    org = SimpleNamespace(id="o1", security_lake_enabled=True)
    ws = SimpleNamespace(id="w1", org_id="o1")
    out = asyncio.run(require_security_lake_enabled(workspace=ws, session=_FakeSession(org)))
    assert out is ws


def test_gate_403_when_disabled():
    org = SimpleNamespace(id="o1", security_lake_enabled=False)
    ws = SimpleNamespace(id="w1", org_id="o1")
    with pytest.raises(HTTPException) as ei:
        asyncio.run(require_security_lake_enabled(workspace=ws, session=_FakeSession(org)))
    assert ei.value.status_code == 403


def test_gate_403_when_org_missing():
    ws = SimpleNamespace(id="w1", org_id="o1")
    with pytest.raises(HTTPException) as ei:
        asyncio.run(require_security_lake_enabled(workspace=ws, session=_FakeSession(None)))
    assert ei.value.status_code == 403
