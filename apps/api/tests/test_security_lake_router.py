"""Router handler tests for the Security Lake query API.

Handlers are called directly as coroutines (no TestClient) — the same
no-HTTP-stack pattern used by other handler tests in this project.
A local SQLite-backed catalog is seeded per test via tmp_path.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog
from pencheff_api.services.security_lake.lake_schema import to_lake_row
from pencheff_api.services.security_lake import map_finding, validate_ocsf, LakeContext
from pencheff_api.routers import security_lake as router_mod


def _settings(tmp_path):
    return SimpleNamespace(
        lake_catalog_type="sql",
        lake_catalog_uri=f"sqlite:///{tmp_path}/cat.db",
        lake_warehouse=f"file://{tmp_path}/wh",
        lake_namespace="pencheff", lake_table="findings",
    )


def _seed(tmp_path):
    w = LakeWriter(build_local_catalog(uri=f"sqlite:///{tmp_path}/cat.db",
                                       warehouse=f"file://{tmp_path}/wh"),
                   namespace="pencheff", table="findings")
    w.ensure_table()
    sca = {"scanner": "osv", "rule_id": None, "severity": "critical", "title": "lodash",
           "description": "d", "file_path": "pl.json", "line_start": None, "line_end": None,
           "code_snippet": None, "cve": "CVE-2020-8203", "package": "lodash",
           "installed_version": "4.1", "fixed_version": "4.2", "raw": {}}
    rows = []
    for asset in ("r1", "r2"):
        ctx = LakeContext(org_id="o1", asset_id=asset, source="sca",
                          time_ms=1_700_000_000_000, is_new=True)
        e = map_finding("sca", sca, ctx); validate_ocsf(e)
        rows.append(to_lake_row(e, org_id="o1", source="sca", asset_id=asset))
    w.append_rows(rows)


def _ws(org_id="o1"):
    return SimpleNamespace(id="ws1", org_id=org_id)


def test_list_findings_handler_scopes_to_org(tmp_path):
    _seed(tmp_path)
    page = asyncio.run(router_mod.list_findings(
        source=None, severity_id=None, status_id=None, asset_id=None,
        limit=100, offset=0, workspace=_ws("o1"), settings=_settings(tmp_path)))
    assert page.total == 2
    assert {i.asset_id for i in page.items} == {"r1", "r2"}
    # other org sees nothing
    empty = asyncio.run(router_mod.list_findings(
        source=None, severity_id=None, status_id=None, asset_id=None,
        limit=100, offset=0, workspace=_ws("o-other"), settings=_settings(tmp_path)))
    assert empty.total == 0


def test_trends_and_correlate_handlers(tmp_path):
    _seed(tmp_path)
    trends = asyncio.run(router_mod.get_trends(workspace=_ws("o1"),
                                               settings=_settings(tmp_path)))
    # Both seeded findings share the same dt but have DIFFERENT finding_uid
    # (different asset_id → different fingerprint), so open_findings == 2.
    assert trends and trends[0].open_findings == 2
    corr = asyncio.run(router_mod.correlate(min_assets=2, workspace=_ws("o1"),
                                            settings=_settings(tmp_path)))
    assert corr[0].cve == "CVE-2020-8203" and corr[0].assets == 2


def test_export_handler_ndjson_org_scoped(tmp_path):
    _seed(tmp_path)  # existing helper seeds org o1 with 2 findings
    resp = asyncio.run(router_mod.export(
        format="ndjson", source=None, workspace=_ws("o1"),
        settings=_settings(tmp_path)))
    body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
    assert resp.media_type == "application/x-ndjson"
    assert len([l for l in body.splitlines() if l]) == 2
    # other org gets nothing
    empty = asyncio.run(router_mod.export(
        format="ndjson", source=None, workspace=_ws("o-other"),
        settings=_settings(tmp_path)))
    empty_body = empty.body.decode() if isinstance(empty.body, bytes) else empty.body
    assert empty_body == ""


def test_export_handler_parquet(tmp_path):
    _seed(tmp_path)
    resp = asyncio.run(router_mod.export(
        format="parquet", source=None, workspace=_ws("o1"),
        settings=_settings(tmp_path)))
    assert resp.media_type == "application/octet-stream"
    assert isinstance(resp.body, (bytes, bytearray)) and len(resp.body) > 0
