"""Security Lake query endpoints — read-only, org-scoped.

Three GET endpoints expose the internal OCSF Iceberg lake:
  GET /security-lake/findings   — current-state deduped findings
  GET /security-lake/trends     — findings over time (by day)
  GET /security-lake/correlate  — same CVE across >=N assets
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..config import Settings, get_settings
from ..db.base import get_session
from ..db.models import Org, Workspace
from ..schemas.security_lake import (
    LakeFindingItem, LakeFindingsPage, LakeTrendPoint, LakeCorrelation,
)
from ..services.security_lake import lake_query


async def require_security_lake_enabled(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> Workspace:
    """403 unless the caller's org has the Security Lake enabled."""
    org = await session.get(Org, workspace.org_id)
    if org is None or not bool(getattr(org, "security_lake_enabled", False)):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Security Lake is disabled for this organization",
        )
    return workspace


router = APIRouter(
    prefix="/security-lake",
    tags=["security-lake"],
    dependencies=[
        Depends(require_scope("security_lake:read")),
        Depends(require_security_lake_enabled),
    ],
)


@router.get("/findings", response_model=LakeFindingsPage)
async def list_findings(
    source: str | None = Query(None, description="sast | dast | sca | iac | secret"),
    severity_id: int | None = Query(None, ge=0, le=6),
    status_id: int | None = Query(None, ge=0),
    asset_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    workspace: Workspace = Depends(get_active_workspace),
    settings: Settings = Depends(get_settings),
) -> LakeFindingsPage:
    rows, total = lake_query.query_findings(
        settings, org_id=workspace.org_id, source=source, severity_id=severity_id,
        status_id=status_id, asset_id=asset_id, limit=limit, offset=offset)
    items = [
        LakeFindingItem(
            finding_uid=r["finding_uid"], class_uid=r["class_uid"], source=r["source"],
            severity_id=r["severity_id"], status_id=r["status_id"], asset_id=r["asset_id"],
            time=r["time"], dt=r["dt"], org_id=r["org_id"], ocsf_json=r.get("ocsf_json"))
        for r in rows
    ]
    return LakeFindingsPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/trends", response_model=list[LakeTrendPoint])
async def get_trends(
    workspace: Workspace = Depends(get_active_workspace),
    settings: Settings = Depends(get_settings),
) -> list[LakeTrendPoint]:
    rows = lake_query.query_trends(settings, org_id=workspace.org_id)
    return [LakeTrendPoint(dt=r["dt"], open_findings=r["open_findings"],
                           high_critical=r["high_critical"]) for r in rows]


@router.get("/correlate", response_model=list[LakeCorrelation])
async def correlate(
    min_assets: int = Query(2, ge=1, le=100),
    workspace: Workspace = Depends(get_active_workspace),
    settings: Settings = Depends(get_settings),
) -> list[LakeCorrelation]:
    rows = lake_query.query_correlate(settings, org_id=workspace.org_id,
                                      min_assets=min_assets)
    return [LakeCorrelation(cve=r["cve"], assets=r["assets"], findings=r["findings"])
            for r in rows]


@router.get("/export")
async def export(
    format: Literal["ndjson", "parquet"] = Query("ndjson"),
    source: str | None = Query(None, description="sast | dast | sca | iac | secret"),
    workspace: Workspace = Depends(get_active_workspace),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Mediated, org-scoped OCSF export. NDJSON for SIEMs; Parquet for lakes."""
    if format == "parquet":
        blob = lake_query.export_org_parquet(settings, org_id=workspace.org_id,
                                             source=source)
        return Response(content=blob, media_type="application/octet-stream",
                        headers={"Content-Disposition":
                                 'attachment; filename="pencheff-findings.parquet"'})
    text = lake_query.export_org_ndjson(settings, org_id=workspace.org_id, source=source)
    return Response(content=text, media_type="application/x-ndjson",
                    headers={"Content-Disposition":
                             'attachment; filename="pencheff-findings.ndjson"'})
