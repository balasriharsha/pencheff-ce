"""Engagement CRUD + ingest pairing + unified findings query."""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user, require_scope
from ..db.base import get_session
from ..db.models import (
    Engagement,
    EngagementIngestToken,
    EngagementMember,
    Finding,
    RepoFinding,
    Scan,
    UnifiedFinding,
    User,
    Workspace,
)
from ..services.engagement_oast import provision_oast, revoke_oast
from ..services.threat_model import (
    generate_threat_model,
    module_priority_bias,
    render_markdown as render_threat_model_markdown,
)

router = APIRouter(prefix="/engagements", tags=["engagements"])

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    s = _SLUG_RE.sub("-", name.lower()).strip("-")
    return s[:64] or "engagement"


def _hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


class EngagementCreate(BaseModel):
    name: str
    description: str | None = None
    retention_days: int = 90


class EngagementOut(BaseModel):
    id: str
    workspace_id: str
    name: str
    slug: str
    description: str | None
    status: str
    oast_mode: str
    oast_domain: str | None
    retention_days: int
    created_at: datetime
    closed_at: datetime | None


class EngagementCreatedOut(EngagementOut):
    ingest_token: str
    pairing_code: str


class IngestHandshake(BaseModel):
    pairing_code: str


class IngestHandshakeOut(BaseModel):
    engagement_id: str
    ingest_token: str
    api_base: str


def _to_out(e: Engagement) -> EngagementOut:
    return EngagementOut(
        id=e.id, workspace_id=e.workspace_id, name=e.name, slug=e.slug,
        description=e.description, status=e.status, oast_mode=e.oast_mode,
        oast_domain=e.oast_domain, retention_days=e.retention_days,
        created_at=e.created_at, closed_at=e.closed_at,
    )


async def _ensure_unique_slug(session: AsyncSession, workspace_id: str, base: str) -> str:
    slug = base
    i = 1
    while True:
        existing = (await session.execute(
            select(Engagement.id).where(
                Engagement.workspace_id == workspace_id, Engagement.slug == slug
            )
        )).scalar_one_or_none()
        if existing is None:
            return slug
        i += 1
        slug = f"{base}-{i}"[:64]


@router.post(
    "",
    response_model=EngagementCreatedOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("engagements:write"))],
)
async def create_engagement(
    body: EngagementCreate,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> EngagementCreatedOut:
    slug = await _ensure_unique_slug(session, workspace.id, _slugify(body.name))
    eng = Engagement(
        org_id=workspace.org_id, workspace_id=workspace.id, name=body.name,
        slug=slug, description=body.description, retention_days=body.retention_days,
        created_by_user_id=user.id, status="open",
    )
    session.add(eng)
    await session.flush()

    # Provision OAST.
    prov = provision_oast(eng)
    eng.oast_mode = prov.mode
    eng.oast_domain = prov.domain
    eng.oast_token = prov.token
    eng.oast_container_id = prov.container_id

    # Add creator as a member.
    session.add(EngagementMember(engagement_id=eng.id, user_id=user.id, role="lead"))

    # Issue ingest token.
    raw = secrets.token_urlsafe(32)
    pairing_code = secrets.token_hex(4).upper()  # 8-char human-typeable
    session.add(EngagementIngestToken(
        engagement_id=eng.id, workspace_id=workspace.id,
        token_hash=_hash_token(raw), pairing_code=pairing_code,
        created_by_user_id=user.id,
    ))

    await session.commit()
    await session.refresh(eng)
    return EngagementCreatedOut(
        **_to_out(eng).model_dump(),
        ingest_token=raw,
        pairing_code=pairing_code,
    )


@router.get(
    "",
    response_model=list[EngagementOut],
    dependencies=[Depends(require_scope("engagements:read"))],
)
async def list_engagements(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
    include_closed: bool = False,
) -> list[EngagementOut]:
    q = select(Engagement).where(Engagement.workspace_id == workspace.id)
    if not include_closed:
        q = q.where(Engagement.status == "open")
    q = q.order_by(Engagement.created_at.desc())
    rows = (await session.execute(q)).scalars().all()
    return [_to_out(e) for e in rows]


async def _get_engagement_for_workspace(
    session: AsyncSession, engagement_id: str, workspace: Workspace
) -> Engagement:
    e = await session.get(Engagement, engagement_id)
    if e is None or e.workspace_id != workspace.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    return e


@router.get(
    "/{engagement_id}",
    response_model=EngagementOut,
    dependencies=[Depends(require_scope("engagements:read"))],
)
async def get_engagement(
    engagement_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> EngagementOut:
    return _to_out(await _get_engagement_for_workspace(session, engagement_id, workspace))


@router.post(
    "/{engagement_id}/close",
    response_model=EngagementOut,
    dependencies=[Depends(require_scope("engagements:write"))],
)
async def close_engagement(
    engagement_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> EngagementOut:
    e = await _get_engagement_for_workspace(session, engagement_id, workspace)
    if e.status == "closed":
        return _to_out(e)
    revoke_oast(e)
    e.status = "closed"
    e.closed_at = datetime.now(timezone.utc)
    e.oast_container_id = None
    await session.commit()
    await session.refresh(e)
    return _to_out(e)


@router.post(
    "/{engagement_id}/pairing-code",
    response_model=dict,
    dependencies=[Depends(require_scope("engagements:write"))],
)
async def rotate_pairing_code(
    engagement_id: str,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    e = await _get_engagement_for_workspace(session, engagement_id, workspace)
    raw = secrets.token_urlsafe(32)
    pairing_code = secrets.token_hex(4).upper()
    session.add(EngagementIngestToken(
        engagement_id=e.id, workspace_id=workspace.id,
        token_hash=_hash_token(raw), pairing_code=pairing_code,
        created_by_user_id=user.id,
    ))
    await session.commit()
    return {"ingest_token": raw, "pairing_code": pairing_code}


# ─────────── Ingest handshake (called by the browser extension) ────────────

handshake_router = APIRouter(prefix="/ingest/extension", tags=["ingest"])


@handshake_router.post("/handshake", response_model=IngestHandshakeOut)
async def handshake(
    body: IngestHandshake,
    session: AsyncSession = Depends(get_session),
) -> IngestHandshakeOut:
    """Exchange a one-time pairing code for the bound ingest token.

    The extension UX is: user pastes the 8-character code, we return the
    token (which the extension stores) and the engagement_id it's bound to.
    """
    code = (body.pairing_code or "").strip().upper()
    if not code:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "pairing_code required")
    row = (await session.execute(
        select(EngagementIngestToken).where(
            EngagementIngestToken.pairing_code == code,
            EngagementIngestToken.revoked_at.is_(None),
        )
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "invalid pairing code")
    # Pairing codes are single-use: clear after exchange.
    row.pairing_code = None
    row.last_used_at = datetime.now(timezone.utc)
    await session.commit()
    # The token itself was returned at creation time — the handshake here is
    # only useful when the client rotated it offline. For the v1 flow the
    # extension already received the token alongside the pairing code at
    # engagement creation. We expose engagement_id so the extension can label
    # captured traffic correctly.
    return IngestHandshakeOut(
        engagement_id=row.engagement_id,
        ingest_token="(rotate via /engagements/{id}/pairing-code)",
        api_base="",
    )


# ─────────── Unified findings ────────────


class UnifiedFindingOut(BaseModel):
    id: str
    kind: str  # dast | sast | sca | iac | secret
    severity: str
    title: str
    risk_score: float | None
    endpoint: str | None
    file_path: str | None
    cve: str | None
    package: str | None
    related: list[dict]


@router.get(
    "/{engagement_id}/findings/unified",
    response_model=list[UnifiedFindingOut],
    dependencies=[Depends(require_scope("engagements:read"))],
)
async def get_unified_findings(
    engagement_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[UnifiedFindingOut]:
    e = await _get_engagement_for_workspace(session, engagement_id, workspace)

    dast_rows = (await session.execute(
        select(Finding).where(Finding.engagement_id == e.id)
    )).scalars().all()
    sast_rows = (await session.execute(
        select(RepoFinding).where(RepoFinding.engagement_id == e.id)
    )).scalars().all()
    edges = (await session.execute(
        select(UnifiedFinding).where(UnifiedFinding.engagement_id == e.id)
    )).scalars().all()

    # Build edge lookup keyed by (kind, id).
    edge_lookup: dict[tuple[str, str], list[dict]] = {}
    for ed in edges:
        key = (ed.primary_finding_kind, ed.primary_finding_id)
        edge_lookup.setdefault(key, []).append({
            "kind": ed.related_finding_kind,
            "id": ed.related_finding_id,
            "link": ed.link_kind,
            "confidence": ed.confidence,
        })

    out: list[UnifiedFindingOut] = []
    for f in dast_rows:
        out.append(UnifiedFindingOut(
            id=f.id, kind="dast", severity=f.severity, title=f.title,
            risk_score=f.risk_score, endpoint=f.endpoint, file_path=None,
            cve=None, package=None,
            related=edge_lookup.get(("dast", f.id), []),
        ))
    for r in sast_rows:
        kind = "sca" if r.scanner in ("osv", "ghsa") else (
            "secret" if r.scanner == "gitleaks" else (
                "iac" if r.scanner in ("trivy_iac", "checkov") else "sast"
            )
        )
        out.append(UnifiedFindingOut(
            id=r.id, kind=kind, severity=r.severity, title=r.title,
            risk_score=None, endpoint=None, file_path=r.file_path,
            cve=r.cve, package=r.package,
            related=edge_lookup.get((kind, r.id), []),
        ))
    return out


# ─────────────────────────── Threat model ────────────────────────────


class ThreatModelGenerateIn(BaseModel):
    method: str = "stride"  # "stride" | "dread"
    target_url: str | None = None
    asset_types: list[str] | None = None
    asset_names: list[str] | None = None


class ThreatModelOut(BaseModel):
    threat_model: dict | None
    threat_model_updated_at: datetime | None
    markdown: str | None
    module_priority_bias: list[str]


def _shape_threat_model_out(e: Engagement) -> ThreatModelOut:
    md = render_threat_model_markdown(e.threat_model) if e.threat_model else None
    return ThreatModelOut(
        threat_model=e.threat_model,
        threat_model_updated_at=e.threat_model_updated_at,
        markdown=md,
        module_priority_bias=module_priority_bias(e.threat_model),
    )


@router.get(
    "/{engagement_id}/threat-model",
    response_model=ThreatModelOut,
    dependencies=[Depends(require_scope("engagements:read"))],
)
async def get_threat_model(
    engagement_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ThreatModelOut:
    e = await _get_engagement_for_workspace(session, engagement_id, workspace)
    return _shape_threat_model_out(e)


@router.post(
    "/{engagement_id}/threat-model",
    response_model=ThreatModelOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("engagements:write"))],
)
async def generate_engagement_threat_model(
    engagement_id: str,
    body: ThreatModelGenerateIn,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ThreatModelOut:
    e = await _get_engagement_for_workspace(session, engagement_id, workspace)
    model = generate_threat_model(
        target_url=body.target_url,
        asset_types=body.asset_types,
        method=body.method,
        asset_names=body.asset_names,
    )
    e.threat_model = model
    e.threat_model_updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(e)
    return _shape_threat_model_out(e)


class ThreatModelPatchIn(BaseModel):
    """Free-form patch — replaces the entire ``threat_model`` JSONB blob.

    Operators editing in the UI send the whole JSON back rather than a
    JSON-Patch — simpler, and the model is small enough that bandwidth
    is irrelevant.
    """

    threat_model: dict


@router.put(
    "/{engagement_id}/threat-model",
    response_model=ThreatModelOut,
    dependencies=[Depends(require_scope("engagements:write"))],
)
async def replace_threat_model(
    engagement_id: str,
    body: ThreatModelPatchIn,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ThreatModelOut:
    e = await _get_engagement_for_workspace(session, engagement_id, workspace)
    if not isinstance(body.threat_model, dict) or not body.threat_model:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "threat_model must be a non-empty JSON object",
        )
    e.threat_model = body.threat_model
    e.threat_model_updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(e)
    return _shape_threat_model_out(e)


@router.delete(
    "/{engagement_id}/threat-model",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("engagements:write"))],
)
async def clear_threat_model(
    engagement_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    e = await _get_engagement_for_workspace(session, engagement_id, workspace)
    e.threat_model = None
    e.threat_model_updated_at = None
    await session.commit()
