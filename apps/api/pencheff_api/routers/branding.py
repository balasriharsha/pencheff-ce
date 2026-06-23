"""Per-workspace report branding."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace
from ..db.base import get_session
from ..db.models import Workspace, WorkspaceBranding

router = APIRouter(prefix="/workspaces/{workspace_id}/branding", tags=["branding"])


class BrandingIn(BaseModel):
    logo_url: str | None = None
    primary_color: str | None = None
    secondary_color: str | None = None
    opening_letter_md: str | None = None
    methodology_md: str | None = None
    footer_text: str | None = None


class BrandingOut(BrandingIn):
    workspace_id: str
    updated_at: datetime


def _to_out(b: WorkspaceBranding) -> BrandingOut:
    return BrandingOut(
        workspace_id=b.workspace_id,
        logo_url=b.logo_url, primary_color=b.primary_color,
        secondary_color=b.secondary_color, opening_letter_md=b.opening_letter_md,
        methodology_md=b.methodology_md, footer_text=b.footer_text,
        updated_at=b.updated_at,
    )


@router.get("", response_model=BrandingOut | None)
async def get_branding(
    workspace_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> BrandingOut | None:
    if workspace.id != workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    b = (await session.execute(
        select(WorkspaceBranding).where(WorkspaceBranding.workspace_id == workspace.id)
    )).scalar_one_or_none()
    return _to_out(b) if b else None


@router.put("", response_model=BrandingOut)
async def upsert_branding(
    workspace_id: str,
    body: BrandingIn,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> BrandingOut:
    if workspace.id != workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    b = (await session.execute(
        select(WorkspaceBranding).where(WorkspaceBranding.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if b is None:
        b = WorkspaceBranding(workspace_id=workspace.id)
        session.add(b)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(b, field, value)
    b.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(b)
    return _to_out(b)
