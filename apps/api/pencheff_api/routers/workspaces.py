"""Workspace CRUD endpoints.

A workspace is created inside an Org (via ``org_id`` in the request body)
and scoped by membership + plan quota. Switching between workspaces is a
frontend concern — the caller sends ``X-Workspace-Id`` on subsequent
requests to the resource routers.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_current_user, get_membership, require_org_role
from ..db.base import get_session
from ..db.models import OrgMember, User, Workspace
from ..schemas.workspaces import (
    WorkspaceCreate,
    WorkspaceMemberOut,
    WorkspaceOut,
    WorkspaceUpdate,
)
from ..services.quota import check_workspace_quota

router = APIRouter(prefix="/workspaces", tags=["workspaces"])

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    s = _SLUG_RE.sub("-", name.lower()).strip("-")
    return s[:64] or "workspace"


async def _ensure_unique_slug(session: AsyncSession, org_id: str, base: str) -> str:
    slug = base
    i = 1
    while True:
        existing = (
            await session.execute(
                select(Workspace.id).where(
                    Workspace.org_id == org_id, Workspace.slug == slug
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            return slug
        i += 1
        slug = f"{base}-{i}"[:64]


def _to_out(w: Workspace) -> WorkspaceOut:
    return WorkspaceOut(
        id=w.id, org_id=w.org_id, name=w.name, slug=w.slug,
        created_at=w.created_at,
        weekly_digest_emails=w.weekly_digest_emails,
    )


def _sanitise_emails(raw: list[str] | None, cap: int = 20) -> list[str] | None:
    """Normalise + dedupe + cap an email recipient list. Returns None
    when the cleaned list is empty (semantically: 'no subscription')."""
    if raw is None:
        return None
    seen: set[str] = set()
    out: list[str] = []
    for v in raw:
        e = (v or "").strip()
        if not e or "@" not in e or e in seen:
            continue
        seen.add(e)
        out.append(e)
    return out[:cap] or None


@router.post("", response_model=WorkspaceOut, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    body: WorkspaceCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> WorkspaceOut:
    member = await get_membership(session, user.id, body.org_id)
    if member is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of this org")
    if member.role not in ("owner", "admin"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "only owners and admins can create workspaces"
        )
    await check_workspace_quota(session, body.org_id)

    slug = await _ensure_unique_slug(session, body.org_id, _slugify(body.name))
    ws = Workspace(
        org_id=body.org_id, name=body.name, slug=slug,
        created_by_user_id=user.id,
    )
    session.add(ws)
    await session.commit()
    await session.refresh(ws)
    return _to_out(ws)


@router.get("", response_model=list[WorkspaceOut])
async def list_workspaces(
    org_id: str | None = None,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[WorkspaceOut]:
    org_ids = (
        await session.execute(
            select(OrgMember.org_id).where(OrgMember.user_id == user.id)
        )
    ).scalars().all()
    if not org_ids:
        return []
    if org_id is not None:
        if org_id not in org_ids:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of this org")
        filter_ids = [org_id]
    else:
        filter_ids = list(org_ids)
    rows = (
        await session.execute(
            select(Workspace)
            .where(Workspace.org_id.in_(filter_ids))
            .order_by(Workspace.created_at.asc())
        )
    ).scalars().all()
    return [_to_out(w) for w in rows]


@router.get("/{workspace_id}", response_model=WorkspaceOut)
async def get_workspace(
    workspace_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> WorkspaceOut:
    ws = await session.get(Workspace, workspace_id)
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    member = await get_membership(session, user.id, ws.org_id)
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    return _to_out(ws)


@router.patch("/{workspace_id}", response_model=WorkspaceOut)
async def update_workspace(
    workspace_id: str,
    body: WorkspaceUpdate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> WorkspaceOut:
    ws = await session.get(Workspace, workspace_id)
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    member = await get_membership(session, user.id, ws.org_id)
    if member is None or member.role not in ("owner", "admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
    if body.name is not None:
        ws.name = body.name
    if body.weekly_digest_emails is not None:
        ws.weekly_digest_emails = _sanitise_emails(body.weekly_digest_emails)
    await session.commit()
    await session.refresh(ws)
    return _to_out(ws)


@router.get("/{workspace_id}/members", response_model=list[WorkspaceMemberOut])
async def list_workspace_members(
    workspace_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[WorkspaceMemberOut]:
    """List org members visible to the active user. Powers the
    recipient-picker dropdown for commission-email and digest UIs.

    Workspaces inherit membership from their parent Org — we expose
    every OrgMember of the workspace's org as a candidate recipient.
    """
    ws = await session.get(Workspace, workspace_id)
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    member = await get_membership(session, user.id, ws.org_id)
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    rows = (
        await session.execute(
            select(OrgMember, User)
            .join(User, User.id == OrgMember.user_id)
            .where(OrgMember.org_id == ws.org_id)
            .order_by(User.email.asc())
        )
    ).all()
    return [
        WorkspaceMemberOut(
            user_id=str(u.id), email=u.email,
            name=getattr(u, "name", None),
            role=om.role,
        )
        for (om, u) in rows
    ]


@router.delete("/{workspace_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workspace(
    workspace_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    ws = await session.get(Workspace, workspace_id)
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    member = await get_membership(session, user.id, ws.org_id)
    if member is None or member.role not in ("owner", "admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
    # Guard the last workspace in an org — we always want at least one so
    # the user has somewhere to land after switching.
    remaining = (
        await session.execute(
            select(Workspace).where(Workspace.org_id == ws.org_id)
        )
    ).scalars().all()
    if len(remaining) <= 1:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "cannot delete the last workspace in an org"
        )
    await session.delete(ws)
    await session.commit()
