"""Organization + membership + invite endpoints.

Lives above the workspace layer — these routes never depend on an active
workspace. Role-gating is enforced via ``require_org_role``.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_current_user, get_membership, require_org_role
from ..config import get_settings
from ..db.base import get_session
from ..db.models import AuditLog, Org, OrgInvite, OrgMember, User, Workspace
from ..services.ai_gate import plan_has_ai
from ..services.security_lake.toggle import apply_lake_toggle


def _ai_enabled_for(plan: str | None) -> bool:
    """Resolve the dashboard-facing AI flag — True when the org's plan
    allows AI OR when ``AI_FREE_TIER_ENABLED`` is on."""
    return plan_has_ai(plan) or get_settings().ai_free_tier_enabled
from ..schemas.orgs import (
    InviteCreate,
    InviteOut,
    MemberOut,
    MemberRoleUpdate,
    OrgCreate,
    OrgOut,
    OrgUpdate,
)
from ..schemas.workspaces import WorkspaceOut
from ..services.email import send_invite_email
from ..services.invites import generate_token, hash_token
from ..services.quota import check_org_quota, check_seat_quota, check_workspace_quota

router = APIRouter(prefix="/orgs", tags=["orgs"])


# ── helpers ─────────────────────────────────────────────────────────────

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


# ── org CRUD ────────────────────────────────────────────────────────────


@router.post("", response_model=OrgOut, status_code=status.HTTP_201_CREATED)
async def create_org(
    body: OrgCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> OrgOut:
    await check_org_quota(session, user.id)

    org = Org(name=body.name, plan="free")
    session.add(org)
    await session.flush()

    session.add(OrgMember(org_id=org.id, user_id=user.id, role="owner"))

    ws_name = body.first_workspace_name or "Default"
    slug = await _ensure_unique_slug(session, org.id, _slugify(ws_name))
    session.add(Workspace(
        org_id=org.id, name=ws_name, slug=slug, created_by_user_id=user.id,
    ))

    # Keep the deprecated users.org_id pointing at the most recently-created
    # org so legacy code paths still resolve a current org.
    user.org_id = org.id

    await session.commit()
    await session.refresh(org)
    return OrgOut(
        id=org.id, name=org.name, plan=org.plan, role="owner",
        created_at=org.created_at, ai_enabled=_ai_enabled_for(org.plan),
        force_deterministic_only=bool(org.force_deterministic_only),
        allow_private_targets=bool(org.allow_private_targets),
        security_lake_enabled=bool(org.security_lake_enabled),
    )


@router.get("", response_model=list[OrgOut])
async def list_my_orgs(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[OrgOut]:
    rows = (
        await session.execute(
            select(Org, OrgMember.role)
            .join(OrgMember, OrgMember.org_id == Org.id)
            .where(OrgMember.user_id == user.id)
            .order_by(Org.created_at.asc())
        )
    ).all()
    return [
        OrgOut(
            id=o.id, name=o.name, plan=o.plan, role=role,
            created_at=o.created_at, ai_enabled=_ai_enabled_for(o.plan),
            force_deterministic_only=bool(o.force_deterministic_only),
            allow_private_targets=bool(o.allow_private_targets),
            security_lake_enabled=bool(o.security_lake_enabled),
        )
        for o, role in rows
    ]


@router.get("/{org_id}", response_model=OrgOut)
async def get_org(
    org_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> OrgOut:
    member = await get_membership(session, user.id, org_id)
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "org not found")
    org = await session.get(Org, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "org not found")
    return OrgOut(
        id=org.id, name=org.name, plan=org.plan, role=member.role,
        created_at=org.created_at, ai_enabled=_ai_enabled_for(org.plan),
        force_deterministic_only=bool(org.force_deterministic_only),
        allow_private_targets=bool(org.allow_private_targets),
        security_lake_enabled=bool(org.security_lake_enabled),
    )


@router.patch("/{org_id}", response_model=OrgOut)
async def update_org(
    org_id: str,
    body: OrgUpdate,
    request: Request,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
) -> OrgOut:
    user, member = ctx
    org = await session.get(Org, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "org not found")
    if body.name is not None:
        org.name = body.name
    # Per-feature-001: force_deterministic_only kill switch. Admin/owner role
    # already enforced by the require_org_role decorator above. Every flip is
    # audit-logged with actor + before/after state for compliance review.
    if body.force_deterministic_only is not None:
        before = bool(org.force_deterministic_only)
        after = bool(body.force_deterministic_only)
        if before != after:
            org.force_deterministic_only = after
            session.add(AuditLog(
                user_id=user.id,
                org_id=org.id,
                action="org.force_deterministic_only.toggle",
                entity_type="org",
                entity_id=org.id,
                meta={"before": before, "after": after, "actor_role": member.role},
            ))
    # Sub-project A (host-target-kind): allow_private_targets flip. The schema
    # validator (OrgUpdate._ack_required_to_enable_private) already rejects
    # enable-without-ack with 422 before we reach here.
    if body.allow_private_targets is not None:
        prior = bool(org.allow_private_targets)
        new_val = bool(body.allow_private_targets)
        if prior != new_val:
            org.allow_private_targets = new_val
            session.add(AuditLog(
                user_id=user.id,
                org_id=org.id,
                action="org.allow_private_targets.flip",
                entity_type="org",
                entity_id=org.id,
                request_ip=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                meta={
                    "prior": prior,
                    "new": new_val,
                    "ack_provided": bool(body.private_targets_disclosure_ack),
                },
            ))
    if body.security_lake_enabled is not None:
        before = bool(org.security_lake_enabled)
        if apply_lake_toggle(org, enabled=bool(body.security_lake_enabled),
                             now=datetime.now(tz=timezone.utc)):
            session.add(AuditLog(
                user_id=user.id,
                org_id=org.id,
                action="org.security_lake_enabled.toggle",
                entity_type="org",
                entity_id=org.id,
                request_ip=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                meta={"before": before, "after": bool(org.security_lake_enabled),
                      "actor_role": member.role},
            ))
    await session.commit()
    await session.refresh(org)
    return OrgOut(
        id=org.id, name=org.name, plan=org.plan, role=member.role,
        created_at=org.created_at, ai_enabled=_ai_enabled_for(org.plan),
        force_deterministic_only=bool(org.force_deterministic_only),
        allow_private_targets=bool(org.allow_private_targets),
        security_lake_enabled=bool(org.security_lake_enabled),
    )


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_org(
    org_id: str,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner")),
    session: AsyncSession = Depends(get_session),
) -> None:
    org = await session.get(Org, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "org not found")
    await session.delete(org)
    await session.commit()


# ── members ─────────────────────────────────────────────────────────────


@router.get("/{org_id}/members", response_model=list[MemberOut])
async def list_members(
    org_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[MemberOut]:
    member = await get_membership(session, user.id, org_id)
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "org not found")
    rows = (
        await session.execute(
            select(User, OrgMember.role, OrgMember.created_at)
            .join(OrgMember, OrgMember.user_id == User.id)
            .where(OrgMember.org_id == org_id)
            .order_by(OrgMember.created_at.asc())
        )
    ).all()
    return [
        MemberOut(
            user_id=u.id, email=u.email, name=u.name, role=role, created_at=created,
        )
        for u, role, created in rows
    ]


@router.patch("/{org_id}/members/{user_id}", response_model=MemberOut)
async def update_member_role(
    org_id: str,
    user_id: str,
    body: MemberRoleUpdate,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
) -> MemberOut:
    caller, caller_member = ctx
    target = await get_membership(session, user_id, org_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "member not found")

    # Only owners can promote/demote owners.
    if body.role == "owner" or target.role == "owner":
        if caller_member.role != "owner":
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "only owners can change owner role"
            )
    target.role = body.role
    await session.commit()
    await session.refresh(target)
    u = await session.get(User, user_id)
    return MemberOut(
        user_id=u.id, email=u.email, name=u.name, role=target.role,
        created_at=target.created_at,
    )


@router.delete("/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    org_id: str,
    user_id: str,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
) -> None:
    caller, caller_member = ctx
    target = await get_membership(session, user_id, org_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "member not found")
    if target.role == "owner":
        owner_count = (
            await session.execute(
                select(OrgMember).where(
                    OrgMember.org_id == org_id, OrgMember.role == "owner"
                )
            )
        ).scalars().all()
        if len(owner_count) <= 1:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "cannot remove the last owner"
            )
    await session.delete(target)
    await session.commit()


# ── invites ─────────────────────────────────────────────────────────────


@router.post(
    "/{org_id}/invites",
    response_model=InviteOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_invite(
    org_id: str,
    body: InviteCreate,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
) -> InviteOut:
    user, caller_member = ctx
    if body.role == "owner" and caller_member.role != "owner":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "only owners can invite new owners"
        )
    await check_seat_quota(session, org_id)

    raw, hashed = generate_token()
    invite = OrgInvite(
        org_id=org_id,
        email=body.email.lower(),
        role=body.role,
        token_hash=hashed,
        invited_by_user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=14),
    )
    session.add(invite)
    await session.commit()
    await session.refresh(invite)

    # Deliver the invite via Resend when configured. Delivery failure is
    # not fatal — the frontend still renders the ``token`` value so the
    # inviter can copy-share the link manually.
    org = await session.get(Org, org_id)
    settings = get_settings()
    app_url = (settings.email_app_url or settings.web_base_url).rstrip("/")
    invite_url = f"{app_url}/invite/{raw}"
    send_invite_email(
        to=invite.email,
        org_name=org.name if org else "Pencheff",
        invite_url=invite_url,
        role=invite.role,
        inviter_name=user.name,
    )

    return InviteOut(
        id=invite.id,
        email=invite.email,
        role=invite.role,
        invited_by_user_id=invite.invited_by_user_id,
        expires_at=invite.expires_at,
        accepted_at=invite.accepted_at,
        created_at=invite.created_at,
        token=raw,
    )


@router.get("/{org_id}/invites", response_model=list[InviteOut])
async def list_invites(
    org_id: str,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
) -> list[InviteOut]:
    rows = (
        await session.execute(
            select(OrgInvite).where(OrgInvite.org_id == org_id).order_by(
                OrgInvite.created_at.desc()
            )
        )
    ).scalars().all()
    return [
        InviteOut(
            id=i.id, email=i.email, role=i.role,
            invited_by_user_id=i.invited_by_user_id,
            expires_at=i.expires_at, accepted_at=i.accepted_at,
            created_at=i.created_at, token=None,
        )
        for i in rows
    ]


# Accept / lookup routes are unprefixed so the invite URL is short.
invite_router = APIRouter(prefix="/invites", tags=["invites"])


@invite_router.get("/{token}", response_model=InviteOut)
async def lookup_invite(
    token: str, session: AsyncSession = Depends(get_session)
) -> InviteOut:
    inv = (
        await session.execute(
            select(OrgInvite).where(OrgInvite.token_hash == hash_token(token))
        )
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "invite not found")
    if inv.accepted_at is not None:
        raise HTTPException(status.HTTP_410_GONE, "invite already accepted")
    if inv.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_410_GONE, "invite expired")
    return InviteOut(
        id=inv.id, email=inv.email, role=inv.role,
        invited_by_user_id=inv.invited_by_user_id,
        expires_at=inv.expires_at, accepted_at=inv.accepted_at,
        created_at=inv.created_at, token=None,
    )


@invite_router.post("/{token}/accept", response_model=OrgOut)
async def accept_invite(
    token: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> OrgOut:
    inv = (
        await session.execute(
            select(OrgInvite).where(OrgInvite.token_hash == hash_token(token))
        )
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "invite not found")
    if inv.accepted_at is not None:
        raise HTTPException(status.HTTP_410_GONE, "invite already accepted")
    if inv.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_410_GONE, "invite expired")
    if inv.email.lower() != user.email.lower():
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this invite is for a different email address",
        )

    existing = await get_membership(session, user.id, inv.org_id)
    if existing is None:
        await check_seat_quota(session, inv.org_id)
        session.add(OrgMember(org_id=inv.org_id, user_id=user.id, role=inv.role))
    inv.accepted_at = datetime.now(timezone.utc)
    user.org_id = inv.org_id

    await session.commit()

    org = await session.get(Org, inv.org_id)
    return OrgOut(
        id=org.id, name=org.name, plan=org.plan, role=inv.role,
        created_at=org.created_at, ai_enabled=_ai_enabled_for(org.plan),
        force_deterministic_only=bool(org.force_deterministic_only),
        allow_private_targets=bool(org.allow_private_targets),
        security_lake_enabled=bool(org.security_lake_enabled),
    )
