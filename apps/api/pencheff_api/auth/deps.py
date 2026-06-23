from __future__ import annotations

import logging

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.base import get_session
from ..db.models import Org, OrgMember, User, Workspace
from .api_key import KEY_PREFIX_SENTINEL, looks_like_api_key, verify_api_key
from .clerk import (
    decode_clerk_jwt,
    display_name,
    fetch_clerk_subscription_plan,
    fetch_clerk_user,
    primary_email,
)
from .jwt import decode_token as decode_native_token
from .scopes import scope_matches

_log = logging.getLogger("pencheff.auth")


# Map Clerk plan keys (configured in the Clerk dashboard) to the values
# used by ``services.quota.PLAN_LIMITS``.
_CLERK_PLAN_TO_LOCAL: dict[str, str] = {
    "free_user": "free",
    "pro": "pro",
    "team": "team",
}


ONBOARDING_REQUIRED = "ONBOARDING_REQUIRED"


def _plan_from_claims(payload: dict) -> str | None:
    """Extract the current subscription plan from a Clerk session JWT.

    See the git history of this file for the full list of claim shapes
    Clerk has shipped — the logic below is deliberately forgiving.
    """
    candidates: list[str] = []

    raw = payload.get("pla")
    if isinstance(raw, str):
        candidates.extend(raw.split(","))
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                candidates.append(item)
            elif isinstance(item, dict):
                for k in ("plan", "key", "k", "slug"):
                    v = item.get(k)
                    if isinstance(v, str):
                        candidates.append(v)

    for key in ("plan", "subscription_plan", "plan_key"):
        v = payload.get(key)
        if isinstance(v, str):
            candidates.append(v)

    for entry in candidates:
        entry = entry.strip()
        if not entry:
            continue
        _, _, key = entry.rpartition(":")
        if not key:
            key = entry
        mapped = _CLERK_PLAN_TO_LOCAL.get(key)
        if mapped and mapped != "free":
            return mapped
        if mapped == "free":
            pass

    return None


async def _provision_user_from_clerk(
    session: AsyncSession, clerk_user_id: str
) -> User:
    """Create a bare ``User`` row for a freshly-signed-up Clerk identity.

    No org is auto-created. The frontend is expected to route the caller
    through ``/onboarding`` where they pick an org name and first workspace.
    """
    info = fetch_clerk_user(clerk_user_id)
    email = primary_email(info)
    if not email:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Clerk user has no email address on file",
        )
    name = display_name(info) or email

    existing_user = (
        await session.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()
    if existing_user is not None:
        existing_user.google_sub = clerk_user_id
        if not existing_user.name:
            existing_user.name = name
        await session.commit()
        await session.refresh(existing_user)
        return existing_user

    user = User(
        email=email,
        name=name,
        google_sub=clerk_user_id,
        org_id=None,
        is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _sync_plan_for_user(session: AsyncSession, user: User, plan: str) -> None:
    """Keep the plan cache fresh for every org the user belongs to."""
    member_rows = (
        await session.execute(
            select(OrgMember.org_id).where(OrgMember.user_id == user.id)
        )
    ).scalars().all()
    for org_id in member_rows:
        current = (
            await session.execute(select(Org.plan).where(Org.id == org_id))
        ).scalar_one_or_none()
        if current == plan or current == "self_hosted":
            continue
        org = await session.get(Org, org_id)
        if org is None:
            continue
        org.plan = plan
    await session.commit()


async def _user_from_token(session: AsyncSession, token: str) -> User:
    try:
        payload = decode_clerk_jwt(token)
    except jwt.InvalidTokenError:
        return await _user_from_native_token(session, token)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token verification failed")

    clerk_user_id = payload.get("sub")
    if not clerk_user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token claims")

    plan = _plan_from_claims(payload)
    if plan is None:
        _log.info(
            "no plan claim in Clerk JWT; payload keys=%s — falling back to backend API",
            sorted(payload.keys()),
        )
        try:
            raw_plan = fetch_clerk_subscription_plan(clerk_user_id)
        except Exception as exc:
            _log.warning("Clerk subscription lookup failed for %s: %s", clerk_user_id, exc)
            raw_plan = None
        plan = _CLERK_PLAN_TO_LOCAL.get(raw_plan or "", "free")

    user = (
        await session.execute(select(User).where(User.google_sub == clerk_user_id))
    ).scalar_one_or_none()
    if user is None:
        user = await _provision_user_from_clerk(session, clerk_user_id)
    await _sync_plan_for_user(session, user, plan)

    if not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user is inactive")
    return user


async def _user_from_native_token(session: AsyncSession, token: str) -> User:
    """Validate a JWT issued by ``auth.jwt.make_access_token``.

    The native token path (signup / login / OAuth via ``routers/auth.py``)
    issues HS-signed JWTs that the Clerk verifier cannot accept. We try
    Clerk first (the web app's primary identity); if that fails, fall
    through here. The native flow already provisions an Org on signup
    via ``_provision_tenancy``, so no plan sync is needed.
    """
    try:
        payload = decode_native_token(token)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not an access token")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token claims")
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    if not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user is inactive")
    return user


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    # Query param fallback is only for short-lived JWTs (SSE / EventSource
    # clients that cannot set headers). API keys MUST come from the header
    # — see ``get_current_user`` for the rejection.
    return request.query_params.get("token") or None


async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> User:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")

    if looks_like_api_key(token):
        # Reject API keys passed via ``?token=`` — header-only.
        if not request.headers.get("authorization", "").lower().startswith("bearer "):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "api keys must be sent in the Authorization header",
            )
        api_key, user = await verify_api_key(session, token)
        # Stash auth context on request.state for downstream dependencies
        # (``require_scope``, ``get_active_workspace``, ``session_only``).
        request.state.auth_kind = "api_key"
        request.state.api_key_id = api_key.id
        request.state.api_key_org_id = api_key.org_id
        request.state.api_key_workspace_id = api_key.workspace_id
        request.state.api_key_scopes = list(api_key.scopes or [])
        return user

    request.state.auth_kind = "session"
    return await _user_from_token(session, token)


async def _resolve_active_workspace(
    request: Request, user: User, session: AsyncSession
) -> Workspace:
    """Resolve and authorise the workspace scope for the current request.

    Reads ``X-Workspace-Id`` (preferred) or ``?workspace_id=`` (for SSE /
    EventSource clients that cannot set headers). Confirms the caller is a
    member of that workspace's org. Raises:

      * ``409 ONBOARDING_REQUIRED`` — user has no org memberships yet.
      * ``400`` — no workspace identifier provided and user has multiple orgs
        (the caller must pick explicitly).
      * ``403`` — the user is not a member of the workspace's org.
      * ``404`` — workspace does not exist.

    For API-keyed requests: the workspace is forced from the key itself.
    A request header that disagrees with the key's pinned workspace is
    rejected (403). A key with ``workspace_id = NULL`` permits any
    workspace in the key's org and falls through to the header logic.
    """
    auth_kind = getattr(request.state, "auth_kind", "session")
    if auth_kind == "api_key":
        key_org = request.state.api_key_org_id
        key_ws = request.state.api_key_workspace_id
        if key_ws is not None:
            header_ws = (
                request.headers.get("x-workspace-id")
                or request.query_params.get("workspace_id")
            )
            if header_ws and header_ws != key_ws:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "api key is pinned to a different workspace",
                )
            ws = await session.get(Workspace, key_ws)
            if ws is None or ws.org_id != key_org:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
            return ws
        # Key is org-scoped only — caller must specify a workspace, and it
        # must belong to the key's org.
        ws_id = (
            request.headers.get("x-workspace-id")
            or request.query_params.get("workspace_id")
            or None
        )
        if not ws_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "missing X-Workspace-Id header (org-scoped api key)",
            )
        ws = await session.get(Workspace, ws_id)
        if ws is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
        if ws.org_id != key_org:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "workspace is outside the api key's org"
            )
        return ws

    memberships = (
        await session.execute(
            select(OrgMember.org_id).where(OrgMember.user_id == user.id)
        )
    ).scalars().all()
    if not memberships:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            ONBOARDING_REQUIRED,
        )

    ws_id = (
        request.headers.get("x-workspace-id")
        or request.query_params.get("workspace_id")
        or None
    )
    if not ws_id:
        # Convenience: if the user belongs to a single org and that org has
        # exactly one workspace, fall back to it. Multi-org users must send
        # the header.
        if len(memberships) != 1:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "missing X-Workspace-Id header",
            )
        rows = (
            await session.execute(
                select(Workspace).where(Workspace.org_id == memberships[0])
            )
        ).scalars().all()
        if len(rows) != 1:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "missing X-Workspace-Id header",
            )
        return rows[0]

    ws = await session.get(Workspace, ws_id)
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    if ws.org_id not in memberships:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of this workspace")
    return ws


async def get_active_workspace(
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Workspace:
    return await _resolve_active_workspace(request, user, session)


async def get_membership(
    session: AsyncSession, user_id: str, org_id: str
) -> OrgMember | None:
    return (
        await session.execute(
            select(OrgMember).where(
                OrgMember.user_id == user_id, OrgMember.org_id == org_id
            )
        )
    ).scalar_one_or_none()


def require_role(*allowed: str):
    """FastAPI dependency factory — only users with one of the listed roles
    in the workspace's org may call the endpoint."""

    async def _dep(
        user: User = Depends(get_current_user),
        workspace: Workspace = Depends(get_active_workspace),
        session: AsyncSession = Depends(get_session),
    ) -> tuple[User, Workspace]:
        member = await get_membership(session, user.id, workspace.org_id)
        if member is None or member.role not in allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"role '{member.role if member else 'none'}' cannot perform this action",
            )
        return user, workspace

    return _dep


def require_org_role(*allowed: str):
    """Variant of ``require_role`` for org-scoped endpoints where there is no
    active workspace yet (invites, member management, org settings)."""

    async def _dep(
        org_id: str,
        user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_session),
    ) -> tuple[User, OrgMember]:
        member = await get_membership(session, user.id, org_id)
        if member is None or member.role not in allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"role '{member.role if member else 'none'}' cannot perform this action",
            )
        return user, member

    return _dep


def require_scope(scope: str):
    """FastAPI dependency factory — endpoints declare the scope they need.

    Default-deny for API keys: a key without ``scope`` (or a wildcard that
    covers it) is rejected with 403. Session (Clerk JWT) callers always
    pass through — their permissions are governed by ``require_role``.

    Endpoints that should NEVER be callable with an API key (org admin,
    billing, the api-key router itself) attach ``session_only`` instead.
    """

    async def _dep(
        request: Request,
        user: User = Depends(get_current_user),
    ) -> User:
        if getattr(request.state, "auth_kind", "session") == "session":
            return user
        granted = getattr(request.state, "api_key_scopes", []) or []
        if not scope_matches(scope, granted):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"api key is missing required scope: {scope}",
            )
        return user

    return _dep


async def session_only(
    request: Request,
    user: User = Depends(get_current_user),
) -> User:
    """Reject API-keyed requests outright.

    Attach to endpoints that touch identity, billing, or key management —
    a stolen key must not be a path to escalation.
    """
    if getattr(request.state, "auth_kind", "session") == "api_key":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this endpoint requires a user session and cannot be called with an api key",
        )
    return user
