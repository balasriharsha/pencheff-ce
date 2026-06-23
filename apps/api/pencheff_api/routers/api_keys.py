"""PENCHEFF_API_KEY CRUD.

All endpoints in this router are session-only — keys can never be created
or revoked using another key (defence in depth: a leaked key cannot mint
more keys for itself).

Plan caps
---------
``api_keys_per_user`` in :mod:`services.quota` decides how many active
(non-revoked) keys a single user may hold. Free orgs default to 5 to keep
the surface containable; paid orgs are effectively uncapped at 200.

Org / workspace scoping
-----------------------
- A key always names exactly one ``org_id`` (the issuing user must be a
  member of that org).
- ``workspace_id = NULL`` is permitted only for org owners and admins —
  members must pin every key to a specific workspace they belong to.
- Scopes are validated against :data:`auth.scopes.SCOPE_CATALOG`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.api_key import generate_key
from ..auth.deps import get_current_user, get_membership, session_only
from ..auth.scopes import (
    SCOPE_CATALOG,
    expand_wildcards,
    validate_scopes,
)
from ..db.base import get_session
from ..db.models import ApiKey, AuditLog, OrgMember, User, Workspace

router = APIRouter(prefix="/api/v1/api-keys", tags=["api-keys"])

MAX_KEYS_PER_USER = 50


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    org_id: str
    workspace_id: Optional[str] = None
    scopes: list[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None


class ApiKeyUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    scopes: Optional[list[str]] = None
    expires_at: Optional[datetime] = None


class ApiKeyOut(BaseModel):
    id: str
    name: str
    prefix: str
    org_id: str
    workspace_id: Optional[str]
    scopes: list[str]
    effective_scopes: list[str]
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    revoked_at: Optional[datetime]
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    """Issued only on POST. ``key`` is the plaintext — show once, never again."""

    key: str


def _serialise(row: ApiKey, *, full_key: str | None = None) -> dict:
    out = {
        "id": row.id,
        "name": row.name,
        "prefix": row.prefix,
        "org_id": row.org_id,
        "workspace_id": row.workspace_id,
        "scopes": list(row.scopes or []),
        "effective_scopes": expand_wildcards(list(row.scopes or [])),
        "expires_at": row.expires_at,
        "last_used_at": row.last_used_at,
        "revoked_at": row.revoked_at,
        "created_at": row.created_at,
    }
    if full_key is not None:
        out["key"] = full_key
    return out


@router.get("/scopes")
async def list_scopes(
    user: User = Depends(session_only),
) -> dict:
    """Return the full scope catalog so the dashboard can render a picker."""
    return {
        "scopes": [{"scope": s, "description": d} for s, d in SCOPE_CATALOG],
    }


@router.get("", response_model=list[ApiKeyOut])
async def list_keys(
    user: User = Depends(session_only),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    rows = (
        await session.execute(
            select(ApiKey)
            .where(ApiKey.user_id == user.id)
            .order_by(ApiKey.created_at.desc())
        )
    ).scalars().all()
    return [_serialise(r) for r in rows]


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_key(
    body: ApiKeyCreate,
    user: User = Depends(session_only),
    session: AsyncSession = Depends(get_session),
) -> dict:
    member = await get_membership(session, user.id, body.org_id)
    if member is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of this org")

    if body.workspace_id is None:
        if member.role not in ("owner", "admin"):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "only org owners and admins may mint org-wide keys (omit workspace_id)",
            )
    else:
        ws = await session.get(Workspace, body.workspace_id)
        if ws is None or ws.org_id != body.org_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "workspace_id does not belong to org_id",
            )

    try:
        scopes = validate_scopes(body.scopes)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    if not scopes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "at least one scope is required")

    if body.expires_at is not None and body.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "expires_at must be in the future")

    active_count = (
        await session.execute(
            select(func.count(ApiKey.id)).where(
                ApiKey.user_id == user.id, ApiKey.revoked_at.is_(None)
            )
        )
    ).scalar_one()
    if active_count >= MAX_KEYS_PER_USER:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"maximum {MAX_KEYS_PER_USER} active keys per user reached — revoke an unused key first",
        )

    full, prefix, digest = generate_key()
    row = ApiKey(
        user_id=user.id,
        org_id=body.org_id,
        workspace_id=body.workspace_id,
        name=body.name,
        prefix=prefix,
        key_hash=digest,
        scopes=scopes,
        expires_at=body.expires_at,
    )
    session.add(row)

    audit = AuditLog(
        user_id=user.id,
        org_id=body.org_id,
        workspace_id=body.workspace_id,
        action="api_key.create",
        entity_type="api_key",
        entity_id=row.id,
        meta={"prefix": prefix, "scopes": scopes},
    )
    session.add(audit)

    await session.commit()
    await session.refresh(row)
    return _serialise(row, full_key=full)


@router.patch("/{key_id}", response_model=ApiKeyOut)
async def update_key(
    key_id: str,
    body: ApiKeyUpdate,
    user: User = Depends(session_only),
    session: AsyncSession = Depends(get_session),
) -> dict:
    row = await session.get(ApiKey, key_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "api key not found")
    if row.revoked_at is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "api key is revoked")

    if body.name is not None:
        row.name = body.name
    if body.scopes is not None:
        try:
            row.scopes = validate_scopes(body.scopes)
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
        if not row.scopes:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "at least one scope is required")
    if body.expires_at is not None:
        if body.expires_at <= datetime.now(timezone.utc):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "expires_at must be in the future")
        row.expires_at = body.expires_at

    session.add(
        AuditLog(
            user_id=user.id,
            org_id=row.org_id,
            workspace_id=row.workspace_id,
            action="api_key.update",
            entity_type="api_key",
            entity_id=row.id,
            meta={"prefix": row.prefix},
        )
    )
    await session.commit()
    await session.refresh(row)
    return _serialise(row)


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(
    key_id: str,
    user: User = Depends(session_only),
    session: AsyncSession = Depends(get_session),
) -> None:
    row = await session.get(ApiKey, key_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "api key not found")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        session.add(
            AuditLog(
                user_id=user.id,
                org_id=row.org_id,
                workspace_id=row.workspace_id,
                action="api_key.revoke",
                entity_type="api_key",
                entity_id=row.id,
                meta={"prefix": row.prefix},
            )
        )
        await session.commit()
