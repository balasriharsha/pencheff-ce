"""PENCHEFF_API_KEY verification.

Format
------
``pcf_live_<32+ url-safe base64 chars>``

The first 8 chars after ``pcf_live_`` are the lookup ``prefix`` (indexed
unique column on ``api_keys.prefix``). The full token is then verified
with a constant-time comparison against the stored SHA-256 hex digest.

Why SHA-256 (no bcrypt)?
    The full token is 256 bits of entropy from
    :func:`secrets.token_urlsafe`, so a brute force is infeasible. Bcrypt's
    work factor is unnecessary here and would make every authenticated
    request expensive.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import ApiKey, OrgMember, User, Workspace

KEY_PREFIX_SENTINEL = "pcf_live_"
PREFIX_LEN = 8  # chars from the random portion that act as the lookup prefix
SECRET_LEN = 32  # bytes — yields ~43 url-safe base64 chars

# ``last_used_at`` is debounced — we only commit the row if at least this
# many seconds have elapsed since the previous write. Without this every
# authenticated request issues a row UPDATE on the api_keys table, which
# turns into a hot-row contention problem on busy keys (e.g. a CI key
# polling the queue). 60 s is granular enough for "is this key still
# being used?" dashboards while keeping write amplification bounded.
LAST_USED_DEBOUNCE_SECONDS = 60


def generate_key() -> tuple[str, str, str]:
    """Mint a fresh key. Returns (full_key, prefix, hash)."""
    secret = secrets.token_urlsafe(SECRET_LEN)
    prefix = secret[:PREFIX_LEN]
    full = f"{KEY_PREFIX_SENTINEL}{secret}"
    digest = hashlib.sha256(full.encode("utf-8")).hexdigest()
    return full, prefix, digest


def hash_key(full_key: str) -> str:
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()


def looks_like_api_key(token: str) -> bool:
    return token.startswith(KEY_PREFIX_SENTINEL)


async def verify_api_key(
    session: AsyncSession, full_key: str
) -> tuple[ApiKey, User]:
    """Verify a key and return (api_key_row, issuing_user).

    Performs an indexed lookup by prefix, a constant-time hash comparison,
    and re-validates that the issuing user is still a member of the key's
    org. Stale memberships invalidate the key immediately.

    Raises ``HTTPException(401)`` on every failure mode — never leak
    *which* check failed.
    """
    if not looks_like_api_key(full_key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid api key")

    secret_part = full_key[len(KEY_PREFIX_SENTINEL):]
    if len(secret_part) < PREFIX_LEN + 8:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid api key")

    prefix = secret_part[:PREFIX_LEN]
    row = (
        await session.execute(select(ApiKey).where(ApiKey.prefix == prefix))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid api key")

    expected = hash_key(full_key)
    if not hmac.compare_digest(row.key_hash, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid api key")

    if row.revoked_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "api key revoked")

    if row.expires_at is not None and row.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "api key expired")

    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "issuing user inactive")

    member = (
        await session.execute(
            select(OrgMember).where(
                OrgMember.user_id == user.id, OrgMember.org_id == row.org_id
            )
        )
    ).scalar_one_or_none()
    if member is None:
        # User no longer belongs to the org — key is dead, even if it has
        # not been explicitly revoked.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "issuing user is not a member of this org")

    if row.workspace_id is not None:
        ws = await session.get(Workspace, row.workspace_id)
        if ws is None or ws.org_id != row.org_id:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "key workspace no longer exists")

    # Best-effort, debounced last_used_at — see LAST_USED_DEBOUNCE_SECONDS.
    # Only commit when the previous write is older than the debounce window
    # (or there has never been one).
    now = datetime.now(timezone.utc)
    last = row.last_used_at
    if last is None or (now - last).total_seconds() >= LAST_USED_DEBOUNCE_SECONDS:
        try:
            row.last_used_at = now
            await session.commit()
        except Exception:
            await session.rollback()

    return row, user
