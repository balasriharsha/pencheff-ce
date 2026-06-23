"""Clerk session JWT verification and user lookup.

Clerk signs session tokens with RS256 using a per-instance JWKS. The
frontend-api host is encoded in the publishable key (everything after
``pk_<env>_`` is base64url of ``<host>$``), which lets us derive the JWKS
URL without extra configuration.
"""

from __future__ import annotations

import base64
import threading
import time

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from ..config import get_settings

_settings = get_settings()

# Refresh the JWKS at most every _JWKS_TTL seconds; clear on verification
# failure so key rotation recovers automatically.
_JWKS_TTL = 60 * 60
_jwks_cache: dict | None = None
_jwks_fetched_at: float = 0.0
_jwks_lock = threading.Lock()


def _derive_frontend_api_host() -> str:
    if _settings.clerk_jwks_url:
        # When operators override the JWKS URL directly, skip derivation.
        return ""
    pk = _settings.clerk_publishable_key
    if not pk:
        raise RuntimeError("CLERK_PUBLISHABLE_KEY is not configured")
    try:
        env, payload = pk.split("_", 1)[1].split("_", 1) if pk.count("_") >= 2 else (None, None)
    except ValueError:
        env, payload = None, None
    # pk format: pk_test_<base64> or pk_live_<base64>; the base64 decodes to "<host>$"
    parts = pk.split("_", 2)
    if len(parts) != 3:
        raise RuntimeError(f"invalid Clerk publishable key format: {pk!r}")
    b64 = parts[2]
    pad = "=" * (-len(b64) % 4)
    host = base64.urlsafe_b64decode(b64 + pad).decode("utf-8").rstrip("$")
    return host


def _jwks_url() -> str:
    if _settings.clerk_jwks_url:
        return _settings.clerk_jwks_url
    host = _derive_frontend_api_host()
    return f"https://{host}/.well-known/jwks.json"


def _fetch_jwks(force: bool = False) -> dict:
    global _jwks_cache, _jwks_fetched_at
    with _jwks_lock:
        now = time.time()
        if (
            not force
            and _jwks_cache is not None
            and now - _jwks_fetched_at < _JWKS_TTL
        ):
            return _jwks_cache
        r = httpx.get(_jwks_url(), timeout=5.0)
        r.raise_for_status()
        _jwks_cache = r.json()
        _jwks_fetched_at = now
        return _jwks_cache


def decode_clerk_jwt(token: str) -> dict:
    """Verify and return the claims of a Clerk-issued session JWT.

    Raises ``jwt.InvalidTokenError`` on failure.
    """
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if not kid:
        raise jwt.InvalidTokenError("token header missing kid")

    for attempt in (False, True):
        jwks = _fetch_jwks(force=attempt)
        key_entry = next(
            (k for k in jwks.get("keys", []) if k.get("kid") == kid), None
        )
        if key_entry is None:
            continue
        public_key = RSAAlgorithm.from_jwk(key_entry)
        return jwt.decode(
            token,
            public_key,
            algorithms=[key_entry.get("alg", "RS256")],
            options={"verify_aud": False},
            leeway=30,
        )
    raise jwt.InvalidTokenError("signing key not found in JWKS")


def fetch_clerk_user(clerk_user_id: str) -> dict:
    """Fetch the authoritative user record from Clerk's Backend API."""
    if not _settings.clerk_secret_key:
        raise RuntimeError("CLERK_SECRET_KEY is not configured")
    r = httpx.get(
        f"https://api.clerk.com/v1/users/{clerk_user_id}",
        headers={"Authorization": f"Bearer {_settings.clerk_secret_key}"},
        timeout=5.0,
    )
    r.raise_for_status()
    return r.json()


def primary_email(user_json: dict) -> str | None:
    """Extract the user's primary email from a Clerk user payload."""
    primary_id = user_json.get("primary_email_address_id")
    for e in user_json.get("email_addresses", []) or []:
        if e.get("id") == primary_id:
            return e.get("email_address")
    emails = user_json.get("email_addresses", []) or []
    if emails:
        return emails[0].get("email_address")
    return None


def display_name(user_json: dict) -> str | None:
    first = user_json.get("first_name") or ""
    last = user_json.get("last_name") or ""
    full = f"{first} {last}".strip()
    if full:
        return full
    return user_json.get("username")


# ---------------------------------------------------------------------------
# Subscription plan lookup via Clerk Backend API
# ---------------------------------------------------------------------------

_PLAN_TTL = 60  # seconds
_plan_cache: dict[str, tuple[float, str | None]] = {}
_plan_lock = threading.Lock()


def _extract_plan_key(obj: dict) -> str | None:
    """Recursively look for a plan identifier in a Clerk JSON payload."""
    if not isinstance(obj, dict):
        return None
    for key in ("slug", "plan_slug", "key", "plan_key", "name"):
        v = obj.get(key)
        if isinstance(v, str) and v:
            return v
    plan = obj.get("plan")
    if isinstance(plan, dict):
        nested = _extract_plan_key(plan)
        if nested:
            return nested
    return None


def plan_key_from_user_json(user_json: dict) -> str | None:
    """Best-effort extraction of the subscription plan key from a Clerk user
    payload. Inspects commonly-used locations (top-level billing fields,
    public/private/unsafe metadata) so that when the user's session token
    lacks plan claims we can still resolve it from the record itself.
    """
    if not isinstance(user_json, dict):
        return None

    # Direct top-level fields that Clerk has used in various versions.
    for top in ("billing", "subscription", "current_subscription"):
        nested = user_json.get(top)
        if isinstance(nested, dict):
            key = _extract_plan_key(nested)
            if key:
                return key
            subs = nested.get("subscriptions") or nested.get("data")
            if isinstance(subs, list):
                for s in subs:
                    key = _extract_plan_key(s) if isinstance(s, dict) else None
                    if key:
                        return key

    for top in ("current_plan_key", "plan_key", "plan"):
        v = user_json.get(top)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, dict):
            key = _extract_plan_key(v)
            if key:
                return key

    for meta_field in ("public_metadata", "private_metadata", "unsafe_metadata"):
        meta = user_json.get(meta_field)
        if isinstance(meta, dict):
            for k in ("plan", "subscription_plan", "plan_key"):
                v = meta.get(k)
                if isinstance(v, str) and v:
                    return v
    return None


def fetch_clerk_subscription_plan(clerk_user_id: str) -> str | None:
    """Return the user's current subscription plan key via Clerk's Backend API.

    Clerk's commerce API surface has changed several times; we try the known
    endpoints in order and return the first plan key we find. ``None`` if
    none of them yield an active subscription.
    """
    if not _settings.clerk_secret_key:
        raise RuntimeError("CLERK_SECRET_KEY is not configured")

    with _plan_lock:
        cached = _plan_cache.get(clerk_user_id)
        if cached and time.time() - cached[0] < _PLAN_TTL:
            return cached[1]

    headers = {"Authorization": f"Bearer {_settings.clerk_secret_key}"}

    # Candidate endpoints — each may or may not exist depending on the
    # instance's Clerk Billing version. We also inspect the base user
    # record, which on newer instances embeds billing / plan data.
    urls = [
        f"https://api.clerk.com/v1/users/{clerk_user_id}/billing/subscription",
        f"https://api.clerk.com/v1/users/{clerk_user_id}/commerce/subscription",
        f"https://api.clerk.com/v1/commerce/subscriptions?user_id={clerk_user_id}",
        f"https://api.clerk.com/v1/commerce/users/{clerk_user_id}/subscriptions",
        f"https://api.clerk.com/v1/users/{clerk_user_id}",
    ]

    plan_key: str | None = None
    for url in urls:
        try:
            r = httpx.get(url, headers=headers, timeout=5.0)
        except httpx.HTTPError:
            continue
        if r.status_code == 404:
            continue
        if r.status_code >= 400:
            continue
        try:
            data = r.json()
        except ValueError:
            continue

        # If this is the full user record, mine it for plan hints first.
        if url.endswith(f"/v1/users/{clerk_user_id}") and isinstance(data, dict):
            plan_key = plan_key_from_user_json(data)
            if plan_key:
                break

        # Response could be a subscription object, a list, or a paginated
        # envelope ``{"data": [...]}``.
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            items = data["data"]
        elif isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = [data]
        else:
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue
            # Prefer an active subscription.
            status_val = (item.get("status") or "").lower()
            if status_val and status_val not in {"active", "trialing"}:
                continue
            plan_key = _extract_plan_key(item)
            if plan_key:
                break
        if plan_key:
            break

    with _plan_lock:
        _plan_cache[clerk_user_id] = (time.time(), plan_key)
    return plan_key
