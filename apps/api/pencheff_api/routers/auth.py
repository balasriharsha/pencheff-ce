import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_current_user
from ..auth.jwt import decode_token, make_access_token, make_refresh_token
from ..auth.oauth_google import oauth
from ..auth.password import hash_password, verify_password
from ..config import get_settings
from ..db.base import get_session
from ..db.models import Org, OrgMember, User, Workspace
from ..schemas.auth import LoginRequest, Me, RefreshRequest, SignupRequest, TokenPair

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


async def _provision_tenancy(session: AsyncSession, user: User, org_name: str) -> Org:
    """Create an Org + owner membership + Default workspace for a new user."""
    org = Org(name=org_name, plan="free")
    session.add(org)
    await session.flush()
    session.add(OrgMember(org_id=org.id, user_id=user.id, role="owner"))
    session.add(Workspace(
        org_id=org.id, name="Default", slug="default",
        created_by_user_id=user.id,
    ))
    user.org_id = org.id
    return org


@router.post("/signup", response_model=TokenPair, status_code=status.HTTP_201_CREATED)
async def signup(body: SignupRequest, session: AsyncSession = Depends(get_session)) -> TokenPair:
    existing = (await session.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")
    user = User(
        email=body.email.lower(),
        name=body.name,
        password_hash=hash_password(body.password),
    )
    session.add(user)
    await session.flush()
    org = await _provision_tenancy(
        session, user,
        body.org_name or (body.name or body.email.split("@")[0]) + "'s org",
    )
    await session.commit()
    return TokenPair(
        access_token=make_access_token(user.id, org.id),
        refresh_token=make_refresh_token(user.id, org.id),
    )


@router.post("/login", response_model=TokenPair)
async def login(body: LoginRequest, session: AsyncSession = Depends(get_session)) -> TokenPair:
    user = (await session.execute(select(User).where(User.email == body.email.lower()))).scalar_one_or_none()
    if not user or not user.password_hash or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid email or password")
    return TokenPair(
        access_token=make_access_token(user.id, user.org_id or ""),
        refresh_token=make_refresh_token(user.id, user.org_id or ""),
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest, session: AsyncSession = Depends(get_session)) -> TokenPair:
    try:
        payload = decode_token(body.refresh_token)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid refresh token")
    if payload.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not a refresh token")
    user_id = payload["sub"]
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    return TokenPair(
        access_token=make_access_token(user.id, user.org_id or ""),
        refresh_token=make_refresh_token(user.id, user.org_id or ""),
    )


@router.post("/desktop-bridge", response_model=TokenPair)
async def desktop_bridge(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> TokenPair:
    """Exchange a Clerk session JWT for a long-lived native JWT pair.

    Pencheff Studio's loopback OAuth flow opens the web at
    /oauth/desktop-bridge; that page completes Clerk sign-in, then POSTs
    here with the user's Clerk session JWT. We re-issue a native access
    + refresh pair the Mac app stores in Keychain and uses for every
    subsequent API call. Refresh works via /auth/refresh, which already
    validates native JWTs after the deps.py fallback.

    Manual try/except (rather than ``Depends(get_current_user)``) so the
    bridge page surfaces the real failure cause — bare 500s on this
    endpoint are useless to debug remotely.
    """
    import logging
    import traceback as _tb
    _log = logging.getLogger("pencheff.auth.desktop_bridge")
    try:
        try:
            user = await get_current_user(request, session)
        except HTTPException:
            raise
        except RuntimeError as e:
            # Most common: CLERK_SECRET_KEY unset on the API; fresh-Clerk-user
            # provisioning calls fetch_clerk_user → raises RuntimeError.
            _log.exception("desktop-bridge: get_current_user RuntimeError")
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"desktop-bridge misconfigured on the server: {e}. "
                f"Check that CLERK_SECRET_KEY is set on the API.",
            )
        except Exception as e:
            _log.exception("desktop-bridge: get_current_user failed")
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                f"desktop-bridge auth failed: {type(e).__name__}: {e}",
            )

        if not user.org_id:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "user has no org membership; finish onboarding first",
            )

        try:
            return TokenPair(
                access_token=make_access_token(user.id, user.org_id),
                refresh_token=make_refresh_token(user.id, user.org_id),
            )
        except Exception as e:
            # JWT_SECRET missing/short / Pydantic shape mismatch / etc.
            _log.exception("desktop-bridge: token mint failed")
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                f"desktop-bridge token mint failed: {type(e).__name__}: {e}. "
                f"Likely cause: JWT_SECRET unset or too short on the API.",
            )
    except HTTPException:
        # Preserve specific 4xx/5xx with messages so the bridge page can
        # render them. Bare-500 with body "Internal Server Error" only
        # happens if something escapes this catch.
        raise
    except BaseException as e:  # noqa: BLE001 — last-resort safety net
        _log.exception("desktop-bridge: unexpected BaseException")
        tb = _tb.format_exc().splitlines()[-1]
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"desktop-bridge unexpected error: {type(e).__name__}: {e} ({tb})",
        )


@router.get("/me", response_model=Me)
async def me(user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)) -> Me:
    # A freshly-provisioned Clerk user has no orgs yet — the frontend will
    # route them through /onboarding. We return an empty-org shell here so
    # /me works as an identity probe.
    if not user.org_id:
        return Me(
            id=user.id, email=user.email, name=user.name,
            org_id="", org_name="", plan="free",
        )
    org = (await session.execute(select(Org).where(Org.id == user.org_id))).scalar_one_or_none()
    if org is None:
        return Me(
            id=user.id, email=user.email, name=user.name,
            org_id="", org_name="", plan="free",
        )
    return Me(id=user.id, email=user.email, name=user.name, org_id=org.id, org_name=org.name, plan=org.plan)


_LOOPBACK_RE = re.compile(r"^http://127\.0\.0\.1:\d{4,5}/callback$")


@router.get("/oauth/google/start")
async def google_start(
    request: Request,
    desktop_redirect: str | None = None,
    state: str | None = None,
):
    if "google" not in oauth._registry:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "google oauth not configured")
    if desktop_redirect is not None:
        if not _LOOPBACK_RE.fullmatch(desktop_redirect):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid desktop_redirect")
        request.session["desktop_redirect"] = desktop_redirect
        request.session["desktop_state"] = state or ""
    else:
        request.session.pop("desktop_redirect", None)
        request.session.pop("desktop_state", None)
    return await oauth.google.authorize_redirect(request, settings.google_redirect_uri)


@router.get("/oauth/google/callback")
async def google_callback(request: Request, session: AsyncSession = Depends(get_session)):
    if "google" not in oauth._registry:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "google oauth not configured")
    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get("userinfo") or await oauth.google.userinfo(token=token)
    sub = userinfo["sub"]
    email = (userinfo.get("email") or "").lower()
    name = userinfo.get("name")

    user = (await session.execute(select(User).where(User.google_sub == sub))).scalar_one_or_none()
    if not user and email:
        user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not user:
        user = User(email=email, name=name, google_sub=sub)
        session.add(user)
        await session.flush()
        await _provision_tenancy(
            session, user, (name or email.split("@")[0]) + "'s org",
        )
    else:
        if not user.google_sub:
            user.google_sub = sub
        if name and not user.name:
            user.name = name
    await session.commit()

    access = make_access_token(user.id, user.org_id or "")
    refresh_token = make_refresh_token(user.id, user.org_id or "")
    desktop_redirect = request.session.pop("desktop_redirect", None)
    desktop_state = request.session.pop("desktop_state", "")
    if desktop_redirect:
        # Loopback — these query params never leave the user's machine.
        url = (
            f"{desktop_redirect}"
            f"?access_token={access}"
            f"&refresh_token={refresh_token}"
            f"&state={desktop_state}"
        )
        return RedirectResponse(url=url)
    redirect = (
        f"{settings.web_base_url}/oauth/callback"
        f"#access_token={access}&refresh_token={refresh_token}"
    )
    return RedirectResponse(url=redirect)
