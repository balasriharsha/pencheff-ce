import logging

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_current_user, session_only
from ..config import get_settings
from ..db.base import get_session
from ..db.models import Org, Subscription, User

log = logging.getLogger(__name__)
router = APIRouter(prefix="/billing", tags=["billing"])
settings = get_settings()

PLAN_BY_PRICE: dict[str, str] = {}
if settings.stripe_price_pro:
    PLAN_BY_PRICE[settings.stripe_price_pro] = "pro"
if settings.stripe_price_team:
    PLAN_BY_PRICE[settings.stripe_price_team] = "team"


def _stripe():
    if not settings.stripe_secret_key:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "stripe not configured")
    stripe.api_key = settings.stripe_secret_key
    return stripe


@router.post(
    "/checkout",
    # API keys must never trigger checkout — that touches Stripe customer
    # state and would let a leaked key change the org's plan.
    dependencies=[Depends(session_only)],
)
async def create_checkout(
    plan: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    s = _stripe()
    org = (await session.execute(select(Org).where(Org.id == user.org_id))).scalar_one()
    if not org.stripe_customer_id:
        cust = s.Customer.create(email=user.email, name=org.name, metadata={"org_id": org.id})
        org.stripe_customer_id = cust.id
        await session.commit()

    price = settings.stripe_price_pro if plan == "pro" else settings.stripe_price_team if plan == "team" else None
    if not price:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown plan")

    checkout = s.checkout.Session.create(
        mode="subscription",
        customer=org.stripe_customer_id,
        line_items=[{"price": price, "quantity": 1}],
        success_url=f"{settings.web_base_url}/billing?status=success",
        cancel_url=f"{settings.web_base_url}/billing?status=cancel",
        metadata={"org_id": org.id, "plan": plan},
    )
    return {"url": checkout.url}


@router.post("/webhook")
async def webhook(request: Request, session: AsyncSession = Depends(get_session)):
    s = _stripe()
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = s.Webhook.construct_event(payload, sig, settings.stripe_webhook_secret)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid signature")

    etype = event["type"]
    obj = event["data"]["object"]

    if etype == "checkout.session.completed":
        org_id = (obj.get("metadata") or {}).get("org_id")
        plan = (obj.get("metadata") or {}).get("plan", "pro")
        sub_id = obj.get("subscription")
        if org_id:
            org = (await session.execute(select(Org).where(Org.id == org_id))).scalar_one_or_none()
            if org:
                org.plan = plan
                if sub_id:
                    sub = Subscription(org_id=org.id, stripe_sub_id=sub_id, status="active", plan=plan)
                    session.add(sub)
                await session.commit()
    elif etype in ("customer.subscription.updated", "customer.subscription.deleted"):
        stripe_sub_id = obj["id"]
        sub = (await session.execute(
            select(Subscription).where(Subscription.stripe_sub_id == stripe_sub_id)
        )).scalar_one_or_none()
        if sub:
            sub.status = obj.get("status", "unknown")
            if etype.endswith("deleted") or sub.status in ("canceled", "unpaid", "incomplete_expired"):
                # Downgrade org
                org = (await session.execute(select(Org).where(Org.id == sub.org_id))).scalar_one_or_none()
                if org:
                    org.plan = "free"
            await session.commit()

    return {"received": True}
