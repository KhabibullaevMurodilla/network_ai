"""Stripe subscription billing. This is wired up but NOT activated -- it
needs real Stripe product/price IDs and webhook secret before it will do
anything. Marked clearly rather than left silently broken."""
import stripe
from fastapi import APIRouter, Depends, Request, HTTPException
from ..core.config import settings
from ..core.auth import require_owner
from ..core.db import get_db
from ..core.limiter import limiter, user_key_func

router = APIRouter(prefix="/billing", tags=["billing"])
stripe.api_key = settings.STRIPE_SECRET_KEY


@router.post("/create-checkout-session")
@limiter.limit("10/minute", key_func=user_key_func)
async def create_checkout_session(request: Request, plan: str, user=Depends(require_owner)):
    """Billing changes are owner-only -- an admin can run day-to-day security
    operations (keys, webhooks, data export/erasure) without being able to
    change what the tenant is paying for."""
    if plan not in settings.STRIPE_PRICE_IDS or not settings.STRIPE_PRICE_IDS[plan]:
        raise HTTPException(
            status_code=400,
            detail=f"Plan '{plan}' not configured -- set STRIPE_PRICE_{plan.upper()} env var "
                   f"after creating the product/price in the Stripe dashboard.",
        )
    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": settings.STRIPE_PRICE_IDS[plan], "quantity": 1}],
        success_url="https://YOUR_DOMAIN/billing/success",
        cancel_url="https://YOUR_DOMAIN/billing/cancelled",
        client_reference_id=user["tenant_id"],
    )
    return {"checkout_url": session.url}


@router.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature")

    db = get_db()
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        tenant_id = session["client_reference_id"]
        db.table("tenants").update({
            "stripe_customer_id": session["customer"],
            "stripe_subscription_id": session["subscription"],
            "subscription_status": "active",
        }).eq("id", tenant_id).execute()
    elif event["type"] in ("customer.subscription.deleted", "customer.subscription.updated"):
        sub = event["data"]["object"]
        db.table("tenants").update({
            "subscription_status": sub["status"],
        }).eq("stripe_subscription_id", sub["id"]).execute()

    return {"received": True}
