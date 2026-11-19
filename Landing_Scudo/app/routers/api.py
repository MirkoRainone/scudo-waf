"""Landing API endpoints: Self-Service Signup, Live WAF/PII Playground & Stripe Webhooks."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import threading
from enum import Enum
from typing import Any

import httpx
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field

from scudo_waf import ScudoEngine, WafConfig, redact_sensitive_data

logger = logging.getLogger("scudo_waf.landing_api")

router = APIRouter(prefix="/api/v1", tags=["Scudo Landing API"])

_demo_engine = ScudoEngine(WafConfig(rate_limit_per_minute=None))

# Lightweight thread-safe fallback registry when running Landing standalone without Control Plane
_REGISTRY_LOCK = threading.Lock()
_TENANT_REGISTRY: dict[str, dict[str, Any]] = {}


class PianoScelto(str, Enum):
    FREE = "free"
    PRO = "pro"


class IscrizioneForm(BaseModel):
    email: EmailStr
    piano_scelto: PianoScelto


class DemoAnalyzeRequest(BaseModel):
    payload: str = Field(..., min_length=1, max_length=2000)


class CheckoutRequest(BaseModel):
    email: EmailStr | None = None
    plan: PianoScelto = PianoScelto.PRO


def _quota_for_plan(plan: str) -> int:
    if plan == "enterprise":
        return 10_000_000
    if plan == "pro":
        return 500_000
    return 10_000


def _provision_local_fallback(email: str, plan: str) -> dict[str, Any]:
    prefix = "sk_live_" if plan == "pro" else "sk_free_"
    api_key = f"{prefix}{secrets.token_hex(12)}"
    record = {
        "email": email.strip().lower(),
        "plan": plan,
        "monthly_quota": _quota_for_plan(plan),
        "api_key": api_key,
        "key_prefix": f"{api_key[:10]}...{api_key[-3:]}",
        "is_active": True,
    }
    with _REGISTRY_LOCK:
        _TENANT_REGISTRY[record["email"]] = record
    return record


async def _provision_with_control_plane(email: str, plan: str) -> dict[str, Any]:
    api_url = os.environ.get("SCUDO_API_URL", "").strip().rstrip("/")
    admin_secret = os.environ.get("SCUDO_ADMIN_SECRET", "").strip()
    if api_url:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if admin_secret:
            headers["X-Scudo-Admin-Secret"] = admin_secret
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.post(
                    f"{api_url}/v1/keys/provision",
                    json={"email": email, "plan": plan},
                    headers=headers,
                )
                if resp.status_code < 400:
                    data = resp.json()
                    with _REGISTRY_LOCK:
                        _TENANT_REGISTRY[email.strip().lower()] = data
                    return data
        except Exception as exc:
            logger.debug("Control Plane HTTP provision unreachable (%s); using local provisioning.", exc)

    # Optional Supabase waitlist mirror
    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    supabase_key = os.environ.get("SUPABASE_KEY", "").strip()
    if supabase_url and supabase_key and "your-project" not in supabase_url:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{supabase_url}/rest/v1/waitlist",
                    json={"cliente_email": email, "piano_scelto": plan},
                    headers={
                        "apikey": supabase_key,
                        "Authorization": f"Bearer {supabase_key}",
                        "Content-Type": "application/json",
                    },
                )
        except Exception as exc:
            logger.debug("Supabase waitlist mirror skipped: %s", exc)

    return _provision_local_fallback(email, plan)


async def _sync_subscription_change(
    *,
    action: str,
    email: str | None,
    plan: str = "pro",
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
) -> dict[str, Any]:
    api_url = os.environ.get("SCUDO_API_URL", "").strip().rstrip("/")
    admin_secret = os.environ.get("SCUDO_ADMIN_SECRET", "").strip()
    if api_url:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if admin_secret:
            headers["X-Scudo-Admin-Secret"] = admin_secret
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.post(
                    f"{api_url}/v1/keys/subscription",
                    json={
                        "action": action,
                        "email": email,
                        "plan": plan,
                        "stripe_customer_id": stripe_customer_id,
                        "stripe_subscription_id": stripe_subscription_id,
                    },
                    headers=headers,
                )
                if resp.status_code < 400:
                    return resp.json()
        except Exception as exc:
            logger.debug("Control Plane subscription sync failed: %s", exc)

    clean_email = (email or "").strip().lower()
    with _REGISTRY_LOCK:
        if action == "activate":
            existing = _TENANT_REGISTRY.get(clean_email) if clean_email else None
            if existing is not None:
                existing["plan"] = plan
                existing["monthly_quota"] = _quota_for_plan(plan)
                existing["is_active"] = True
                return existing
            return _provision_local_fallback(clean_email or f"stripe_{stripe_customer_id}@scudo-waf.dev", plan)

        # Deactivate / downgrade
        downgraded = 0
        for rec in _TENANT_REGISTRY.values():
            if (clean_email and rec.get("email") == clean_email) or (
                stripe_customer_id and rec.get("stripe_customer_id") == stripe_customer_id
            ):
                rec["plan"] = "free"
                rec["monthly_quota"] = _quota_for_plan("free")
                downgraded += 1
        return {"status": "deactivated", "downgraded_keys": downgraded, "plan": "free"}


def _verify_stripe_signature(payload_bytes: bytes, sig_header: str, secret: str) -> bool:
    """Verify Stripe ``Stripe-Signature`` header using HMAC-SHA256."""
    if not sig_header or not secret:
        return False

    timestamp = ""
    signatures: list[str] = []
    for part in sig_header.split(","):
        if "=" not in part:
            continue
        k, v = part.strip().split("=", 1)
        if k == "t":
            timestamp = v
        elif k == "v1":
            signatures.append(v)

    if not timestamp or not signatures:
        return False

    signed_payload = f"{timestamp}.".encode() + payload_bytes
    expected_sig = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected_sig, s) for s in signatures)


@router.get("/health")
async def api_health() -> dict[str, Any]:
    """API router health status."""
    return {"status": "ok", "version": "1.0.0", "ml_loaded": _demo_engine.ml_loaded}


@router.post("/demo/analyze")
async def demo_analyze(req: DemoAnalyzeRequest) -> dict[str, Any]:
    """Run live 3-level Scudo WAF inspection AND PII/Secret Redactor preview."""
    result = _demo_engine.inspect(req.payload)
    redaction = redact_sensitive_data(req.payload, redact_pii=True, redact_secrets=True)
    out = result.to_dict()
    out["redacted_payload"] = redaction.redacted_text
    out["pii_detected"] = bool(redaction.contains_pii or redaction.contains_secrets)
    out["pii_findings"] = redaction.findings
    return out


@router.post("/checkout")
async def create_checkout_session(req: CheckoutRequest) -> dict[str, Any]:
    """Create a Stripe Checkout session when Stripe credentials are configured."""
    stripe_key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    price_id = os.environ.get("STRIPE_PRO_PRICE_ID", "").strip()
    success_url = os.environ.get("STRIPE_SUCCESS_URL", "http://localhost:8080/?checkout=success")
    cancel_url = os.environ.get("STRIPE_CANCEL_URL", "http://localhost:8080/?checkout=cancelled")

    if stripe_key and price_id:
        try:
            import stripe  # type: ignore

            stripe.api_key = stripe_key
            session_kwargs: dict[str, Any] = {
                "mode": "subscription",
                "line_items": [{"price": price_id, "quantity": 1}],
                "success_url": success_url,
                "cancel_url": cancel_url,
            }
            if req.email:
                session_kwargs["customer_email"] = str(req.email)
            session = stripe.checkout.Session.create(**session_kwargs)
            return {"status": "ready", "mode": "stripe", "checkout_url": session.url}
        except ImportError:
            pass
        except Exception as exc:
            return {"status": "error", "message": f"Stripe checkout error: {exc}"}

    return {
        "status": "waitlist_fallback",
        "mode": "waitlist",
        "message": "Stripe non configurato in questo ambiente: usa il form di iscrizione per ottenere subito la tua API Key.",
        "redirect": "#form-iscrizione",
    }


@router.post("/stripe/webhook")
async def stripe_webhook(request: Request) -> dict[str, Any]:
    """Signed Stripe webhook handler managing Pro subscription lifecycle."""
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()
    if not webhook_secret:
        raise HTTPException(status_code=400, detail="STRIPE_WEBHOOK_SECRET non configurato")

    raw_body = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    if not _verify_stripe_signature(raw_body, sig_header, webhook_secret):
        raise HTTPException(status_code=400, detail="Firma Stripe Webhook non valida")

    try:
        event = json.loads(raw_body.decode("utf-8"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Payload JSON webhook non valido") from exc

    event_type = str(event.get("type", ""))
    obj = event.get("data", {}).get("object", {})
    customer_email = obj.get("customer_email") or obj.get("customer_details", {}).get("email")
    customer_id = obj.get("customer")
    subscription_id = obj.get("subscription") or (obj.get("id") if "subscription" in event_type else None)

    if event_type in {"checkout.session.completed", "invoice.paid"}:
        res = await _sync_subscription_change(
            action="activate",
            email=customer_email,
            plan="pro",
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription_id,
        )
        return {
            "status": "processed",
            "event_type": event_type,
            "plan": "pro",
            "key_prefix": res.get("key_prefix"),
        }

    if event_type in {"customer.subscription.deleted", "invoice.payment_failed"}:
        res = await _sync_subscription_change(
            action="deactivate",
            email=customer_email,
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription_id,
        )
        return {
            "status": "processed",
            "event_type": event_type,
            "plan": "free",
            "downgraded_keys": res.get("downgraded_keys", 0),
        }

    return {"status": "ignored", "event_type": event_type}


@router.post("/signup")
async def signup_json(req: IscrizioneForm) -> dict[str, Any]:
    """Programmatic self-service API Key signup endpoint (returns provisioned key JSON)."""
    provisioned = await _provision_with_control_plane(str(req.email), req.piano_scelto.value)
    return {
        "status": "provisioned",
        "email": provisioned["email"],
        "plan": provisioned["plan"],
        "monthly_quota": provisioned["monthly_quota"],
        "api_key": provisioned["api_key"],
    }


@router.post("/iscriviti", response_class=HTMLResponse)
async def gestisci_iscrizione(
    email: str = Form(...),
    piano_scelto: str = Form("free"),
):
    try:
        dati_validati = IscrizioneForm(email=email, piano_scelto=piano_scelto)
    except Exception:
        return HTMLResponse(
            "<h3>Errore: Indirizzo email non valido o piano scorretto. 🛡️</h3>",
            status_code=400,
        )

    provisioned = await _provision_with_control_plane(
        str(dati_validati.email),
        dati_validati.piano_scelto.value,
    )
    safe_plan = html.escape(provisioned["plan"].upper())
    safe_email = html.escape(provisioned["email"])
    safe_key = html.escape(provisioned["api_key"])
    quota_fmt = f"{int(provisioned['monthly_quota']):,}".replace(",", ".")
    dashboard_url = html.escape(os.environ.get("DASHBOARD_URL", "http://localhost:8501"))

    return HTMLResponse(
        f"""
        <html><body style='background:#f8fafc; color:#0f172a; text-align:center; padding:60px 20px; font-family:Inter,system-ui,sans-serif;'>
            <div style='max-width:600px; margin:0 auto; background:white; padding:40px; border-radius:16px; border:1px solid #e2e8f0; box-shadow:0 20px 40px -15px rgba(0,0,0,0.06); text-align:left;'>
                <div style='text-align:center;'>
                    <h2 style='color:#10b981; font-weight:800; margin-bottom:8px;'>🎉 API Key Scudo WAF Attivata!</h2>
                    <p style='color:#64748b;'>Account: <strong>{safe_email}</strong> · Piano <strong>{safe_plan}</strong> ({quota_fmt} req/mese)</p>
                </div>
                <div style='background:#0f172a; color:#f8fafc; padding:16px 20px; border-radius:10px; margin:20px 0; font-family:monospace; font-size:0.95rem; word-break:break-all;'>
                    <div style='color:#94a3b8; font-size:0.75rem; margin-bottom:6px;'>LA TUA API KEY PERSONALE (salvala subito):</div>
                    <strong style='color:#10b981;'>{safe_key}</strong>
                </div>
                <div style='background:#f1f5f9; padding:14px 16px; border-radius:10px; font-family:monospace; font-size:0.82rem; color:#0f172a; margin-bottom:24px;'>
                    pip install scudo-waf<br>
                    app.add_middleware(WafMiddleware, api_key="{safe_key}")
                </div>
                <div style='text-align:center; display:flex; gap:12px; justify-content:center; flex-wrap:wrap;'>
                    <a href='{dashboard_url}' target='_blank' style='background:#0f172a; color:white; padding:12px 24px; text-decoration:none; border-radius:8px; font-weight:700;'>Apri Console Analytics</a>
                    <a href='/' style='background:#10b981; color:white; padding:12px 24px; text-decoration:none; border-radius:8px; font-weight:700;'>Torna alla Home</a>
                </div>
            </div>
        </body></html>
        """
    )
