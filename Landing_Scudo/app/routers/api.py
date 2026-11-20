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
from urllib.parse import quote

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
    AGENCY = "agency"


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
    if plan == "agency":
        return 2_500_000
    if plan == "pro":
        return 500_000
    return 10_000


def _provision_local_fallback(email: str, plan: str) -> dict[str, Any]:
    prefix = "sk_live_" if plan in {"pro", "agency", "enterprise"} else "sk_free_"
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


async def _create_stripe_checkout(plan: str, email: str | None = None) -> dict[str, Any]:
    """Resolve direct Stripe Payment Link or create a Stripe Checkout Session via HTTPS API."""
    clean_plan = plan if plan in {"pro", "agency"} else "pro"
    payment_link_var = "STRIPE_AGENCY_PAYMENT_LINK" if clean_plan == "agency" else "STRIPE_PRO_PAYMENT_LINK"
    payment_link = os.environ.get(payment_link_var, "").strip()
    if payment_link:
        url = payment_link
        if email:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}prefilled_email={quote(email.strip(), safe='')}"
        return {"status": "ready", "mode": "payment_link", "plan": clean_plan, "checkout_url": url}

    stripe_key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    price_var = "STRIPE_AGENCY_PRICE_ID" if clean_plan == "agency" else "STRIPE_PRO_PRICE_ID"
    price_id = os.environ.get(price_var, "").strip()
    success_url = os.environ.get("STRIPE_SUCCESS_URL", "http://localhost:8080/?checkout=success")
    cancel_url = os.environ.get("STRIPE_CANCEL_URL", "http://localhost:8080/?checkout=cancelled")

    if stripe_key and price_id:
        form_data: dict[str, str] = {
            "mode": "subscription",
            "line_items[0][price]": price_id,
            "line_items[0][quantity]": "1",
            "success_url": success_url,
            "cancel_url": cancel_url,
            "metadata[plan]": clean_plan,
        }
        if email:
            form_data["customer_email"] = email.strip()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(
                    "https://api.stripe.com/v1/checkout/sessions",
                    data=form_data,
                    headers={"Authorization": f"Bearer {stripe_key}"},
                )
            payload = resp.json()
            if resp.status_code < 400 and payload.get("url"):
                return {
                    "status": "ready",
                    "mode": "stripe",
                    "plan": clean_plan,
                    "checkout_url": payload["url"],
                }
            msg = payload.get("error", {}).get("message", f"HTTP {resp.status_code}")
            return {"status": "error", "message": f"Stripe checkout error: {msg}"}
        except Exception as exc:
            return {"status": "error", "message": f"Stripe checkout error: {exc}"}

    return {
        "status": "waitlist_fallback",
        "mode": "waitlist",
        "plan": clean_plan,
        "message": "Stripe non configurato in questo ambiente: usa il form di iscrizione per ottenere subito la tua API Key.",
        "redirect": "#form-iscrizione",
    }


@router.post("/checkout")
async def create_checkout_session(req: CheckoutRequest) -> dict[str, Any]:
    """Create a Stripe Checkout session (or Payment Link) for Pro or Agency tiers."""
    if req.plan == PianoScelto.FREE:
        return {
            "status": "free_tier",
            "mode": "free",
            "message": "Il piano Free non richiede Stripe Checkout: usa #form-iscrizione per generare subito la tua chiave.",
            "redirect": "#form-iscrizione",
        }
    return await _create_stripe_checkout(req.plan.value, str(req.email) if req.email else None)


@router.post("/stripe/webhook")
async def stripe_webhook(request: Request) -> dict[str, Any]:
    """Signed Stripe webhook handler managing Pro and Agency subscription lifecycle."""
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
    raw_meta_plan = str(obj.get("metadata", {}).get("plan", "pro")).lower().strip()
    target_plan = raw_meta_plan if raw_meta_plan in {"pro", "agency", "enterprise"} else "pro"

    if event_type in {"checkout.session.completed", "invoice.paid"}:
        res = await _sync_subscription_change(
            action="activate",
            email=customer_email,
            plan=target_plan,
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription_id,
        )
        return {
            "status": "processed",
            "event_type": event_type,
            "plan": target_plan,
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

    stripe_cta_html = ""
    if dati_validati.piano_scelto.value in {"pro", "agency"}:
        checkout_info = await _create_stripe_checkout(
            dati_validati.piano_scelto.value,
            str(dati_validati.email),
        )
        checkout_url = checkout_info.get("checkout_url")
        if checkout_url:
            safe_checkout = html.escape(str(checkout_url))
            stripe_cta_html = (
                f"<a href='{safe_checkout}' target='_blank' "
                "style='background:#1d4ed8; color:white; padding:12px 22px; text-decoration:none; "
                "border-radius:9px; font-weight:700; display:inline-block;'>Completa Attivazione Stripe</a>"
            )

    return HTMLResponse(
        f"""
        <!DOCTYPE html>
        <html lang='it'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>Certificato API Key Attivata — Scudo WAF</title>
        </head>
        <body style='background:linear-gradient(180deg,#eff6ff 0%,#f8fafc 100%); color:#0f172a; margin:0; padding:48px 20px; font-family:"Plus Jakarta Sans",Inter,system-ui,sans-serif;'>
            <div style='max-width:680px; margin:0 auto; background:#ffffff; padding:38px; border-radius:18px; border:1px solid #cbd5e1; box-shadow:0 24px 48px -16px rgba(11,23,42,0.10); text-align:left;'>
                <div style='display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px; border-bottom:1px solid #e2e8f0; padding-bottom:20px; margin-bottom:24px;'>
                    <div>
                        <div style='display:inline-block; background:#ecfdf5; color:#065f46; border:1px solid #a7f3d0; padding:4px 12px; border-radius:999px; font-size:12px; font-weight:700; margin-bottom:8px;'>CERTIFICATO DI ATTIVAZIONE LICENZA</div>
                        <h2 style='color:#0b172a; font-weight:800; margin:0; font-size:24px;'>API Key Scudo WAF Pronta all'Uso</h2>
                    </div>
                    <div style='width:48px; height:48px; border-radius:12px; background:linear-gradient(135deg,#1d4ed8 0%,#059669 100%); color:#ffffff; display:flex; align-items:center; justify-content:center; font-size:22px; font-weight:800;'>&#10003;</div>
                </div>

                <div style='display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-bottom:22px; background:#f8fafc; padding:14px 18px; border-radius:12px; border:1px solid #e2e8f0; font-size:14px;'>
                    <div><div style='color:#64748b; font-size:12px; font-weight:600;'>INTESTATARIO</div><strong style='color:#0f172a;'>{safe_email}</strong></div>
                    <div><div style='color:#64748b; font-size:12px; font-weight:600;'>PIANO ATTIVO</div><strong style='color:#1d4ed8;'>{safe_plan}</strong></div>
                    <div><div style='color:#64748b; font-size:12px; font-weight:600;'>QUOTA CLOUD MENSILE</div><strong style='color:#059669;'>{quota_fmt} req/mese</strong></div>
                </div>

                <div style='background:#0b172a; color:#f8fafc; padding:18px 20px; border-radius:12px; margin-bottom:20px; border:1px solid #1e293b;'>
                    <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; gap:10px; flex-wrap:wrap;'>
                        <span style='color:#94a3b8; font-size:11px; font-weight:700; letter-spacing:0.6px;'>LA TUA API KEY PERSONALE (CIFRATA SHA-256 SUL SERVER)</span>
                        <button type='button' id='copy-key-btn' onclick='copyApiKey()' style='background:#1e293b; color:#e2e8f0; border:1px solid #334155; padding:4px 10px; border-radius:6px; font-size:12px; font-weight:600; cursor:pointer;'>Copia Chiave</button>
                    </div>
                    <code id='api-key-val' style='color:#34d399; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:15px; font-weight:700; word-break:break-all;'>{safe_key}</code>
                </div>

                <div style='background:#f1f5f9; padding:16px 18px; border-radius:12px; border:1px solid #e2e8f0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; color:#0f172a; margin-bottom:22px; line-height:1.65;'>
                    <div style='color:#475569; font-family:Inter,system-ui,sans-serif; font-size:12px; font-weight:700; margin-bottom:6px;'>GUIDA RAPIDA IN 3 RIGHE (MODO FAIL-OPEN GARANTITO):</div>
                    pip install scudo-waf<br>
                    app.add_middleware(WafMiddleware, mode="block", api_key="{safe_key}")
                </div>

                <div style='background:#ecfdf5; border:1px solid #a7f3d0; border-radius:10px; padding:12px 16px; color:#065f46; font-size:13px; margin-bottom:24px;'>
                    <strong>Garanzia di Continuità Operativa:</strong> Anche se superi la quota di telemetria mensile o il Control Plane fosse irraggiungibile, l'ispezione locale nella RAM della tua app continua a funzionare senza interruzioni.
                </div>

                <div style='display:flex; gap:12px; justify-content:center; flex-wrap:wrap;'>
                    {stripe_cta_html}
                    <a href='{dashboard_url}' target='_blank' style='background:#0b172a; color:white; padding:12px 22px; text-decoration:none; border-radius:9px; font-weight:700; display:inline-block;'>Apri Console Analytics</a>
                    <a href='/' style='background:#059669; color:white; padding:12px 22px; text-decoration:none; border-radius:9px; font-weight:700; display:inline-block;'>Torna alla Home</a>
                </div>
            </div>
            <script>
                function copyApiKey() {{
                    var val = document.getElementById('api-key-val').textContent;
                    var btn = document.getElementById('copy-key-btn');
                    if (navigator.clipboard) {{
                        navigator.clipboard.writeText(val).then(function() {{
                            btn.textContent = 'Copiata!';
                            setTimeout(function() {{ btn.textContent = 'Copia Chiave'; }}, 1800);
                        }});
                    }}
                }}
            </script>
        </body>
        </html>
        """
    )
