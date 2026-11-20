"""Landing API endpoints: Persistent Signup, Mandatory Email Checkout, Stripe Portal & Live WAF Playground."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
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

# ==========================================
# Persistent Multi-Tenant SQLite + Supabase Store
# ==========================================
_DB_LOCK = threading.RLock()
_STORAGE_MODE = os.environ.get("SCUDO_STORAGE_MODE", "auto").strip().lower()
_DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "scudo_landing.db"
_DB_TARGET = (
    ":memory:"
    if _STORAGE_MODE == "memory"
    else os.environ.get("SCUDO_SQLITE_PATH", str(_DEFAULT_DB_PATH)).strip()
)
if _DB_TARGET != ":memory:":
    Path(_DB_TARGET).parent.mkdir(parents=True, exist_ok=True)

_db_conn = sqlite3.connect(_DB_TARGET, check_same_thread=False)
_db_conn.row_factory = sqlite3.Row


def _init_landing_db() -> None:
    with _DB_LOCK:
        _db_conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                email TEXT PRIMARY KEY,
                api_key TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                monthly_quota INTEGER NOT NULL DEFAULT 10000,
                is_active INTEGER NOT NULL DEFAULT 1,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS waitlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cliente_email TEXT NOT NULL,
                piano_scelto TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        _db_conn.commit()


_init_landing_db()


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
    email: EmailStr
    plan: PianoScelto = PianoScelto.PRO


class CustomerPortalRequest(BaseModel):
    email: EmailStr


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _quota_for_plan(plan: str) -> int:
    if plan == "enterprise":
        return 10_000_000
    if plan == "agency":
        return 2_500_000
    if plan == "pro":
        return 500_000
    return 10_000


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _mask_key(api_key: str) -> str:
    if len(api_key) <= 10:
        return f"{api_key[:4]}***"
    return f"{api_key[:10]}...{api_key[-3:]}"


def _generate_key(plan: str) -> str:
    prefix = "sk_live_" if plan in {"pro", "agency", "enterprise"} else "sk_free_"
    return f"{prefix}{secrets.token_hex(12)}"


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "email": row["email"],
        "api_key": row["api_key"],
        "key_hash": row["key_hash"],
        "key_prefix": row["key_prefix"],
        "plan": row["plan"],
        "monthly_quota": int(row["monthly_quota"]),
        "is_active": bool(row["is_active"]),
        "stripe_customer_id": row["stripe_customer_id"],
        "stripe_subscription_id": row["stripe_subscription_id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _db_record_waitlist(email: str, plan: str) -> None:
    clean_email = email.strip().lower()
    now = _now_iso()
    with _DB_LOCK:
        _db_conn.execute(
            "INSERT INTO waitlist (cliente_email, piano_scelto, created_at) VALUES (?, ?, ?)",
            (clean_email, plan, now),
        )
        _db_conn.commit()


def _db_upsert_tenant(
    email: str,
    plan: str,
    *,
    api_key: str | None = None,
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
    preserve_existing_higher_plan: bool = False,
) -> dict[str, Any]:
    clean_email = email.strip().lower()
    now = _now_iso()
    with _DB_LOCK:
        existing = _db_conn.execute(
            "SELECT * FROM api_keys WHERE email = ?",
            (clean_email,),
        ).fetchone()

        if existing is not None:
            effective_plan = plan
            if preserve_existing_higher_plan and existing["plan"] in {"pro", "agency", "enterprise"} and plan == "free":
                effective_plan = str(existing["plan"])
            effective_key = api_key or str(existing["api_key"])
            _db_conn.execute(
                """
                UPDATE api_keys
                SET api_key = ?,
                    key_hash = ?,
                    key_prefix = ?,
                    plan = ?,
                    monthly_quota = ?,
                    is_active = 1,
                    stripe_customer_id = COALESCE(?, stripe_customer_id),
                    stripe_subscription_id = COALESCE(?, stripe_subscription_id),
                    updated_at = ?
                WHERE email = ?
                """,
                (
                    effective_key,
                    _hash_key(effective_key),
                    _mask_key(effective_key),
                    effective_plan,
                    _quota_for_plan(effective_plan),
                    stripe_customer_id,
                    stripe_subscription_id,
                    now,
                    clean_email,
                ),
            )
            _db_conn.commit()
            row = _db_conn.execute("SELECT * FROM api_keys WHERE email = ?", (clean_email,)).fetchone()
            assert row is not None
            return _row_to_dict(row)

        new_key = api_key or _generate_key(plan)
        _db_conn.execute(
            """
            INSERT INTO api_keys (
                email, api_key, key_hash, key_prefix, plan, monthly_quota,
                is_active, stripe_customer_id, stripe_subscription_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
            """,
            (
                clean_email,
                new_key,
                _hash_key(new_key),
                _mask_key(new_key),
                plan,
                _quota_for_plan(plan),
                stripe_customer_id,
                stripe_subscription_id,
                now,
                now,
            ),
        )
        _db_conn.commit()
        row = _db_conn.execute("SELECT * FROM api_keys WHERE email = ?", (clean_email,)).fetchone()
        assert row is not None
        return _row_to_dict(row)


def _db_get_by_email(email: str) -> dict[str, Any] | None:
    clean_email = email.strip().lower()
    with _DB_LOCK:
        row = _db_conn.execute("SELECT * FROM api_keys WHERE email = ?", (clean_email,)).fetchone()
        return _row_to_dict(row) if row is not None else None


async def _mirror_to_supabase(record: dict[str, Any], *, waitlist_plan: str | None = None) -> None:
    """Persist waitlist & API key record into Supabase REST API if configured."""
    supabase_url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    supabase_key = os.environ.get("SUPABASE_KEY", "").strip()
    if not supabase_url or not supabase_key or "your-project" in supabase_url:
        return

    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            if waitlist_plan:
                await client.post(
                    f"{supabase_url}/rest/v1/waitlist",
                    json={"cliente_email": record["email"], "piano_scelto": waitlist_plan},
                    headers=headers,
                )

            existing = await client.get(
                f"{supabase_url}/rest/v1/api_keys",
                params={"email": f"eq.{record['email']}", "select": "email"},
                headers=headers,
            )
            payload = {
                "key_string": record["api_key"],
                "key_hash": record["key_hash"],
                "email": record["email"],
                "plan": record["plan"],
                "is_active": bool(record.get("is_active", True)),
            }
            if existing.status_code == 200 and existing.json():
                await client.patch(
                    f"{supabase_url}/rest/v1/api_keys",
                    params={"email": f"eq.{record['email']}"},
                    json={"plan": record["plan"], "is_active": bool(record.get("is_active", True))},
                    headers=headers,
                )
            else:
                await client.post(
                    f"{supabase_url}/rest/v1/api_keys",
                    json=payload,
                    headers=headers,
                )
    except Exception as exc:
        logger.warning("Supabase sync skipped/failed (local DB preserved): %s", exc)


async def _send_transactional_email(to_email: str, plan: str, api_key: str) -> bool:
    """Send transactional onboarding email with API key via Resend if configured."""
    resend_key = os.environ.get("RESEND_API_KEY", "").strip()
    from_email = os.environ.get("RESEND_FROM_EMAIL", "Scudo WAF <onboarding@resend.dev>").strip()
    if not resend_key:
        return False

    safe_key = html.escape(api_key)
    safe_plan = html.escape(plan.upper())
    html_body = (
        f"<h2>Benvenuto su Scudo WAF</h2>"
        f"<p>La tua API Key per il piano <strong>{safe_plan}</strong> è stata attivata:</p>"
        f"<pre style='background:#0b172a;color:#34d399;padding:12px;border-radius:8px;'>{safe_key}</pre>"
        f"<p>Installazione rapida:</p>"
        f"<pre>pip install scudo-waf\napp.add_middleware(WafMiddleware, mode=\"block\", api_key=\"{safe_key}\")</pre>"
    )
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                json={
                    "from": from_email,
                    "to": [to_email],
                    "subject": f"La tua API Key Scudo WAF ({plan.upper()})",
                    "html": html_body,
                },
                headers={"Authorization": f"Bearer {resend_key}"},
            )
            return resp.status_code < 400
    except Exception as exc:
        logger.debug("Transactional email delivery skipped (%s): %s", to_email, exc)
        return False


async def _provision_with_control_plane(email: str, plan: str) -> dict[str, Any]:
    _db_record_waitlist(email, plan)
    api_url = os.environ.get("SCUDO_API_URL", "").strip().rstrip("/")
    admin_secret = os.environ.get("SCUDO_ADMIN_SECRET", "").strip()
    cp_key: str | None = None

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
                    cp_key = data.get("api_key")
        except Exception as exc:
            logger.debug("Control Plane HTTP provision unreachable (%s); using local DB.", exc)

    record = _db_upsert_tenant(email, plan, api_key=cp_key)
    await _mirror_to_supabase(record, waitlist_plan=plan)
    return record


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
    cp_result: dict[str, Any] | None = None

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
                    cp_result = resp.json()
        except Exception as exc:
            logger.debug("Control Plane subscription sync failed: %s", exc)

    clean_email = (email or "").strip().lower()
    if action == "activate":
        target_email = clean_email or f"stripe_{stripe_customer_id}@scudo-waf.dev"
        record = _db_upsert_tenant(
            target_email,
            plan,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
        )
        await _mirror_to_supabase(record)
        await _send_transactional_email(target_email, plan, record["api_key"])
        return cp_result or record

    # Deactivate / downgrade in SQLite + Supabase
    now = _now_iso()
    clauses: list[str] = []
    params: list[Any] = []
    if clean_email:
        clauses.append("email = ?")
        params.append(clean_email)
    if stripe_customer_id:
        clauses.append("stripe_customer_id = ?")
        params.append(stripe_customer_id)
    if stripe_subscription_id:
        clauses.append("stripe_subscription_id = ?")
        params.append(stripe_subscription_id)

    downgraded = 0
    if clauses:
        where_sql = " OR ".join(clauses)
        with _DB_LOCK:
            rows = _db_conn.execute(f"SELECT * FROM api_keys WHERE ({where_sql})", params).fetchall()
            cur = _db_conn.execute(
                f"UPDATE api_keys SET plan = 'free', monthly_quota = ?, updated_at = ? WHERE ({where_sql})",
                [_quota_for_plan("free"), now, *params],
            )
            _db_conn.commit()
            downgraded = int(cur.rowcount) if cur.rowcount and cur.rowcount > 0 else 0
        for row in rows:
            rec = _row_to_dict(row)
            rec["plan"] = "free"
            rec["monthly_quota"] = _quota_for_plan("free")
            await _mirror_to_supabase(rec)

    if cp_result is not None:
        return cp_result
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
    return {
        "status": "ok",
        "version": "1.0.0",
        "ml_loaded": _demo_engine.ml_loaded,
        "storage": "memory" if _DB_TARGET == ":memory:" else "sqlite",
    }


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


async def _create_stripe_checkout(plan: str, email: str) -> dict[str, Any]:
    """Resolve direct Stripe Payment Link or create a Stripe Checkout Session via HTTPS API."""
    clean_plan = plan if plan in {"pro", "agency"} else "pro"
    clean_email = email.strip().lower()
    payment_link_var = "STRIPE_AGENCY_PAYMENT_LINK" if clean_plan == "agency" else "STRIPE_PRO_PAYMENT_LINK"
    payment_link = os.environ.get(payment_link_var, "").strip()
    if payment_link:
        sep = "&" if "?" in payment_link else "?"
        url = f"{payment_link}{sep}prefilled_email={quote(clean_email, safe='')}"
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
            "customer_email": clean_email,
            "success_url": success_url,
            "cancel_url": cancel_url,
            "metadata[plan]": clean_plan,
        }
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
        "message": "Stripe non configurato in questo ambiente: la tua email e la tua API Key sono state comunque salvate nel database.",
        "redirect": "#form-iscrizione",
    }


@router.post("/checkout")
async def create_checkout_session(req: CheckoutRequest) -> dict[str, Any]:
    """Create a Stripe Checkout session after saving mandatory transactional customer email."""
    clean_email = str(req.email).strip().lower()
    _db_record_waitlist(clean_email, req.plan.value)
    record = _db_upsert_tenant(clean_email, "free", preserve_existing_higher_plan=True)
    await _mirror_to_supabase(record, waitlist_plan=req.plan.value)

    if req.plan == PianoScelto.FREE:
        return {
            "status": "free_tier",
            "mode": "free",
            "email": clean_email,
            "key_prefix": record["key_prefix"],
            "message": "Account Free salvato nel database. Usa #form-iscrizione per visualizzare la tua chiave.",
            "redirect": "#form-iscrizione",
        }

    checkout = await _create_stripe_checkout(req.plan.value, clean_email)
    checkout["email"] = clean_email
    checkout["key_prefix"] = record["key_prefix"]
    return checkout


@router.post("/stripe/portal")
async def create_customer_portal_session(req: CustomerPortalRequest) -> dict[str, Any]:
    """Open Stripe Billing Customer Portal (self-service invoices, payment methods & cancellation)."""
    clean_email = str(req.email).strip().lower()
    portal_link = os.environ.get("STRIPE_CUSTOMER_PORTAL_URL", "").strip()
    if portal_link:
        sep = "&" if "?" in portal_link else "?"
        return {
            "status": "ready",
            "mode": "portal_link",
            "portal_url": f"{portal_link}{sep}prefilled_email={quote(clean_email, safe='')}",
        }

    stripe_key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not stripe_key:
        return {
            "status": "not_configured",
            "message": "Portale Clienti non ancora configurato: imposta STRIPE_CUSTOMER_PORTAL_URL o STRIPE_SECRET_KEY su Render.",
        }

    return_url = os.environ.get("STRIPE_SUCCESS_URL", "http://localhost:8080/").split("?")[0]
    customer_id: str | None = None
    existing = _db_get_by_email(clean_email)
    if existing and existing.get("stripe_customer_id"):
        customer_id = str(existing["stripe_customer_id"])

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            if not customer_id:
                search_resp = await client.get(
                    "https://api.stripe.com/v1/customers",
                    params={"email": clean_email, "limit": 1},
                    headers={"Authorization": f"Bearer {stripe_key}"},
                )
                if search_resp.status_code < 400:
                    customers = search_resp.json().get("data", [])
                    if customers:
                        customer_id = str(customers[0]["id"])

            if not customer_id:
                return {
                    "status": "customer_not_found",
                    "message": "Nessun cliente o abbonamento Stripe trovato per questa email.",
                }

            portal_resp = await client.post(
                "https://api.stripe.com/v1/billing_portal/sessions",
                data={"customer": customer_id, "return_url": return_url},
                headers={"Authorization": f"Bearer {stripe_key}"},
            )
            portal_payload = portal_resp.json()
            if portal_resp.status_code < 400 and portal_payload.get("url"):
                return {
                    "status": "ready",
                    "mode": "stripe_billing_portal",
                    "portal_url": portal_payload["url"],
                }
            msg = portal_payload.get("error", {}).get("message", f"HTTP {portal_resp.status_code}")
            return {"status": "error", "message": f"Errore Stripe Customer Portal: {msg}"}
    except Exception as exc:
        return {"status": "error", "message": f"Errore comunicazione Stripe: {exc}"}


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
    await _send_transactional_email(provisioned["email"], provisioned["plan"], provisioned["api_key"])
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
            "<h3>Errore: Indirizzo email transazionale non valido o piano scorretto.</h3>",
            status_code=400,
        )

    provisioned = await _provision_with_control_plane(
        str(dati_validati.email),
        dati_validati.piano_scelto.value,
    )
    email_sent = await _send_transactional_email(
        provisioned["email"],
        provisioned["plan"],
        provisioned["api_key"],
    )

    safe_plan = html.escape(provisioned["plan"].upper())
    safe_email = html.escape(provisioned["email"])
    safe_key = html.escape(provisioned["api_key"])
    quota_fmt = f"{int(provisioned['monthly_quota']):,}".replace(",", ".")
    dashboard_url = html.escape(os.environ.get("DASHBOARD_URL", "http://localhost:8501"))

    email_notice = (
        f"Copia inviata automaticamente anche via email a <strong>{safe_email}</strong>."
        if email_sent
        else f"Account salvato nel database per <strong>{safe_email}</strong>. Salva questa chiave qui sotto."
    )

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
                "border-radius:9px; font-weight:700; display:inline-block;'>Completa Pagamento su Stripe</a>"
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
                <div style='display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px; border-bottom:1px solid #e2e8f0; padding-bottom:20px; margin-bottom:20px;'>
                    <div>
                        <div style='display:inline-block; background:#ecfdf5; color:#065f46; border:1px solid #a7f3d0; padding:4px 12px; border-radius:999px; font-size:12px; font-weight:700; margin-bottom:8px;'>CERTIFICATO DI ATTIVAZIONE LICENZA</div>
                        <h2 style='color:#0b172a; font-weight:800; margin:0; font-size:24px;'>API Key Scudo WAF Registrata</h2>
                    </div>
                    <div style='width:48px; height:48px; border-radius:12px; background:linear-gradient(135deg,#1d4ed8 0%,#059669 100%); color:#ffffff; display:flex; align-items:center; justify-content:center; font-size:22px; font-weight:800;'>&#10003;</div>
                </div>

                <p style='color:#334155; font-size:14px; margin-top:0; margin-bottom:18px;'>{email_notice}</p>

                <div style='display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-bottom:22px; background:#f8fafc; padding:14px 18px; border-radius:12px; border:1px solid #e2e8f0; font-size:14px;'>
                    <div><div style='color:#64748b; font-size:12px; font-weight:600;'>EMAIL TRANSAZIONALE</div><strong style='color:#0f172a;'>{safe_email}</strong></div>
                    <div><div style='color:#64748b; font-size:12px; font-weight:600;'>PIANO SCELTO</div><strong style='color:#1d4ed8;'>{safe_plan}</strong></div>
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
