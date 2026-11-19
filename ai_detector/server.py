"""Scudo WAF Control Plane API Server (Multi-Tenant Scan, Rules, Quotas, Telemetry & Webhooks)."""

import hmac
import logging
import os
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Literal

import httpx
import uvicorn
from cachetools import TTLCache
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, EmailStr, Field

from scudo_waf import ScudoEngine, ThreatCategory, WafConfig, redact_sensitive_data

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from storage import ScudoStorage  # noqa: E402

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("scudo_waf.server")

START_TIME = time.monotonic()

# ==========================================
# Storage & Configuration
# ==========================================
STORAGE_MODE_ENV = os.environ.get("SCUDO_STORAGE_MODE", "auto").strip().lower()
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "").strip()
SQLITE_PATH = os.environ.get("SCUDO_SQLITE_PATH", str(BASE_DIR / "scudo_control_plane.db")).strip()
DEMO_API_KEY = os.environ.get("SCUDO_DEMO_API_KEY", os.environ.get("WAF_API_KEY", "sk_test_default")).strip()
MAX_REQUESTS_PER_MINUTE = int(os.environ.get("SCUDO_RATE_LIMIT_PER_MINUTE", "120"))
ADMIN_SECRET = os.environ.get("SCUDO_ADMIN_SECRET", "").strip()

supabase_client: Any = None
ACTIVE_STORAGE = "memory"

if STORAGE_MODE_ENV not in {"memory", "sqlite"} and SUPABASE_URL and SUPABASE_KEY and "your-project" not in SUPABASE_URL:
    try:
        from supabase import create_client

        supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        ACTIVE_STORAGE = "supabase"
        logger.info("Connected to Supabase backend.")
    except Exception as exc:
        if STORAGE_MODE_ENV == "supabase":
            raise RuntimeError(f"Supabase storage explicitly requested but failed: {exc}") from exc
        logger.warning("Supabase unavailable (%s); falling back to SQLite/memory storage.", exc)
elif STORAGE_MODE_ENV == "supabase":
    raise ValueError("SCUDO_STORAGE_MODE=supabase requires SUPABASE_URL and SUPABASE_KEY.")
elif STORAGE_MODE_ENV == "sqlite":
    ACTIVE_STORAGE = "sqlite"
    logger.info("Running in persistent SQLite storage mode (%s).", SQLITE_PATH)
else:
    ACTIVE_STORAGE = "memory"
    logger.info("Running in in-memory SQLite storage mode (demo/local/CI).")

storage = ScudoStorage(
    mode=ACTIVE_STORAGE,
    sqlite_path=SQLITE_PATH if ACTIVE_STORAGE == "sqlite" else None,
    supabase_client=supabase_client,
)
storage.ensure_seed_key(DEMO_API_KEY, email="demo@scudo-waf.dev", plan="pro")

# ==========================================
# Hybrid 3-Level Engine Initialization
# ==========================================
engine = ScudoEngine(
    WafConfig(
        model_dir=BASE_DIR,
        rate_limit_per_minute=None,
    )
)

app = FastAPI(title="Scudo WAF Control Plane API", version="1.0.0")

# Thread-safe per-minute API rate limiter
_rate_buckets: TTLCache[str, deque[float]] = TTLCache(maxsize=10000, ttl=60)
_rate_lock = threading.Lock()


class ScanRequest(BaseModel):
    """Input payload for traffic inspection."""

    testo: str = Field(..., min_length=1, max_length=10_000)
    client_ip: str | None = Field(None, max_length=64)
    path: str | None = Field(None, max_length=300)


class TelemetryEvent(BaseModel):
    """Blocked/monitored threat telemetry submitted by Scudo SDK middleware."""

    tipo_attacco: str = Field(..., min_length=1, max_length=100)
    payload_malevolo: str = Field(..., min_length=1, max_length=2000)
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    category: str | None = Field(None, max_length=64)
    level: str | None = Field(None, max_length=32)
    path: str | None = Field(None, max_length=300)
    client_ip: str | None = Field(None, max_length=64)


class ProvisionKeyRequest(BaseModel):
    """Self-service tenant API key provisioning request."""

    email: EmailStr
    plan: Literal["free", "pro", "enterprise"] = "free"


class SubscriptionSyncRequest(BaseModel):
    """Internal Stripe subscription lifecycle sync payload."""

    action: Literal["activate", "deactivate"]
    email: EmailStr | None = None
    plan: Literal["free", "pro", "enterprise"] = "pro"
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None


class RulesUpdateRequest(BaseModel):
    """Custom WAF policy configuration per tenant."""

    mode: Literal["block", "monitor"] | None = None
    ml_threshold: float | None = Field(None, ge=0.0, le=1.0)
    allowlist_ips: list[str] | None = None
    blocklist_ips: list[str] | None = None
    exclude_paths: list[str] | None = None
    redact_pii: bool | None = None
    webhook_url: str | None = Field(None, max_length=500)


def _extract_bearer(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Accesso Negato: API Key mancante")
    token = authorization.replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Accesso Negato: API Key mancante")
    return token


def _check_api_rate_limit(api_key: str) -> None:
    now = time.monotonic()
    with _rate_lock:
        bucket = _rate_buckets.get(api_key)
        if bucket is None:
            bucket = deque()
            _rate_buckets[api_key] = bucket
        while bucket and (now - bucket[0]) >= 60.0:
            bucket.popleft()
        if len(bucket) >= MAX_REQUESTS_PER_MINUTE:
            raise HTTPException(status_code=429, detail="Too Many Requests: Limite al minuto superato.")
        bucket.append(now)


def _authorize_and_consume(api_key: str, *, consume: int = 1) -> dict[str, Any]:
    _check_api_rate_limit(api_key)
    status, tenant = storage.validate_and_consume_quota(api_key, consume=consume)
    if status == "invalid" or tenant is None:
        raise HTTPException(status_code=401, detail="Accesso Negato: API Key non valida")
    if status == "quota_exceeded":
        raise HTTPException(
            status_code=429,
            detail=f"Quota mensile superata ({tenant['used_this_month']}/{tenant['monthly_quota']}). Passa al Piano Pro.",
        )
    return tenant


def _authorize_read_only(api_key: str) -> dict[str, Any]:
    _check_api_rate_limit(api_key)
    tenant = storage.get_tenant(api_key)
    if tenant is None:
        raise HTTPException(status_code=401, detail="Accesso Negato: API Key non valida")
    return tenant


def _persist_attack_log(
    tipo_attacco: str,
    payload: str,
    api_key: str,
    *,
    risk_score: float = 1.0,
    latency_ms: float = 0.0,
    level: str = "L1-Regex",
    client_ip: str = "",
) -> None:
    storage.log_attack(
        api_key=api_key,
        tipo_attacco=tipo_attacco,
        payload=payload,
        risk_score=risk_score,
        latency_ms=latency_ms,
        level=level,
        client_ip=client_ip,
    )


async def _dispatch_webhook(
    webhook_url: str,
    *,
    category: str,
    level: str,
    risk_score: float,
    request_id: str,
    client_ip: str,
    payload_preview: str,
) -> None:
    if not webhook_url.startswith(("http://", "https://")):
        return
    body = {
        "text": (
            f"🚨 *Scudo WAF Alert* — `{category}` ({level}, risk={risk_score:.2f}) "
            f"blocked (ip={client_ip or 'unknown'}, req={request_id})"
        ),
        "event": "scudo.threat_blocked",
        "category": category,
        "level": level,
        "risk_score": round(risk_score, 4),
        "request_id": request_id,
        "client_ip": client_ip,
        "payload_preview": payload_preview[:200],
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(webhook_url, json=body)
    except Exception as exc:
        logger.debug("Webhook delivery failed (%s): %s", webhook_url, exc)


@app.get("/health")
async def health() -> dict[str, Any]:
    """Liveness & readiness check."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "model_loaded": engine.ml_loaded,
        "storage": ACTIVE_STORAGE,
        "uptime_seconds": round(time.monotonic() - START_TIME, 2),
    }


@app.post("/v1/scan")
@app.post("/scansiona")
async def scan_traffic(
    richiesta: ScanRequest,
    background_tasks: BackgroundTasks,
    response: Response,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Inspect text payload through Scudo 3-level hybrid WAF engine with tenant policies."""
    api_key = _extract_bearer(authorization)
    tenant = _authorize_and_consume(api_key, consume=1)
    rules = storage.get_rules(api_key)

    response.headers["X-Scudo-Quota-Remaining"] = str(tenant["remaining_quota"])
    client_ip = (richiesta.client_ip or "").strip()
    req_path = (richiesta.path or "").strip()

    # Check tenant excluded paths
    if req_path:
        for prefix in rules["exclude_paths"]:
            if not prefix:
                continue
            norm_prefix = prefix.rstrip("/") or "/"
            if req_path == norm_prefix or req_path.startswith(norm_prefix + "/"):
                return {
                    "status": "200 OK",
                    "blocked": False,
                    "is_malicious": False,
                    "category": "none",
                    "level": "L0-ExcludedPath",
                    "risk_score": 0.0,
                    "latency_ms": 0.01,
                    "request_id": "excluded_path",
                    "quota_remaining": tenant["remaining_quota"],
                    "messaggio": "Accesso consentito (percorso escluso)",
                }

    # Check tenant allowlist / blocklist first
    if client_ip and client_ip in rules["allowlist_ips"]:
        return {
            "status": "200 OK",
            "blocked": False,
            "is_malicious": False,
            "category": "none",
            "level": "L0-Allowlist",
            "risk_score": 0.0,
            "latency_ms": 0.01,
            "request_id": "allowlist",
            "quota_remaining": tenant["remaining_quota"],
            "messaggio": "Accesso consentito (allowlist)",
        }

    if client_ip and client_ip in rules["blocklist_ips"]:
        is_blocked = rules["mode"] == "block"
        background_tasks.add_task(
            _persist_attack_log,
            "ip_blocklist (L0-Blocklist)",
            f"Blocked IP: {client_ip}",
            api_key,
            risk_score=1.0,
            latency_ms=0.01,
            level="L0-Blocklist",
            client_ip=client_ip,
        )
        if rules["webhook_url"]:
            background_tasks.add_task(
                _dispatch_webhook,
                rules["webhook_url"],
                category=ThreatCategory.IP_BLOCKLIST.value,
                level="L0-Blocklist",
                risk_score=1.0,
                request_id="ip_block",
                client_ip=client_ip,
                payload_preview=f"Blocked IP: {client_ip}",
            )
        return {
            "status": "403 Forbidden" if is_blocked else "200 OK (Monitored)",
            "blocked": is_blocked,
            "is_malicious": True,
            "category": ThreatCategory.IP_BLOCKLIST.value,
            "level": "L0-Blocklist",
            "risk_score": 1.0,
            "latency_ms": 0.01,
            "request_id": "ip_block",
            "quota_remaining": tenant["remaining_quota"],
            "messaggio": "IP BLOCCATO" if is_blocked else "IP monitorato",
        }

    result = engine.inspect(richiesta.testo)

    # Apply tenant-specific ML threshold when decision came from ML / cache of ML score
    effective_malicious = result.is_malicious
    effective_category = result.category.value
    tenant_thresh = float(rules["ml_threshold"])
    if result.level in {"L3-ML", "L2-Cache"} and result.category in {
        ThreatCategory.NONE,
        ThreatCategory.ML_ANOMALY,
    }:
        effective_malicious = result.risk_score >= tenant_thresh
        effective_category = ThreatCategory.ML_ANOMALY.value if effective_malicious else ThreatCategory.NONE.value

    effective_blocked = effective_malicious and rules["mode"] == "block"

    payload_for_log = richiesta.testo
    redaction_info: dict[str, Any] | None = None
    if rules["redact_pii"]:
        red = redact_sensitive_data(richiesta.testo, redact_pii=True, redact_secrets=True)
        payload_for_log = red.redacted_text
        redaction_info = red.to_dict()

    if effective_malicious:
        background_tasks.add_task(
            _persist_attack_log,
            f"{effective_category} ({result.level})",
            payload_for_log,
            api_key,
            risk_score=result.risk_score,
            latency_ms=result.latency_ms,
            level=result.level,
            client_ip=client_ip,
        )
        if rules["webhook_url"]:
            background_tasks.add_task(
                _dispatch_webhook,
                rules["webhook_url"],
                category=effective_category,
                level=result.level,
                risk_score=result.risk_score,
                request_id=result.request_id,
                client_ip=client_ip,
                payload_preview=payload_for_log,
            )

        out: dict[str, Any] = {
            "status": "403 Forbidden" if effective_blocked else "200 OK (Monitored)",
            "blocked": effective_blocked,
            "is_malicious": True,
            "category": effective_category,
            "level": result.level,
            "risk_score": round(result.risk_score, 4),
            "latency_ms": round(result.latency_ms, 4),
            "request_id": result.request_id,
            "quota_remaining": tenant["remaining_quota"],
            "messaggio": "ATTACCO BLOCCATO" if effective_blocked else "Attacco rilevato (Modalita Monitor)",
        }
        if redaction_info is not None:
            out["redaction"] = redaction_info
        return out

    out_ok: dict[str, Any] = {
        "status": "200 OK",
        "blocked": False,
        "is_malicious": False,
        "category": effective_category,
        "level": result.level,
        "risk_score": round(result.risk_score, 4),
        "latency_ms": round(result.latency_ms, 4),
        "request_id": result.request_id,
        "quota_remaining": tenant["remaining_quota"],
        "messaggio": "Accesso consentito",
    }
    if redaction_info is not None:
        out_ok["redaction"] = redaction_info
    return out_ok


@app.post("/v1/telemetry")
async def ingest_telemetry(
    event: TelemetryEvent,
    background_tasks: BackgroundTasks,
    authorization: str | None = Header(None),
) -> dict[str, str]:
    """Receive asynchronous threat telemetry from SDK middleware deployments."""
    api_key = _extract_bearer(authorization)
    _authorize_read_only(api_key)

    label = event.category or event.tipo_attacco
    background_tasks.add_task(
        _persist_attack_log,
        label,
        event.payload_malevolo,
        api_key,
        risk_score=event.risk_score,
        level=event.level or "L1-Regex",
        client_ip=event.client_ip or "",
    )
    return {"status": "accepted"}


@app.post("/v1/keys/provision")
async def provision_api_key(
    req: ProvisionKeyRequest,
    x_scudo_admin_secret: str | None = Header(None),
) -> dict[str, Any]:
    """Provision a new tenant API key and initialize default WAF rules."""
    if req.plan in {"pro", "enterprise"} and ADMIN_SECRET:
        if not x_scudo_admin_secret or not hmac.compare_digest(x_scudo_admin_secret, ADMIN_SECRET):
            raise HTTPException(status_code=403, detail="Admin secret richiesto per provisioning piani Pro/Enterprise")

    created = storage.create_api_key(str(req.email), req.plan)
    return {
        "status": "created",
        "api_key": created["api_key"],
        "key_prefix": created["key_prefix"],
        "email": created["email"],
        "plan": created["plan"],
        "monthly_quota": created["monthly_quota"],
    }


@app.post("/v1/keys/rotate")
async def rotate_key(authorization: str | None = Header(None)) -> dict[str, Any]:
    """Rotate the caller's active API key and revoke the old key."""
    api_key = _extract_bearer(authorization)
    _authorize_read_only(api_key)
    rotated = storage.rotate_api_key(api_key)
    if rotated is None:
        raise HTTPException(status_code=401, detail="API Key non valida o già revocata")
    return {
        "status": "rotated",
        "api_key": rotated["api_key"],
        "key_prefix": rotated["key_prefix"],
        "plan": rotated["plan"],
        "monthly_quota": rotated["monthly_quota"],
    }


@app.post("/v1/keys/subscription")
async def sync_subscription(
    req: SubscriptionSyncRequest,
    x_scudo_admin_secret: str | None = Header(None),
) -> dict[str, Any]:
    """Synchronize Stripe subscription activation/cancellation into Control Plane storage."""
    if ADMIN_SECRET:
        if not x_scudo_admin_secret or not hmac.compare_digest(x_scudo_admin_secret, ADMIN_SECRET):
            raise HTTPException(status_code=403, detail="Admin secret non valido")

    if req.action == "activate":
        if not req.email:
            raise HTTPException(status_code=400, detail="Email richiesta per attivazione piano")
        res = storage.upgrade_or_provision_subscription(
            str(req.email),
            req.plan,
            stripe_customer_id=req.stripe_customer_id,
            stripe_subscription_id=req.stripe_subscription_id,
        )
        return {"status": "activated", "plan": res["plan"], "key_prefix": res["key_prefix"], "api_key": res.get("api_key")}

    updated = storage.deactivate_subscription(
        stripe_customer_id=req.stripe_customer_id,
        stripe_subscription_id=req.stripe_subscription_id,
        email=str(req.email) if req.email else None,
        downgrade_to_free=True,
    )
    return {"status": "deactivated", "downgraded_keys": updated, "plan": "free"}


@app.get("/v1/account")
async def get_account(authorization: str | None = Header(None)) -> dict[str, Any]:
    """Return current tenant plan, monthly quota usage, custom rules, and attack summary."""
    api_key = _extract_bearer(authorization)
    tenant = _authorize_read_only(api_key)
    rules = storage.get_rules(api_key)
    logs = storage.get_attack_logs(api_key, limit=10)
    return {
        "email": tenant["email"],
        "plan": tenant["plan"],
        "key_prefix": tenant["key_prefix"],
        "monthly_quota": tenant["monthly_quota"],
        "used_this_month": tenant["used_this_month"],
        "remaining_quota": tenant["remaining_quota"],
        "rules": rules,
        "recent_attack_count": len(logs),
    }


@app.get("/v1/rules")
async def read_rules(authorization: str | None = Header(None)) -> dict[str, Any]:
    """Read custom WAF rules for the authenticated tenant."""
    api_key = _extract_bearer(authorization)
    _authorize_read_only(api_key)
    return storage.get_rules(api_key)


@app.put("/v1/rules")
async def update_rules(
    patch: RulesUpdateRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Update custom WAF policy rules for the authenticated tenant."""
    api_key = _extract_bearer(authorization)
    _authorize_read_only(api_key)
    try:
        updated = storage.update_rules(api_key, patch.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return updated


@app.get("/v1/logs")
async def read_logs(
    limit: int = 200,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Fetch recent security logs for the authenticated tenant."""
    api_key = _extract_bearer(authorization)
    _authorize_read_only(api_key)
    safe_limit = max(1, min(limit, 1000))
    return {"logs": storage.get_attack_logs(api_key, limit=safe_limit)}


@app.get("/v1/metrics")
async def metrics() -> dict[str, Any]:
    """Return engine statistics and event counter."""
    stats = engine.stats()
    stats["storage"] = ACTIVE_STORAGE
    stats["recent_memory_events"] = storage.count_total_logs()
    return stats


if __name__ == "__main__":
    porta = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=porta)
