"""Multi-tenant storage layer for Scudo WAF Control Plane (SQLite / In-Memory / Supabase)."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("scudo_waf.storage")

PLAN_QUOTAS: dict[str, int] = {
    "free": 10_000,
    "pro": 500_000,
    "enterprise": 10_000_000,
}

DEFAULT_RULES: dict[str, Any] = {
    "mode": "block",
    "ml_threshold": 0.75,
    "allowlist_ips": [],
    "blocklist_ips": [],
    "exclude_paths": ["/health", "/metrics", "/static"],
    "redact_pii": False,
    "webhook_url": None,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_api_key(api_key: str) -> str:
    """Return hex SHA-256 digest of an API key."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def mask_api_key(api_key: str) -> str:
    """Return a non-sensitive display prefix for logs and UI."""
    if len(api_key) <= 10:
        return f"{api_key[:4]}***"
    return f"{api_key[:10]}...{api_key[-3:]}"


def generate_api_key(plan: str = "free") -> str:
    """Generate a prefixed tenant API key."""
    prefix = "sk_live_" if plan in {"pro", "enterprise"} else "sk_free_"
    return f"{prefix}{secrets.token_hex(12)}"


class ScudoStorage:
    """Thread-safe dual-mode multi-tenant persistence for keys, quotas, rules, and logs."""

    def __init__(
        self,
        mode: str = "memory",
        *,
        sqlite_path: Path | str | None = None,
        supabase_client: Any | None = None,
    ) -> None:
        self.mode = mode
        self.supabase = supabase_client
        self._lock = threading.RLock()

        if mode == "sqlite" and sqlite_path is not None:
            path_obj = Path(sqlite_path)
            path_obj.parent.mkdir(parents=True, exist_ok=True)
            db_target = str(path_obj)
        else:
            db_target = ":memory:"

        # Always keep a relational SQLite engine (either on-disk or :memory:) so full
        # multi-tenant rules, quotas, and logs work consistently even with Supabase fallback.
        self._conn = sqlite3.connect(db_target, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        schema_file = Path(__file__).resolve().parent / "schema.sql"
        sql = schema_file.read_text(encoding="utf-8")
        with self._lock:
            self._conn.executescript(sql)
            self._conn.commit()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._conn.close()

    def ensure_seed_key(
        self,
        api_key: str,
        *,
        email: str = "demo@scudo-waf.dev",
        plan: str = "pro",
    ) -> dict[str, Any]:
        """Ensure ``api_key`` exists in storage (idempotent)."""
        if not api_key:
            raise ValueError("Seed API key cannot be empty")
        key_hash = hash_api_key(api_key)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            if row is not None:
                return self._row_to_tenant(row)

            clean_plan = plan if plan in PLAN_QUOTAS else "pro"
            quota = PLAN_QUOTAS[clean_plan]
            now = _now_iso()
            self._conn.execute(
                """
                INSERT INTO api_keys (
                    key_hash, key_prefix, email, plan, monthly_quota, used_this_month,
                    is_active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?)
                """,
                (key_hash, mask_api_key(api_key), email, clean_plan, quota, now, now),
            )
            self._ensure_default_rules(key_hash, now)
            self._conn.commit()
            created = self._conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            assert created is not None
            return self._row_to_tenant(created)

    def _ensure_default_rules(self, key_hash: str, now: str) -> None:
        self._conn.execute(
            """
            INSERT OR IGNORE INTO tenant_rules (
                key_hash, mode, ml_threshold, allowlist_ips, blocklist_ips,
                exclude_paths, redact_pii, webhook_url, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key_hash,
                DEFAULT_RULES["mode"],
                DEFAULT_RULES["ml_threshold"],
                json.dumps(DEFAULT_RULES["allowlist_ips"]),
                json.dumps(DEFAULT_RULES["blocklist_ips"]),
                json.dumps(DEFAULT_RULES["exclude_paths"]),
                int(DEFAULT_RULES["redact_pii"]),
                DEFAULT_RULES["webhook_url"],
                now,
            ),
        )

    @staticmethod
    def _row_to_tenant(row: sqlite3.Row) -> dict[str, Any]:
        quota = int(row["monthly_quota"])
        used = int(row["used_this_month"])
        return {
            "key_hash": row["key_hash"],
            "key_prefix": row["key_prefix"],
            "email": row["email"],
            "plan": row["plan"],
            "monthly_quota": quota,
            "used_this_month": used,
            "remaining_quota": max(0, quota - used),
            "is_active": bool(row["is_active"]),
            "stripe_customer_id": row["stripe_customer_id"],
            "stripe_subscription_id": row["stripe_subscription_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_api_key(
        self,
        email: str,
        plan: str = "free",
        *,
        raw_key: str | None = None,
        monthly_quota: int | None = None,
        stripe_customer_id: str | None = None,
        stripe_subscription_id: str | None = None,
    ) -> dict[str, Any]:
        """Provision a fresh API key and default rules for a customer tenant."""
        clean_plan = plan.lower().strip()
        if clean_plan not in PLAN_QUOTAS:
            clean_plan = "free"
        quota = monthly_quota if monthly_quota is not None else PLAN_QUOTAS[clean_plan]
        secret_key = raw_key or generate_api_key(clean_plan)
        key_hash = hash_api_key(secret_key)
        prefix = mask_api_key(secret_key)
        now = _now_iso()

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO api_keys (
                    key_hash, key_prefix, email, plan, monthly_quota, used_this_month,
                    is_active, stripe_customer_id, stripe_subscription_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?)
                """,
                (
                    key_hash,
                    prefix,
                    email.strip().lower(),
                    clean_plan,
                    quota,
                    stripe_customer_id,
                    stripe_subscription_id,
                    now,
                    now,
                ),
            )
            self._ensure_default_rules(key_hash, now)
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            assert row is not None
            info = self._row_to_tenant(row)

        if self.supabase is not None:
            try:
                self.supabase.table("api_keys").insert(
                    {
                        "key_string": secret_key,
                        "key_hash": key_hash,
                        "email": email.strip().lower(),
                        "plan": clean_plan,
                        "is_active": True,
                    }
                ).execute()
            except Exception as exc:
                logger.warning("Supabase create_api_key mirror failed (continuing locally): %s", exc)

        info["api_key"] = secret_key
        return info

    def upgrade_or_provision_subscription(
        self,
        email: str,
        plan: str = "pro",
        *,
        stripe_customer_id: str | None = None,
        stripe_subscription_id: str | None = None,
    ) -> dict[str, Any]:
        """Upgrade an existing active customer key to ``plan`` or provision a new one."""
        clean_email = email.strip().lower()
        clean_plan = plan.lower().strip() if plan.lower().strip() in PLAN_QUOTAS else "pro"
        quota = PLAN_QUOTAS[clean_plan]
        now = _now_iso()

        with self._lock:
            row = None
            if stripe_customer_id:
                row = self._conn.execute(
                    "SELECT * FROM api_keys WHERE stripe_customer_id = ? ORDER BY id DESC LIMIT 1",
                    (stripe_customer_id,),
                ).fetchone()
            if row is None and clean_email:
                row = self._conn.execute(
                    "SELECT * FROM api_keys WHERE email = ? AND is_active = 1 ORDER BY id DESC LIMIT 1",
                    (clean_email,),
                ).fetchone()

            if row is not None:
                self._conn.execute(
                    """
                    UPDATE api_keys
                    SET plan = ?, monthly_quota = ?, is_active = 1,
                        stripe_customer_id = COALESCE(?, stripe_customer_id),
                        stripe_subscription_id = COALESCE(?, stripe_subscription_id),
                        updated_at = ?
                    WHERE key_hash = ?
                    """,
                    (clean_plan, quota, stripe_customer_id, stripe_subscription_id, now, row["key_hash"]),
                )
                self._conn.commit()
                updated = self._conn.execute(
                    "SELECT * FROM api_keys WHERE key_hash = ?",
                    (row["key_hash"],),
                ).fetchone()
                assert updated is not None
                return self._row_to_tenant(updated)

        return self.create_api_key(
            clean_email,
            clean_plan,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
        )

    def deactivate_subscription(
        self,
        *,
        stripe_customer_id: str | None = None,
        stripe_subscription_id: str | None = None,
        email: str | None = None,
        downgrade_to_free: bool = True,
    ) -> int:
        """Downgrade or deactivate subscription keys following Stripe cancellation/payment failure."""
        now = _now_iso()
        clauses: list[str] = []
        params: list[Any] = []
        if stripe_subscription_id:
            clauses.append("stripe_subscription_id = ?")
            params.append(stripe_subscription_id)
        if stripe_customer_id:
            clauses.append("stripe_customer_id = ?")
            params.append(stripe_customer_id)
        if email:
            clauses.append("email = ?")
            params.append(email.strip().lower())
        if not clauses:
            return 0

        where_sql = " OR ".join(clauses)
        with self._lock:
            if downgrade_to_free:
                cur = self._conn.execute(
                    f"""
                    UPDATE api_keys
                    SET plan = 'free', monthly_quota = ?, updated_at = ?
                    WHERE ({where_sql})
                    """,
                    [PLAN_QUOTAS["free"], now, *params],
                )
            else:
                cur = self._conn.execute(
                    f"""
                    UPDATE api_keys
                    SET is_active = 0, updated_at = ?
                    WHERE ({where_sql})
                    """,
                    [now, *params],
                )
            self._conn.commit()
            return int(cur.rowcount)

    def rotate_api_key(self, current_api_key: str) -> dict[str, Any] | None:
        """Issue a replacement API key for the same tenant and revoke the previous one."""
        old_hash = hash_api_key(current_api_key)
        with self._lock:
            old_row = self._conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1",
                (old_hash,),
            ).fetchone()
            if old_row is None:
                return None

            new_key = generate_api_key(old_row["plan"])
            new_hash = hash_api_key(new_key)
            now = _now_iso()

            self._conn.execute(
                "UPDATE api_keys SET is_active = 0, updated_at = ? WHERE key_hash = ?",
                (now, old_hash),
            )
            self._conn.execute(
                """
                INSERT INTO api_keys (
                    key_hash, key_prefix, email, plan, monthly_quota, used_this_month,
                    is_active, stripe_customer_id, stripe_subscription_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                """,
                (
                    new_hash,
                    mask_api_key(new_key),
                    old_row["email"],
                    old_row["plan"],
                    old_row["monthly_quota"],
                    old_row["used_this_month"],
                    old_row["stripe_customer_id"],
                    old_row["stripe_subscription_id"],
                    now,
                    now,
                ),
            )

            # Copy existing tenant rules & logs association cleanly
            rules_row = self._conn.execute(
                "SELECT * FROM tenant_rules WHERE key_hash = ?",
                (old_hash,),
            ).fetchone()
            if rules_row is not None:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO tenant_rules (
                        key_hash, mode, ml_threshold, allowlist_ips, blocklist_ips,
                        exclude_paths, redact_pii, webhook_url, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_hash,
                        rules_row["mode"],
                        rules_row["ml_threshold"],
                        rules_row["allowlist_ips"],
                        rules_row["blocklist_ips"],
                        rules_row["exclude_paths"],
                        rules_row["redact_pii"],
                        rules_row["webhook_url"],
                        now,
                    ),
                )
            else:
                self._ensure_default_rules(new_hash, now)

            self._conn.execute(
                "UPDATE log_attacchi SET key_hash = ? WHERE key_hash = ?",
                (new_hash, old_hash),
            )
            self._conn.commit()
            created = self._conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?",
                (new_hash,),
            ).fetchone()
            assert created is not None
            out = self._row_to_tenant(created)
            out["api_key"] = new_key
            return out

    def get_tenant(self, api_key: str) -> dict[str, Any] | None:
        """Fetch active tenant details by plaintext API key."""
        key_hash = hash_api_key(api_key)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1",
                (key_hash,),
            ).fetchone()
            if row is not None:
                return self._row_to_tenant(row)

        if self.supabase is not None:
            try:
                res = (
                    self.supabase.table("api_keys")
                    .select("*")
                    .eq("key_string", api_key)
                    .eq("is_active", True)
                    .execute()
                )
                if res.data:
                    item = res.data[0]
                    return self.ensure_seed_key(
                        api_key,
                        email=str(item.get("email", "customer@scudo-waf.dev")),
                        plan=str(item.get("plan", "pro")),
                    )
            except Exception as exc:
                logger.error("Supabase API key lookup error: %s", exc)
        return None

    def set_quota_for_testing(self, api_key: str, *, monthly_quota: int, used_this_month: int = 0) -> None:
        """Adjust quota limits (for administrative / test scenarios)."""
        key_hash = hash_api_key(api_key)
        with self._lock:
            self._conn.execute(
                "UPDATE api_keys SET monthly_quota = ?, used_this_month = ?, updated_at = ? WHERE key_hash = ?",
                (monthly_quota, used_this_month, _now_iso(), key_hash),
            )
            self._conn.commit()

    def validate_and_consume_quota(
        self,
        api_key: str,
        *,
        consume: int = 1,
    ) -> tuple[str, dict[str, Any] | None]:
        """Validate ``api_key`` and atomically consume ``consume`` monthly quota units.

        Returns ``("ok", tenant)``, ``("invalid", None)``, or ``("quota_exceeded", tenant)``.
        """
        tenant = self.get_tenant(api_key)
        if tenant is None:
            return "invalid", None

        key_hash = tenant["key_hash"]
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1",
                (key_hash,),
            ).fetchone()
            if row is None:
                return "invalid", None

            used = int(row["used_this_month"])
            quota = int(row["monthly_quota"])
            if used + consume > quota:
                return "quota_exceeded", self._row_to_tenant(row)

            self._conn.execute(
                "UPDATE api_keys SET used_this_month = used_this_month + ?, updated_at = ? WHERE key_hash = ?",
                (consume, _now_iso(), key_hash),
            )
            self._conn.commit()
            updated = self._conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            assert updated is not None
            return "ok", self._row_to_tenant(updated)

    def get_rules(self, api_key: str) -> dict[str, Any]:
        """Return per-tenant custom WAF policy rules."""
        key_hash = hash_api_key(api_key)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tenant_rules WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            if row is None:
                return dict(DEFAULT_RULES)
            return {
                "mode": row["mode"],
                "ml_threshold": float(row["ml_threshold"]),
                "allowlist_ips": json.loads(row["allowlist_ips"]),
                "blocklist_ips": json.loads(row["blocklist_ips"]),
                "exclude_paths": json.loads(row["exclude_paths"]),
                "redact_pii": bool(row["redact_pii"]),
                "webhook_url": row["webhook_url"],
                "updated_at": row["updated_at"],
            }

    def update_rules(self, api_key: str, patch: dict[str, Any]) -> dict[str, Any]:
        """Validate and persist updated custom rules for ``api_key``."""
        key_hash = hash_api_key(api_key)
        now = _now_iso()
        with self._lock:
            self._ensure_default_rules(key_hash, now)
            current = self.get_rules(api_key)

            mode = str(patch.get("mode", current["mode"])).lower().strip()
            if mode not in {"block", "monitor"}:
                raise ValueError("mode must be 'block' or 'monitor'")

            ml_threshold = float(patch.get("ml_threshold", current["ml_threshold"]))
            if not (0.0 <= ml_threshold <= 1.0):
                raise ValueError("ml_threshold must be between 0.0 and 1.0")

            def _str_list(val: Any) -> list[str]:
                if not isinstance(val, list):
                    return []
                return [str(x).strip() for x in val if str(x).strip()]

            allowlist_ips = (
                _str_list(patch["allowlist_ips"]) if "allowlist_ips" in patch else current["allowlist_ips"]
            )
            blocklist_ips = (
                _str_list(patch["blocklist_ips"]) if "blocklist_ips" in patch else current["blocklist_ips"]
            )
            exclude_paths = (
                _str_list(patch["exclude_paths"]) if "exclude_paths" in patch else current["exclude_paths"]
            )
            redact_pii = bool(patch.get("redact_pii", current["redact_pii"]))
            webhook_raw = patch.get("webhook_url", current["webhook_url"])
            webhook_url = str(webhook_raw).strip() if webhook_raw else None

            self._conn.execute(
                """
                UPDATE tenant_rules
                SET mode = ?, ml_threshold = ?, allowlist_ips = ?, blocklist_ips = ?,
                    exclude_paths = ?, redact_pii = ?, webhook_url = ?, updated_at = ?
                WHERE key_hash = ?
                """,
                (
                    mode,
                    ml_threshold,
                    json.dumps(allowlist_ips),
                    json.dumps(blocklist_ips),
                    json.dumps(exclude_paths),
                    int(redact_pii),
                    webhook_url,
                    now,
                    key_hash,
                ),
            )
            self._conn.commit()
            return self.get_rules(api_key)

    def log_attack(
        self,
        api_key: str,
        tipo_attacco: str,
        payload: str,
        *,
        risk_score: float = 1.0,
        latency_ms: float = 0.0,
        level: str = "L1-Regex",
        client_ip: str = "",
    ) -> None:
        """Persist a blocked/monitored security event for ``api_key``."""
        key_hash = hash_api_key(api_key)
        masked = mask_api_key(api_key)
        now = _now_iso()
        preview = payload[:500]

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO log_attacchi (
                    created_at, key_hash, api_key_usata, tipo_attacco, payload_malevolo,
                    risk_score, latency_ms, level, client_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (now, key_hash, masked, tipo_attacco, preview, float(risk_score), float(latency_ms), level, client_ip),
            )
            self._conn.commit()

        if self.supabase is not None:
            try:
                self.supabase.table("log_attacchi").insert(
                    {
                        "tipo_attacco": tipo_attacco,
                        "payload_malevolo": preview,
                        "api_key_usata": api_key,
                    }
                ).execute()
            except Exception as exc:
                logger.error("Failed async log insert to Supabase: %s", exc)

    def get_attack_logs(self, api_key: str, *, limit: int = 200) -> list[dict[str, Any]]:
        """Return recent attack logs scoped to ``api_key``."""
        key_hash = hash_api_key(api_key)
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT created_at, tipo_attacco, payload_malevolo, risk_score, latency_ms, level, client_ip
                FROM log_attacchi
                WHERE key_hash = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (key_hash, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def count_total_logs(self) -> int:
        """Return total number of recorded security events across all tenants."""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS cnt FROM log_attacchi").fetchone()
            return int(row["cnt"]) if row else 0

    def record_waitlist(self, email: str, piano: str) -> None:
        """Persist a waitlist signup in SQLite (and optionally Supabase)."""
        now = _now_iso()
        clean_email = email.strip().lower()
        clean_plan = piano.strip().lower()
        with self._lock:
            self._conn.execute(
                "INSERT INTO waitlist (cliente_email, piano_scelto, created_at) VALUES (?, ?, ?)",
                (clean_email, clean_plan, now),
            )
            self._conn.commit()
