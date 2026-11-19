-- Scudo WAF v1.0.0 Control Plane Schema (SQLite & PostgreSQL / Supabase compatible)

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    email TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    monthly_quota INTEGER NOT NULL DEFAULT 10000,
    used_this_month INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_rules (
    key_hash TEXT PRIMARY KEY,
    mode TEXT NOT NULL DEFAULT 'block',
    ml_threshold REAL NOT NULL DEFAULT 0.75,
    allowlist_ips TEXT NOT NULL DEFAULT '[]',
    blocklist_ips TEXT NOT NULL DEFAULT '[]',
    exclude_paths TEXT NOT NULL DEFAULT '["/health","/metrics","/static"]',
    redact_pii INTEGER NOT NULL DEFAULT 0,
    webhook_url TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log_attacchi (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    api_key_usata TEXT NOT NULL,
    tipo_attacco TEXT NOT NULL,
    payload_malevolo TEXT NOT NULL,
    risk_score REAL NOT NULL DEFAULT 1.0,
    latency_ms REAL NOT NULL DEFAULT 0.0,
    level TEXT NOT NULL DEFAULT 'L1-Regex',
    client_ip TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_logs_key_created ON log_attacchi (key_hash, created_at DESC);

CREATE TABLE IF NOT EXISTS waitlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cliente_email TEXT NOT NULL,
    piano_scelto TEXT NOT NULL,
    created_at TEXT NOT NULL
);
