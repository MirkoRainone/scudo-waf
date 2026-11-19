"""Configuration, enums, and inspection result models for Scudo WAF."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ThreatCategory(str, Enum):
    """Supported attack classification categories."""

    NONE = "none"
    SQLI = "sqli"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    PROMPT_INJECTION = "prompt_injection"
    ML_ANOMALY = "ml_anomaly"
    RATE_LIMIT = "rate_limit"
    IP_BLOCKLIST = "ip_blocklist"


class WafMode(str, Enum):
    """Enforcement behavior when a threat is detected."""

    BLOCK = "block"
    MONITOR = "monitor"


@dataclass
class WafConfig:
    """Configuration options for :class:`ScudoEngine` and :class:`WafMiddleware`."""

    api_key: str = "sk_test_default"
    mode: WafMode = WafMode.BLOCK
    ml_threshold: float | None = None
    cache_maxsize: int = 10_000
    cache_ttl: int = 600
    max_input_length: int = 10_000
    inspect_headers: bool = True
    inspect_path: bool = True
    inspect_prompt_injection: bool = True
    rate_limit_per_minute: int | None = 120
    exclude_paths: tuple[str, ...] = ("/health", "/metrics", "/static", "/favicon.ico")
    allowlist_ips: frozenset[str] = field(default_factory=frozenset)
    blocklist_ips: frozenset[str] = field(default_factory=frozenset)
    expose_headers: bool = False
    fail_open: bool = True
    telemetry_url: str | None = None
    enable_telemetry: bool = False
    model_dir: Path | str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.mode, str):
            self.mode = WafMode(self.mode.lower())
        if isinstance(self.exclude_paths, list):
            self.exclude_paths = tuple(self.exclude_paths)
        if not isinstance(self.allowlist_ips, frozenset):
            self.allowlist_ips = frozenset(self.allowlist_ips)
        if not isinstance(self.blocklist_ips, frozenset):
            self.blocklist_ips = frozenset(self.blocklist_ips)
        if self.ml_threshold is not None and not (0.0 <= self.ml_threshold <= 1.0):
            raise ValueError("ml_threshold must be between 0.0 and 1.0")
        if self.max_input_length <= 0:
            raise ValueError("max_input_length must be positive")


@dataclass
class InspectionResult:
    """Structured outcome produced by :meth:`ScudoEngine.inspect`."""

    blocked: bool
    is_malicious: bool
    category: ThreatCategory
    level: str
    risk_score: float
    latency_ms: float
    matched_rule: str | None = None
    request_id: str = ""
    mode: WafMode = WafMode.BLOCK

    def to_dict(self) -> dict[str, Any]:
        """Serialize the inspection outcome to a JSON-friendly dictionary."""
        return {
            "blocked": self.blocked,
            "is_malicious": self.is_malicious,
            "category": self.category.value,
            "level": self.level,
            "risk_score": round(self.risk_score, 4),
            "latency_ms": round(self.latency_ms, 4),
            "matched_rule": self.matched_rule,
            "request_id": self.request_id,
            "mode": self.mode.value,
        }
