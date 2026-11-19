"""Scudo WAF — AI-Powered Hybrid Web Application Firewall for Python APIs & LLMs."""

from __future__ import annotations

from .adapters import (
    PromptGuard,
    PromptInjectionError,
    ScudoDjangoMiddleware,
    ScudoFlask,
)
from .config import InspectionResult, ThreatCategory, WafConfig, WafMode
from .engine import ScudoEngine, analyze, get_default_engine
from .middleware import WafMiddleware
from .pii import PiiRedactor, RedactionResult, redact_sensitive_data
from .proxy import create_proxy_app

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "WafMiddleware",
    "ScudoEngine",
    "WafConfig",
    "WafMode",
    "ThreatCategory",
    "InspectionResult",
    "analyze",
    "get_default_engine",
    "ScudoFlask",
    "ScudoDjangoMiddleware",
    "PromptGuard",
    "PromptInjectionError",
    "PiiRedactor",
    "RedactionResult",
    "redact_sensitive_data",
    "create_proxy_app",
]
