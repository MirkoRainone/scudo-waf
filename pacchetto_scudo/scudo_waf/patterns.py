"""Compiled Level-1 signature rules across 6 attack families."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .config import ThreatCategory


@dataclass(frozen=True)
class Rule:
    """A single named Level-1 detection signature."""

    name: str
    category: ThreatCategory
    pattern: re.Pattern[str]


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


CORE_RULES: tuple[Rule, ...] = (
    # --- SQL Injection ---
    Rule(
        name="sqli_tautology",
        category=ThreatCategory.SQLI,
        pattern=_compile(
            r"(?:^|['\"\s(])(?:OR|AND)\s+(?:'[^']{1,20}'\s*=\s*'[^']{1,20}'|\"[^\"]{1,20}\"\s*=\s*\"[^\"]{1,20}\"|\d+\s*=\s*\d+)(?:\s*(?:--|#|$|/\*|\)))"
        ),
    ),
    Rule(
        name="sqli_union_select",
        category=ThreatCategory.SQLI,
        pattern=_compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b"),
    ),
    Rule(
        name="sqli_stacked_ddl",
        category=ThreatCategory.SQLI,
        pattern=_compile(
            r";\s*(?:DROP|TRUNCATE|ALTER)\s+(?:TABLE|DATABASE|SCHEMA)\b|;\s*DELETE\s+FROM\s+[a-z_][a-z0-9_]*|;\s*INSERT\s+INTO\s+[a-z_][a-z0-9_]*"
        ),
    ),
    Rule(
        name="sqli_time_blind",
        category=ThreatCategory.SQLI,
        pattern=_compile(
            r"\b(?:SLEEP|PG_SLEEP|BENCHMARK)\s*\(\s*\d+|\bWAITFOR\s+DELAY\s+['\"]\d"
        ),
    ),
    Rule(
        name="sqli_schema_error",
        category=ThreatCategory.SQLI,
        pattern=_compile(
            r"\binformation_schema\.(?:tables|columns)\b|\b(?:EXTRACTVALUE|UPDATEXML)\s*\(|\bINTO\s+(?:OUTFILE|DUMPFILE)\b|'\s*(?:--|#|;)"
        ),
    ),
    # --- Cross-Site Scripting (XSS) & SSTI ---
    Rule(
        name="xss_script_tag",
        category=ThreatCategory.XSS,
        pattern=_compile(r"<\s*/?\s*script\b[^>]*>"),
    ),
    Rule(
        name="xss_event_handler",
        category=ThreatCategory.XSS,
        pattern=_compile(
            r"<[a-z][a-z0-9]*\b[^>]*\bon(?:error|load|toggle|focus|mouseover|click|start|mouseenter|blur|input)\s*="
        ),
    ),
    Rule(
        name="xss_dangerous_uri",
        category=ThreatCategory.XSS,
        pattern=_compile(r"\b(?:javascript|vbscript)\s*:|data\s*:\s*text/html"),
    ),
    Rule(
        name="xss_dom_eval",
        category=ThreatCategory.XSS,
        pattern=_compile(
            r"\bdocument\.(?:cookie|domain|write)\b|\beval\s*\(|\balert\s*\("
        ),
    ),
    Rule(
        name="xss_ssti",
        category=ThreatCategory.XSS,
        pattern=_compile(
            r"\{\{\s*(?:\d+\s*[\*+\-/]\s*\d+|config\.|self\.|request\.|__class__|__mro__)\b"
        ),
    ),
    # --- Command Injection (checked before LFI so `; cat /etc/passwd` classifies as CMDi) ---
    Rule(
        name="cmd_shell_separator",
        category=ThreatCategory.COMMAND_INJECTION,
        pattern=_compile(
            r"(?:;|\|\||\|(?!\|)|&&)\s*(?:cat|ls|id|whoami|uname|pwd|env|printenv|bash|sh|zsh|nc|ncat|curl|wget|python3?|perl|ruby|powershell|cmd(?:\.exe)?|chmod|chown|rm)\b"
        ),
    ),
    Rule(
        name="cmd_subshell",
        category=ThreatCategory.COMMAND_INJECTION,
        pattern=_compile(
            r"\$\(\s*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|nc|python3?)\b|`[^`]{1,120}(?:cat|ls|id|whoami|uname|curl|wget|bash|sh)[^`]*`|\bpowershell\s+[^\n]*\s-enc\b"
        ),
    ),
    # --- Server-Side Request Forgery (SSRF; checked before LFI so `file:///etc/passwd` classifies as SSRF) ---
    Rule(
        name="ssrf_cloud_metadata",
        category=ThreatCategory.SSRF,
        pattern=_compile(
            r"(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)(?::\d+)?(?:/|$)"
        ),
    ),
    Rule(
        name="ssrf_internal_or_scheme",
        category=ThreatCategory.SSRF,
        pattern=_compile(
            r"\b(?:file|gopher|dict)://|\bhttps?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|2130706433|0x7f000001)(?::\d+)?/"
        ),
    ),
    # --- Path Traversal / LFI ---
    Rule(
        name="lfi_dot_dot_slash",
        category=ThreatCategory.PATH_TRAVERSAL,
        pattern=_compile(r"(?:\.\.[/\\]){2,}"),
    ),
    Rule(
        name="lfi_sensitive_files",
        category=ThreatCategory.PATH_TRAVERSAL,
        pattern=_compile(
            r"/(?:etc/(?:passwd|shadow|hosts)|proc/self/(?:environ|cmdline)|windows[/\\]win\.ini|boot\.ini)|php://(?:filter|input)|expect://"
        ),
    ),
)

PROMPT_INJECTION_RULES: tuple[Rule, ...] = (
    Rule(
        name="prompt_ignore_instructions",
        category=ThreatCategory.PROMPT_INJECTION,
        pattern=_compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|directives|constraints|policies|guidelines)\b"
        ),
    ),
    Rule(
        name="prompt_reveal_system",
        category=ThreatCategory.PROMPT_INJECTION,
        pattern=_compile(
            r"\b(?:reveal|print|repeat|output|leak|show)\s+(?:your\s+|the\s+)?(?:full\s+|hidden\s+|entire\s+)?(?:system\s+prompt|system\s+message|system\s+instructions|secret\s+api\s+keys)\b"
        ),
    ),
    Rule(
        name="prompt_jailbreak_role",
        category=ThreatCategory.PROMPT_INJECTION,
        pattern=_compile(
            r"\b(?:you\s+are\s+now\s+DAN|Do\s+Anything\s+Now|Developer\s+Mode|pretend\s+safety\s+policies\s+do\s+not\s+exist)\b"
        ),
    ),
    Rule(
        name="prompt_delimiter_override",
        category=ThreatCategory.PROMPT_INJECTION,
        pattern=_compile(
            r"(?:###\s*SYSTEM\s*:|\[INST\]\s*<<SYS>>|<\|im_start\|>system|===\s*ADMIN\s+OVERRIDE\s*===)"
        ),
    ),
    Rule(
        name="prompt_ignore_multilang",
        category=ThreatCategory.PROMPT_INJECTION,
        pattern=_compile(
            r"\b(?:ignora|dimentica|disattiva)\s+(?:tutte\s+)?(?:le\s+)?(?:istruzioni|regole|direttive)\s+(?:precedenti|di\s+sistema)\b|\b(?:ignora|olvida)\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+anteriores\b"
        ),
    ),
)


def match_patterns(
    text: str,
    *,
    include_prompt_injection: bool = True,
) -> tuple[ThreatCategory, str] | None:
    """Return ``(ThreatCategory, rule_name)`` on first L1 match, else ``None``."""
    if not text:
        return None
    for rule in CORE_RULES:
        if rule.pattern.search(text):
            return rule.category, rule.name
    if include_prompt_injection:
        for rule in PROMPT_INJECTION_RULES:
            if rule.pattern.search(text):
                return rule.category, rule.name
    return None
