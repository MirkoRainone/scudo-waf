"""PII & API-secret detection and redaction for LLM Guard & API pipelines."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

# Order matters: secrets & long structured IDs (IBAN, Credit Card) first, then Email, CF, Phone.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "secret_openai_key",
        re.compile(r"\bsk-(?:proj-|live-|test-|svcacct-)?[A-Za-z0-9_-]{16,}\b"),
    ),
    (
        "secret_anthropic_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
    ),
    (
        "secret_scudo_key",
        re.compile(r"\bsk_(?:live|free|test)_[A-Za-z0-9_-]{12,}\b"),
    ),
    (
        "secret_aws_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "secret_github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "secret_slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "secret_google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ),
    (
        "secret_jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b")
_ITALIAN_CF_RE = re.compile(r"\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b")
_CREDIT_CARD_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")
_PHONE_RE = re.compile(r"(?<!\w)\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b")


def luhn_valid(digits: str) -> bool:
    """Return ``True`` if ``digits`` passes the Luhn credit card checksum."""
    if not (13 <= len(digits) <= 19) or not digits.isdigit() or len(set(digits)) <= 1:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        val = ord(ch) - 48
        if idx % 2 == 1:
            val *= 2
            if val > 9:
                val -= 9
        total += val
    return total % 10 == 0


def _mask_value(raw: str) -> str:
    cleaned = raw.strip()
    if len(cleaned) <= 6:
        return "***"
    return f"{cleaned[:3]}***{cleaned[-2:]}"


@dataclass
class RedactionResult:
    """Outcome produced by :class:`PiiRedactor`."""

    redacted_text: str
    contains_pii: bool
    contains_secrets: bool
    findings: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize redaction outcome to a JSON-friendly dict."""
        return asdict(self)


class PiiRedactor:
    """Detector and redactor for PII (emails, cards, IBAN, CF, phone) and API secrets."""

    def redact(
        self,
        text: str,
        *,
        redact_pii: bool = True,
        redact_secrets: bool = True,
    ) -> RedactionResult:
        """Scan ``text`` and replace detected sensitive tokens with placeholders."""
        if not text:
            return RedactionResult(
                redacted_text="",
                contains_pii=False,
                contains_secrets=False,
                findings=[],
            )

        out = text
        findings: list[dict[str, str]] = []
        has_secrets = False
        has_pii = False

        if redact_secrets:
            for secret_type, pat in _SECRET_PATTERNS:

                def _replace_secret(m: re.Match[str], stype: str = secret_type) -> str:
                    nonlocal has_secrets
                    has_secrets = True
                    findings.append({"type": stype, "masked": _mask_value(m.group(0))})
                    return "[REDACTED_SECRET]"

                out = pat.sub(_replace_secret, out)

        if redact_pii:

            def _replace_cc(m: re.Match[str]) -> str:
                nonlocal has_pii
                raw = m.group(0)
                digits = "".join(ch for ch in raw if ch.isdigit())
                if not luhn_valid(digits):
                    return raw
                has_pii = True
                findings.append({"type": "credit_card", "masked": f"****-{digits[-4:]}"})
                return "[REDACTED_CREDIT_CARD]"

            out = _CREDIT_CARD_RE.sub(_replace_cc, out)

            def _replace_iban(m: re.Match[str]) -> str:
                nonlocal has_pii
                raw = m.group(0)
                compact = raw.replace(" ", "")
                if not (15 <= len(compact) <= 34) or sum(ch.isdigit() for ch in compact) < 8:
                    return raw
                has_pii = True
                findings.append({"type": "iban", "masked": _mask_value(compact)})
                return "[REDACTED_IBAN]"

            out = _IBAN_RE.sub(_replace_iban, out)

            def _replace_cf(m: re.Match[str]) -> str:
                nonlocal has_pii
                has_pii = True
                findings.append({"type": "italian_cf", "masked": _mask_value(m.group(0))})
                return "[REDACTED_CF]"

            out = _ITALIAN_CF_RE.sub(_replace_cf, out)

            def _replace_email(m: re.Match[str]) -> str:
                nonlocal has_pii
                has_pii = True
                findings.append({"type": "email", "masked": _mask_value(m.group(0))})
                return "[REDACTED_EMAIL]"

            out = _EMAIL_RE.sub(_replace_email, out)

            def _replace_phone(m: re.Match[str]) -> str:
                nonlocal has_pii
                has_pii = True
                findings.append({"type": "phone", "masked": _mask_value(m.group(0))})
                return "[REDACTED_PHONE]"

            out = _PHONE_RE.sub(_replace_phone, out)

        return RedactionResult(
            redacted_text=out,
            contains_pii=has_pii,
            contains_secrets=has_secrets,
            findings=findings,
        )


_DEFAULT_REDACTOR = PiiRedactor()


def redact_sensitive_data(
    text: str,
    *,
    redact_pii: bool = True,
    redact_secrets: bool = True,
) -> RedactionResult:
    """Convenience function to scan and redact PII and/or secrets from text."""
    return _DEFAULT_REDACTOR.redact(text, redact_pii=redact_pii, redact_secrets=redact_secrets)
