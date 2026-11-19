"""Input canonicalization, structural de-obfuscation, and JSON value extraction."""

from __future__ import annotations

import base64
import binascii
import html
import json
import re
import unicodedata
from typing import Any
from urllib.parse import unquote_plus

_MYSQL_COND_COMMENT_RE = re.compile(r"/\*!\d*\s*(.*?)\*/", re.DOTALL)
_SQL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_SQL_SPLIT_KEYWORDS = frozenset(
    {
        "UNION",
        "ALL",
        "SELECT",
        "FROM",
        "WHERE",
        "OR",
        "AND",
        "DROP",
        "DELETE",
        "INSERT",
        "UPDATE",
        "SLEEP",
        "HAVING",
        "ORDER",
        "GROUP",
        "INTO",
    }
)
_HEX_LITERAL_RE = re.compile(r"\b0x([0-9a-fA-F]{8,128})\b")
_BASE64_CALL_RE = re.compile(
    r"(?:atob|base64_decode|frombase64)\s*\(\s*['\"]([A-Za-z0-9+/=_-]{8,512})['\"]\s*\)|base64,([A-Za-z0-9+/=_-]{8,512})",
    re.IGNORECASE,
)
_BASE64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=_-])")
_WHITESPACE_RE = re.compile(r"\s+")


def _is_printable_ascii(raw_bytes: bytes) -> bool:
    if not raw_bytes:
        return False
    return all((32 <= b <= 126) or b in (9, 10, 13) for b in raw_bytes)


def decode_inline_hex(text: str) -> str:
    """Decode printable ASCII ``0x...`` SQL/XSS hex literals in-place or as tokens."""
    if "0x" not in text and "0X" not in text:
        return text

    def _replace(match: re.Match[str]) -> str:
        hex_str = match.group(1)
        if len(hex_str) % 2 != 0:
            return match.group(0)
        try:
            decoded_bytes = bytes.fromhex(hex_str)
        except ValueError:
            return match.group(0)
        if _is_printable_ascii(decoded_bytes):
            decoded = decoded_bytes.decode("ascii", errors="ignore").strip()
            if decoded and any(ch.isalpha() or ch in "<>'\";=/" for ch in decoded):
                return f"{match.group(0)} {decoded}"
        return match.group(0)

    return _HEX_LITERAL_RE.sub(_replace, text)


def _try_decode_base64(token: str) -> str | None:
    padded = token.replace("-", "+").replace("_", "/")
    rem = len(padded) % 4
    if rem:
        padded += "=" * (4 - rem)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 4 or not _is_printable_ascii(raw):
        return None
    decoded = raw.decode("ascii", errors="ignore").strip()
    if not decoded or decoded == token:
        return None
    if not any(ch.isalpha() for ch in decoded):
        return None
    return decoded


def expand_encoded_segments(text: str) -> str:
    """Decode inline hex literals and embedded Base64 attack segments for L1 scanning."""
    if not text:
        return ""
    expanded = decode_inline_hex(text)
    extras: list[str] = []

    for match in _BASE64_CALL_RE.finditer(expanded):
        candidate = match.group(1) or match.group(2)
        if candidate:
            decoded = _try_decode_base64(candidate)
            if decoded:
                extras.append(decoded)

    for match in _BASE64_TOKEN_RE.finditer(expanded):
        candidate = match.group(1)
        decoded = _try_decode_base64(candidate)
        if decoded and (" " in decoded or any(ch in "<>'\";=/" for ch in decoded)):
            extras.append(decoded)

    if extras:
        return f"{expanded} {' '.join(extras[:8])}"
    return expanded


def normalize_text(text: str, max_length: int = 10_000) -> str:
    """Canonicalize raw user input before inspection.

    Applies length truncation, null-byte stripping, iterative URL decoding (up
    to 3 passes to catch double-encoding), HTML entity unescaping, NFKC Unicode
    normalization, and whitespace collapsing.
    """
    if not text:
        return ""

    cleaned = text[:max_length].replace("\x00", "")

    for _ in range(3):
        decoded = unquote_plus(cleaned)
        if decoded == cleaned:
            break
        cleaned = decoded

    cleaned = html.unescape(cleaned)
    cleaned = unicodedata.normalize("NFKC", cleaned)
    cleaned = _WHITESPACE_RE.sub(" ", cleaned).strip()
    return cleaned[:max_length]


def _smart_strip_sql_comments(text: str) -> str:
    """Collapse obfuscating inline comments (UN/**/ION -> UNION) and normalize keyword separators."""

    def _replace_comment(match: re.Match[str]) -> str:
        start, end = match.span()
        left_slice = text[max(0, start - 20) : start]
        right_slice = text[end : min(len(text), end + 20)]

        left_m = re.search(r"([A-Za-z0-9_]+|['\")])$", left_slice)
        right_m = re.match(r"^([A-Za-z0-9_]+|['\"(])", right_slice)
        if not left_m or not right_m:
            return " "

        left_tok = left_m.group(1).upper()
        right_tok = right_m.group(1).upper()
        if (
            left_tok in _SQL_SPLIT_KEYWORDS
            or right_tok in _SQL_SPLIT_KEYWORDS
            or left_tok in {"'", '"', ")"}
            or right_tok in {"'", '"', "("}
        ):
            return " "
        return ""

    return _SQL_BLOCK_COMMENT_RE.sub(_replace_comment, text)


def normalize_for_regex(text: str, max_length: int = 10_000) -> str:
    """Normalize input, strip MySQL/SQL inline comments, and decode hex/base64 segments."""
    base = normalize_text(text, max_length=max_length)
    if not base:
        return ""
    unwrapped = _MYSQL_COND_COMMENT_RE.sub(r" \1 ", base)
    cleaned = _smart_strip_sql_comments(unwrapped) if "/*" in unwrapped else unwrapped
    expanded = expand_encoded_segments(cleaned)
    return _WHITESPACE_RE.sub(" ", expanded).strip()[:max_length]


def _collect_json_strings(node: Any, out: list[str], depth: int = 0) -> None:
    if depth > 16 or len(out) >= 512:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key:
                out.append(key)
            _collect_json_strings(value, out, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _collect_json_strings(item, out, depth + 1)
    elif isinstance(node, str):
        if node:
            out.append(node)
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        out.append(str(node))


def extract_values_from_json(raw: str) -> list[str] | None:
    """Parse a JSON payload and recursively extract string values and keys.

    Returns ``None`` if ``raw`` is not valid JSON.
    """
    if not raw:
        return None
    stripped = raw.lstrip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return None

    extracted: list[str] = []
    _collect_json_strings(parsed, extracted)
    return extracted
