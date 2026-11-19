"""Pure ASGI WAF Middleware for FastAPI and Starlette applications."""

from __future__ import annotations

import asyncio
import html
import inspect
import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qsl

from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import InspectionResult, ThreatCategory, WafConfig, WafMode
from .engine import ScudoEngine
from .normalizer import extract_values_from_json
from .telemetry import TelemetryClient

logger = logging.getLogger("scudo_waf.middleware")

_UNSET: Any = object()
_INSPECTED_HEADERS = ("user-agent", "referer", "x-forwarded-host", "cookie")


def _render_block_html(result: InspectionResult) -> str:
    safe_cat = html.escape(result.category.value)
    safe_req = html.escape(result.request_id)
    safe_level = html.escape(result.level)
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>403 Forbidden — Scudo WAF</title></head>
<body style="background:#0f172a;color:#f8fafc;text-align:center;padding:72px 20px;font-family:Inter,system-ui,sans-serif;margin:0;">
  <div style="max-width:560px;margin:0 auto;background:#1e293b;border:1px solid #334155;border-radius:16px;padding:40px;">
    <div style="font-size:2.5rem;margin-bottom:8px;">&#128737;&#65039;</div>
    <h1 style="font-size:1.75rem;margin:0 0 12px;color:#fb7185;">Request Blocked by Scudo WAF</h1>
    <p style="color:#cbd5e1;line-height:1.6;margin:0 0 24px;">
      Our 3-level hybrid firewall intercepted this request due to a detected security threat.
    </p>
    <div style="background:#0f172a;border-radius:8px;padding:12px 16px;font-family:monospace;font-size:0.85rem;color:#94a3b8;text-align:left;margin-bottom:24px;">
      <div>Category: <strong style="color:#f8fafc;">{safe_cat}</strong></div>
      <div>Engine Level: <strong style="color:#f8fafc;">{safe_level}</strong></div>
      <div>Request ID: <strong style="color:#f8fafc;">{safe_req}</strong></div>
    </div>
    <a href="/" style="display:inline-block;background:#10b981;color:#fff;padding:10px 22px;border-radius:8px;text-decoration:none;font-weight:600;">Return Home</a>
  </div>
</body>
</html>"""


def _render_rate_limit_html(client_ip: str) -> str:
    safe_ip = html.escape(client_ip)
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>429 Too Many Requests — Scudo WAF</title></head>
<body style="background:#0f172a;color:#f8fafc;text-align:center;padding:72px 20px;font-family:Inter,system-ui,sans-serif;margin:0;">
  <div style="max-width:520px;margin:0 auto;background:#1e293b;border:1px solid #334155;border-radius:16px;padding:40px;">
    <h1 style="font-size:1.65rem;margin:0 0 12px;color:#fbbf24;">429 Too Many Requests</h1>
    <p style="color:#cbd5e1;line-height:1.6;">Rate limit exceeded for IP <code>{safe_ip}</code>. Please retry in 60 seconds.</p>
  </div>
</body>
</html>"""


class WafMiddleware:
    """Pure ASGI 3-level Hybrid Web Application Firewall middleware.

    Compatible with FastAPI and Starlette via ``app.add_middleware(WafMiddleware, ...)``.
    """

    def __init__(
        self,
        app: ASGIApp,
        api_key: str = "sk_test_default",
        *,
        config: WafConfig | None = None,
        mode: WafMode | str | None = None,
        ml_threshold: float | None = None,
        rate_limit_per_minute: int | None = _UNSET,
        exclude_paths: tuple[str, ...] | list[str] | None = None,
        allowlist_ips: frozenset[str] | set[str] | list[str] | tuple[str, ...] | None = None,
        blocklist_ips: frozenset[str] | set[str] | list[str] | tuple[str, ...] | None = None,
        inspect_headers: bool | None = None,
        inspect_path: bool | None = None,
        inspect_prompt_injection: bool | None = None,
        fail_open: bool | None = None,
        validate_key: Callable[[str], bool] | None = None,
        block_response: Callable[[InspectionResult], Response] | Response | None = None,
        on_block: Callable[[InspectionResult, dict[str, Any]], Any] | None = None,
        on_allow: Callable[[InspectionResult, dict[str, Any]], Any] | None = None,
        telemetry_url: str | None = None,
        enable_telemetry: bool | None = None,
        expose_headers: bool | None = None,
        engine: ScudoEngine | None = None,
    ) -> None:
        self.app = app
        cfg = config if config is not None else WafConfig(api_key=api_key)
        if config is not None and api_key != "sk_test_default":
            cfg.api_key = api_key
        if mode is not None:
            cfg.mode = WafMode(mode.lower()) if isinstance(mode, str) else mode
        if ml_threshold is not None:
            cfg.ml_threshold = ml_threshold
        if rate_limit_per_minute is not _UNSET:
            cfg.rate_limit_per_minute = rate_limit_per_minute
        if exclude_paths is not None:
            cfg.exclude_paths = tuple(exclude_paths)
        if allowlist_ips is not None:
            cfg.allowlist_ips = frozenset(allowlist_ips)
        if blocklist_ips is not None:
            cfg.blocklist_ips = frozenset(blocklist_ips)
        if inspect_headers is not None:
            cfg.inspect_headers = inspect_headers
        if inspect_path is not None:
            cfg.inspect_path = inspect_path
        if inspect_prompt_injection is not None:
            cfg.inspect_prompt_injection = inspect_prompt_injection
        if fail_open is not None:
            cfg.fail_open = fail_open
        if telemetry_url is not None:
            cfg.telemetry_url = telemetry_url
        if enable_telemetry is not None:
            cfg.enable_telemetry = enable_telemetry
        if expose_headers is not None:
            cfg.expose_headers = expose_headers

        if validate_key is not None and not validate_key(cfg.api_key):
            raise ValueError("Invalid Scudo WAF API key rejected by validate_key callback.")

        self.config = cfg
        self.api_key = cfg.api_key
        self.engine = engine if engine is not None else ScudoEngine(cfg)
        self.block_response = block_response
        self.on_block = on_block
        self.on_allow = on_allow
        self.telemetry: TelemetryClient | None = (
            TelemetryClient(cfg.telemetry_url, cfg.api_key)
            if cfg.enable_telemetry and cfg.telemetry_url
            else None
        )

    def _is_excluded(self, path: str) -> bool:
        for prefix in self.config.exclude_paths:
            if not prefix:
                continue
            normalized = prefix.rstrip("/") or "/"
            if path == normalized or path.startswith(normalized + "/"):
                return True
        return False

    @staticmethod
    def _extract_client_ip(scope: Scope, headers: dict[str, str]) -> str:
        xff = headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        client = scope.get("client")
        if client and isinstance(client, (tuple, list)) and client[0]:
            return str(client[0])
        return "unknown"

    @staticmethod
    def _wants_json(headers: dict[str, str]) -> bool:
        accept = headers.get("accept", "").lower()
        ctype = headers.get("content-type", "").lower()
        return "application/json" in accept or "application/json" in ctype

    async def _invoke_hook(
        self,
        hook: Callable[..., Any] | None,
        result: InspectionResult,
        context: dict[str, Any],
    ) -> None:
        if hook is None:
            return
        try:
            sig = inspect.signature(hook)
            param_count = len(sig.parameters)
        except (TypeError, ValueError):
            param_count = 1
        out = hook(result) if param_count == 1 else hook(result, context)
        if inspect.isawaitable(out):
            await out

    def _build_scudo_headers(self, result: InspectionResult, status_label: str) -> dict[str, str]:
        if not self.config.expose_headers:
            return {}
        return {
            "X-Scudo-Status": status_label,
            "X-Scudo-Latency-Ms": f"{result.latency_ms:.3f}",
            "X-Scudo-Request-Id": result.request_id,
        }

    def _make_block_response(
        self,
        result: InspectionResult,
        headers: dict[str, str],
    ) -> Response:
        extra_headers = self._build_scudo_headers(
            result,
            "blocked" if result.blocked else "monitored",
        )
        if self.block_response is not None:
            resp = self.block_response(result) if callable(self.block_response) else self.block_response
            for k, v in extra_headers.items():
                resp.headers[k] = v
            return resp

        if self._wants_json(headers):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Request blocked by Scudo WAF",
                    "category": result.category.value,
                    "level": result.level,
                    "risk_score": round(result.risk_score, 4),
                    "matched_rule": result.matched_rule,
                    "request_id": result.request_id,
                },
                headers=extra_headers,
            )

        return HTMLResponse(
            content=_render_block_html(result),
            status_code=403,
            headers=extra_headers,
        )

    async def _forward_request(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        result: InspectionResult,
    ) -> None:
        if not self.config.expose_headers:
            await self.app(scope, receive, send)
            return

        status_label = "monitored" if result.is_malicious else "allowed"
        scudo_hdrs = self._build_scudo_headers(result, status_label)
        encoded_hdrs = [
            (k.lower().encode("latin-1"), v.encode("latin-1"))
            for k, v in scudo_hdrs.items()
        ]

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = list(message.get("headers", []))
                existing.extend(encoded_hdrs)
                message = {**message, "headers": existing}
            await send(message)

        await self.app(scope, receive, send_wrapper)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", "/"))
        if self._is_excluded(path):
            await self.app(scope, receive, send)
            return

        headers_dict: dict[str, str] = {}
        for raw_k, raw_v in scope.get("headers", []):
            k = raw_k.decode("latin-1").lower()
            v = raw_v.decode("latin-1")
            headers_dict[k] = f"{headers_dict[k]}, {v}" if k in headers_dict else v

        client_ip = self._extract_client_ip(scope, headers_dict)
        if client_ip in self.config.allowlist_ips:
            await self.app(scope, receive, send)
            return

        # Level 0a: Explicit IP blocklist
        if self.engine.is_ip_blocked(client_ip):
            is_blocked = self.config.mode == WafMode.BLOCK
            block_res = InspectionResult(
                blocked=is_blocked,
                is_malicious=True,
                category=ThreatCategory.IP_BLOCKLIST,
                level="L0-Blocklist",
                risk_score=1.0,
                latency_ms=0.01,
                matched_rule="ip_blocklist",
                request_id=uuid.uuid4().hex[:12],
                mode=self.config.mode,
            )
            self.engine._record_stats(block_res)
            method = str(scope.get("method", "GET")).upper()
            context = {"path": path, "method": method, "client_ip": client_ip}
            await self._invoke_hook(self.on_block, block_res, context)
            if self.telemetry is not None:
                asyncio.create_task(
                    self.telemetry.send_event(
                        block_res,
                        f"Blocked IP: {client_ip}",
                        path=path,
                        client_ip=client_ip,
                    )
                )
            if block_res.blocked:
                block_resp = self._make_block_response(block_res, headers_dict)
                await block_resp(scope, receive, send)
                return
            await self._forward_request(scope, receive, send, block_res)
            return

        # Level 0b: Per-IP rate limiting
        if not self.engine.check_rate_limit(client_ip):
            rate_headers = {"Retry-After": "60"}
            if self._wants_json(headers_dict):
                resp: Response = JSONResponse(
                    status_code=429,
                    content={"detail": "Too Many Requests", "category": ThreatCategory.RATE_LIMIT.value},
                    headers=rate_headers,
                )
            else:
                resp = HTMLResponse(
                    content=_render_rate_limit_html(client_ip),
                    status_code=429,
                    headers=rate_headers,
                )
            await resp(scope, receive, send)
            return

        method = str(scope.get("method", "GET")).upper()
        body_bytes = b""
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            chunks: list[bytes] = []
            while True:
                message = await receive()
                if message["type"] == "http.request":
                    chunks.append(message.get("body", b""))
                    if not message.get("more_body", False):
                        break
                elif message["type"] == "http.disconnect":
                    break
            body_bytes = b"".join(chunks)

        body_sent = False

        async def replay_receive() -> Message:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            return await receive()

        final_result = InspectionResult(
            blocked=False,
            is_malicious=False,
            category=ThreatCategory.NONE,
            level="none",
            risk_score=0.0,
            latency_ms=0.0,
            mode=self.config.mode,
        )
        matched_payload_preview = ""

        try:
            # 1. Inspect path (L1 Regex only to avoid path ML false positives)
            if self.config.inspect_path and path and path != "/":
                res = self.engine.inspect(path, regex_only=True)
                final_result = res
                if res.is_malicious:
                    matched_payload_preview = path

            # 2. Inspect headers (L1 Regex only — standard browser UAs never trigger ML)
            if not final_result.is_malicious and self.config.inspect_headers:
                for hdr_name in _INSPECTED_HEADERS:
                    hdr_val = headers_dict.get(hdr_name)
                    if hdr_val:
                        res = self.engine.inspect(hdr_val, regex_only=True)
                        if res.is_malicious:
                            final_result = res
                            matched_payload_preview = f"{hdr_name}: {hdr_val}"
                            break

            # 3. Inspect query parameters (Full L1 -> L2 -> L3)
            if not final_result.is_malicious:
                query_raw = scope.get("query_string", b"").decode("utf-8", errors="ignore")
                if query_raw:
                    pairs = parse_qsl(query_raw, keep_blank_values=True)
                    query_candidates: list[str] = []
                    if pairs:
                        values = [v for _, v in pairs if v]
                        empty_keys = [k for k, v in pairs if not v and k]
                        if values:
                            query_candidates.append(" ".join(values))
                        if empty_keys:
                            query_candidates.append(" ".join(empty_keys))
                        # Also check keys via regex only in case an attack is placed in a parameter name
                        for k, _ in pairs:
                            if k:
                                key_res = self.engine.inspect(k, regex_only=True)
                                if key_res.is_malicious:
                                    final_result = key_res
                                    matched_payload_preview = k
                                    break
                    else:
                        query_candidates.append(query_raw)

                    if not final_result.is_malicious:
                        for q_text in query_candidates:
                            res = self.engine.inspect(q_text)
                            final_result = res
                            if res.is_malicious:
                                matched_payload_preview = q_text
                                break

            # 4. Inspect request body (Full L1 -> L2 -> L3)
            if not final_result.is_malicious and body_bytes:
                raw_body = body_bytes.decode("utf-8", errors="ignore")
                ctype = headers_dict.get("content-type", "").lower()
                candidates: list[str] = []

                if "application/json" in ctype or raw_body.lstrip().startswith(("{", "[")):
                    json_vals = extract_values_from_json(raw_body)
                    if json_vals is not None:
                        if len(json_vals) <= 3:
                            joined = " ".join(json_vals)
                            if joined:
                                candidates.append(joined)
                        else:
                            # Inspect individual field strings so one payload cannot be diluted by benign fields
                            candidates.extend(v for v in json_vals if v.strip())
                    elif raw_body.strip():
                        candidates.append(raw_body)
                elif "application/x-www-form-urlencoded" in ctype:
                    form_pairs = parse_qsl(raw_body, keep_blank_values=True)
                    if form_pairs:
                        candidates.extend(v for _, v in form_pairs if v.strip())
                        for k, _ in form_pairs:
                            if k:
                                key_res = self.engine.inspect(k, regex_only=True)
                                if key_res.is_malicious:
                                    final_result = key_res
                                    matched_payload_preview = k
                                    break
                    elif raw_body.strip():
                        candidates.append(raw_body)
                elif raw_body.strip():
                    candidates.append(raw_body)

                if not final_result.is_malicious and candidates:
                    # Pass 1: fast L1 regex across all fields so explicit signatures are never masked
                    for item in candidates:
                        res = self.engine.inspect(item, regex_only=True)
                        if res.is_malicious:
                            final_result = res
                            matched_payload_preview = item
                            break
                    # Pass 2: full L2 cache + L3 ML inspection
                    if not final_result.is_malicious:
                        for item in candidates:
                            res = self.engine.inspect(item)
                            final_result = res
                            if res.is_malicious:
                                matched_payload_preview = item
                                break

            # 5. Act on inspection outcome
            context = {"path": path, "method": method, "client_ip": client_ip}
            if final_result.is_malicious:
                await self._invoke_hook(self.on_block, final_result, context)
                if self.telemetry is not None:
                    asyncio.create_task(
                        self.telemetry.send_event(
                            final_result,
                            matched_payload_preview or path,
                            path=path,
                            client_ip=client_ip,
                        )
                    )
                if final_result.blocked:
                    block_resp = self._make_block_response(final_result, headers_dict)
                    await block_resp(scope, replay_receive, send)
                    return
            else:
                await self._invoke_hook(self.on_allow, final_result, context)

        except Exception as exc:
            if not self.config.fail_open:
                raise
            logger.warning("WafMiddleware inspection error (fail-open active): %s", exc)

        await self._forward_request(scope, replay_receive, send, final_result)
