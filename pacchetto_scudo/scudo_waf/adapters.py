"""Framework adapters for Flask, Django, and LLM Prompt Injection defense."""

from __future__ import annotations

import functools
import inspect
import uuid
from collections.abc import Callable
from typing import Any, TypeVar

from .config import InspectionResult, ThreatCategory, WafConfig
from .engine import ScudoEngine
from .pii import PiiRedactor, RedactionResult

F = TypeVar("F", bound=Callable[..., Any])


class PromptInjectionError(ValueError):
    """Raised by :class:`PromptGuard` when a prompt injection, secret leak, or limit violation is detected."""

    def __init__(self, message: str, result: InspectionResult) -> None:
        super().__init__(message)
        self.result = result


class PromptGuard:
    """Guard for LLM applications (LangChain, OpenAI, custom RAG agents)."""

    def __init__(
        self,
        engine: ScudoEngine | None = None,
        *,
        threshold: float | None = None,
        redact_pii: bool = False,
        redact_secrets: bool = False,
        block_secrets: bool = False,
        max_prompt_chars: int | None = None,
    ) -> None:
        if engine is not None:
            self.engine = engine
        else:
            cfg = WafConfig(ml_threshold=threshold, inspect_prompt_injection=True)
            self.engine = ScudoEngine(cfg)
        self.redact_pii = redact_pii
        self.redact_secrets = redact_secrets
        self.block_secrets = block_secrets
        self.max_prompt_chars = max_prompt_chars
        self.redactor = PiiRedactor()

    def check(self, prompt: str) -> InspectionResult:
        """Inspect ``prompt`` and raise :class:`PromptInjectionError` if unsafe."""
        if self.max_prompt_chars is not None and len(prompt) > self.max_prompt_chars:
            res_len = InspectionResult(
                blocked=True,
                is_malicious=True,
                category=ThreatCategory.PROMPT_INJECTION,
                level="L0-Length",
                risk_score=1.0,
                latency_ms=0.01,
                matched_rule="prompt_length_exceeded",
                request_id=uuid.uuid4().hex[:12],
                mode=self.engine.config.mode,
            )
            raise PromptInjectionError(
                f"Blocked oversized LLM prompt ({len(prompt)} > {self.max_prompt_chars} chars)",
                result=res_len,
            )

        result = self.engine.inspect_prompt(prompt)
        if result.is_malicious:
            raise PromptInjectionError(
                f"Blocked unsafe LLM prompt ({result.category.value}, rule={result.matched_rule})",
                result=result,
            )
        return result

    def sanitize(
        self,
        prompt: str,
        *,
        redact_pii: bool | None = None,
        redact_secrets: bool | None = None,
        block_secrets: bool | None = None,
    ) -> tuple[str, InspectionResult, RedactionResult | None]:
        """Inspect ``prompt`` for injection and optionally redact/block PII & API secrets."""
        result = self.check(prompt)
        do_pii = self.redact_pii if redact_pii is None else redact_pii
        do_sec = self.redact_secrets if redact_secrets is None else redact_secrets
        do_block_sec = self.block_secrets if block_secrets is None else block_secrets

        if not (do_pii or do_sec or do_block_sec):
            return prompt, result, None

        redaction = self.redactor.redact(
            prompt,
            redact_pii=do_pii,
            redact_secrets=(do_sec or do_block_sec),
        )
        if do_block_sec and redaction.contains_secrets:
            sec_res = InspectionResult(
                blocked=True,
                is_malicious=True,
                category=ThreatCategory.PROMPT_INJECTION,
                level="L0-Secrets",
                risk_score=1.0,
                latency_ms=result.latency_ms,
                matched_rule="secret_leak_blocked",
                request_id=result.request_id,
                mode=self.engine.config.mode,
            )
            raise PromptInjectionError(
                "Blocked LLM prompt containing exposed API key or secret token",
                result=sec_res,
            )
        return redaction.redacted_text, result, redaction

    def protect(
        self,
        func: F | None = None,
        *,
        arg_name: str = "prompt",
        redact_pii: bool | None = None,
        redact_secrets: bool | None = None,
        block_secrets: bool | None = None,
    ) -> Any:
        """Decorator protecting sync or async LLM handler functions."""

        def decorator(fn: F) -> F:
            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    new_args, new_kwargs = self._guard_call_args(
                        fn,
                        arg_name,
                        args,
                        kwargs,
                        redact_pii=redact_pii,
                        redact_secrets=redact_secrets,
                        block_secrets=block_secrets,
                    )
                    return await fn(*new_args, **new_kwargs)

                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                new_args, new_kwargs = self._guard_call_args(
                    fn,
                    arg_name,
                    args,
                    kwargs,
                    redact_pii=redact_pii,
                    redact_secrets=redact_secrets,
                    block_secrets=block_secrets,
                )
                return fn(*new_args, **new_kwargs)

            return sync_wrapper  # type: ignore[return-value]

        if func is not None:
            return decorator(func)
        return decorator

    def _guard_call_args(
        self,
        fn: Callable[..., Any],
        arg_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        redact_pii: bool | None = None,
        redact_secrets: bool | None = None,
        block_secrets: bool | None = None,
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        prompt_val = self._extract_prompt_arg(fn, arg_name, args, kwargs)
        if not isinstance(prompt_val, str):
            return args, kwargs

        sanitized, _, _ = self.sanitize(
            prompt_val,
            redact_pii=redact_pii,
            redact_secrets=redact_secrets,
            block_secrets=block_secrets,
        )
        if sanitized == prompt_val:
            return args, kwargs

        return self._replace_prompt_arg(fn, arg_name, args, kwargs, sanitized)

    @staticmethod
    def _replace_prompt_arg(
        fn: Callable[..., Any],
        arg_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        new_value: str,
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        if arg_name in kwargs and isinstance(kwargs[arg_name], str):
            updated_kw = dict(kwargs)
            updated_kw[arg_name] = new_value
            return args, updated_kw

        try:
            params = list(inspect.signature(fn).parameters.keys())
            if arg_name in params:
                idx = params.index(arg_name)
                if idx < len(args) and isinstance(args[idx], str):
                    updated_args = list(args)
                    updated_args[idx] = new_value
                    return tuple(updated_args), kwargs
        except Exception:
            pass

        if args and isinstance(args[0], str):
            return (new_value, *args[1:]), kwargs
        return args, kwargs

    @staticmethod
    def _extract_prompt_arg(
        fn: Callable[..., Any],
        arg_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> str | None:
        if arg_name in kwargs and isinstance(kwargs[arg_name], str):
            return kwargs[arg_name]
        try:
            bound = inspect.signature(fn).bind_partial(*args, **kwargs)
            if arg_name in bound.arguments and isinstance(bound.arguments[arg_name], str):
                return bound.arguments[arg_name]
        except Exception:
            pass
        if args and isinstance(args[0], str):
            return args[0]
        return None


class ScudoFlask:
    """Flask extension hooking :class:`ScudoEngine` into ``before_request``."""

    def __init__(self, app: Any = None, config: WafConfig | None = None) -> None:
        self.config = config or WafConfig()
        self.engine = ScudoEngine(self.config)
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Any) -> None:
        """Attach Scudo WAF protection to a Flask application instance."""
        from flask import abort, jsonify, request

        @app.before_request
        def _scudo_before_request() -> Any:
            path = request.path or "/"
            if any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.config.exclude_paths if p):
                return None

            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
            if client_ip in self.config.allowlist_ips:
                return None

            if self.engine.is_ip_blocked(client_ip):
                resp = jsonify(
                    {
                        "detail": "Forbidden: IP blocklisted",
                        "category": ThreatCategory.IP_BLOCKLIST.value,
                        "matched_rule": "ip_blocklist",
                    }
                )
                resp.status_code = 403
                return resp

            if not self.engine.check_rate_limit(client_ip):
                resp = jsonify({"detail": "Too Many Requests", "category": "rate_limit"})
                resp.status_code = 429
                resp.headers["Retry-After"] = "60"
                return resp

            candidates: list[str] = []
            if request.query_string:
                candidates.append(request.query_string.decode("utf-8", errors="ignore"))
            raw_body = request.get_data(as_text=True)
            if raw_body:
                candidates.append(raw_body)

            for item in candidates:
                res = self.engine.inspect(item)
                if res.blocked:
                    if request.is_json or "application/json" in request.headers.get("Accept", ""):
                        resp = jsonify(res.to_dict())
                        resp.status_code = 403
                        return resp
                    abort(403)
            return None


class ScudoDjangoMiddleware:
    """Django middleware integrating :class:`ScudoEngine` into HTTP request processing."""

    def __init__(self, get_response: Callable[[Any], Any]) -> None:
        self.get_response = get_response
        cfg = self._load_config()
        self.engine = ScudoEngine(cfg)

    @staticmethod
    def _load_config() -> WafConfig:
        try:
            from django.conf import settings  # type: ignore

            raw_cfg = getattr(settings, "SCUDO_WAF_CONFIG", None)
            if isinstance(raw_cfg, WafConfig):
                return raw_cfg
            if isinstance(raw_cfg, dict):
                return WafConfig(**raw_cfg)
        except Exception:
            pass
        return WafConfig()

    def __call__(self, request: Any) -> Any:
        path = getattr(request, "path", "/")
        for prefix in self.engine.config.exclude_paths:
            if prefix and (path == prefix or path.startswith(prefix.rstrip("/") + "/")):
                return self.get_response(request)

        meta = getattr(request, "META", {})
        client_ip = str(meta.get("HTTP_X_FORWARDED_FOR", meta.get("REMOTE_ADDR", "unknown"))).split(",")[0].strip()
        if client_ip in self.engine.config.allowlist_ips:
            return self.get_response(request)

        if self.engine.is_ip_blocked(client_ip):
            return self._build_django_response(
                {
                    "detail": "Forbidden: IP blocklisted",
                    "category": ThreatCategory.IP_BLOCKLIST.value,
                    "matched_rule": "ip_blocklist",
                },
                status=403,
            )

        if not self.engine.check_rate_limit(client_ip):
            return self._build_django_response(
                {"detail": "Too Many Requests", "category": "rate_limit"},
                status=429,
                headers={"Retry-After": "60"},
            )

        candidates: list[str] = []
        get_params = getattr(request, "GET", None)
        if get_params:
            candidates.append(" ".join(str(v) for v in get_params.values()))
        raw_body = getattr(request, "body", b"")
        if raw_body:
            candidates.append(raw_body.decode("utf-8", errors="ignore") if isinstance(raw_body, bytes) else str(raw_body))

        for item in candidates:
            if not item.strip():
                continue
            res = self.engine.inspect(item)
            if res.blocked:
                return self._build_django_response(res.to_dict(), status=403)

        return self.get_response(request)

    @staticmethod
    def _build_django_response(
        payload: dict[str, Any],
        *,
        status: int,
        headers: dict[str, str] | None = None,
    ) -> Any:
        try:
            from django.http import JsonResponse  # type: ignore

            resp = JsonResponse(payload, status=status)
            if headers:
                for k, v in headers.items():
                    resp[k] = v
            return resp
        except ImportError:
            import json

            class _MinimalResponse:
                def __init__(self, data: dict[str, Any], status_code: int) -> None:
                    self.status_code = status_code
                    self.content = json.dumps(data).encode("utf-8")
                    self.headers = headers or {}

            return _MinimalResponse(payload, status)
