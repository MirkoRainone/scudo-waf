"""Universal ASGI Reverse-Proxy Sidecar protected by Scudo 3-Level WAF."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp

from .config import WafConfig
from .engine import ScudoEngine
from .middleware import WafMiddleware

logger = logging.getLogger("scudo_waf.proxy")

_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)
_RESPONSE_SKIP_HEADERS = _HOP_BY_HOP_HEADERS | frozenset({"content-encoding"})


def create_proxy_app(
    upstream_url: str,
    config: WafConfig | None = None,
    *,
    timeout: float = 30.0,
    transport: Any | None = None,
) -> ASGIApp:
    """Create a universal reverse-proxy ASGI app wrapping ``upstream_url`` with Scudo WAF.

    Any HTTP service (Node.js, Go, PHP, Ruby, Java, Python) placed behind this proxy
    receives L0–L3 hybrid protection without modifying application source code.
    """
    try:
        import httpx
    except ImportError as exc:
        raise RuntimeError(
            "Scudo reverse-proxy requires 'httpx'. Install with: pip install 'scudo-waf[proxy]'"
        ) from exc

    clean_upstream = upstream_url.rstrip("/")
    if not clean_upstream:
        raise ValueError("upstream_url must be a non-empty URL (e.g. http://127.0.0.1:3000)")

    cfg = config if config is not None else WafConfig()
    for internal_path in ("/_scudo/health", "/_scudo/stats"):
        if internal_path not in cfg.exclude_paths:
            cfg.exclude_paths = tuple([*cfg.exclude_paths, internal_path])

    engine = ScudoEngine(cfg)
    client_holder: dict[str, httpx.AsyncClient | None] = {"client": None}

    def _get_client() -> httpx.AsyncClient:
        cli = client_holder["client"]
        if cli is None or cli.is_closed:
            kwargs: dict[str, Any] = {
                "base_url": clean_upstream,
                "timeout": timeout,
                "follow_redirects": False,
            }
            if transport is not None:
                kwargs["transport"] = transport
            cli = httpx.AsyncClient(**kwargs)
            client_holder["client"] = cli
        return cli

    async def _shutdown() -> None:
        cli = client_holder["client"]
        if cli is not None and not cli.is_closed:
            await cli.aclose()
            client_holder["client"] = None

    async def scudo_health(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "service": "scudo-reverse-proxy",
                "version": "1.0.0",
                "upstream": clean_upstream,
                "ml_loaded": engine.ml_loaded,
                "mode": cfg.mode.value,
            }
        )

    async def scudo_stats(_request: Request) -> JSONResponse:
        return JSONResponse(engine.stats())

    async def forward_request(request: Request) -> Response:
        rel_path = request.url.path or "/"
        query = request.url.query
        target = f"{rel_path}?{query}" if query else rel_path

        fwd_headers: dict[str, str] = {}
        for k, v in request.headers.items():
            if k.lower() not in _HOP_BY_HOP_HEADERS:
                fwd_headers[k] = v

        client_host = request.client.host if request.client else "unknown"
        existing_xff = fwd_headers.get("x-forwarded-for") or fwd_headers.get("X-Forwarded-For")
        fwd_headers["X-Forwarded-For"] = f"{existing_xff}, {client_host}" if existing_xff else client_host

        body = await request.body()
        client = _get_client()
        try:
            upstream_resp = await client.request(
                method=request.method,
                url=target,
                headers=fwd_headers,
                content=body if body else None,
            )
        except httpx.RequestError as exc:
            logger.warning("Upstream request to %s%s failed: %s", clean_upstream, target, exc)
            return JSONResponse(
                status_code=502,
                content={
                    "detail": "Bad Gateway: upstream unavailable",
                    "upstream": clean_upstream,
                },
                headers={"X-Scudo-Proxy": "v1.0.0"},
            )

        resp_headers = {
            k: v
            for k, v in upstream_resp.headers.items()
            if k.lower() not in _RESPONSE_SKIP_HEADERS
        }
        resp_headers["X-Scudo-Proxy"] = "v1.0.0"

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=upstream_resp.headers.get("content-type"),
        )

    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    routes = [
        Route("/_scudo/health", scudo_health, methods=["GET"]),
        Route("/_scudo/stats", scudo_stats, methods=["GET"]),
        Route("/", forward_request, methods=methods),
        Route("/{path:path}", forward_request, methods=methods),
    ]

    @asynccontextmanager
    async def _lifespan(_app: Starlette) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await _shutdown()

    inner_app = Starlette(routes=routes, lifespan=_lifespan)
    return WafMiddleware(
        inner_app,
        config=cfg,
        engine=engine,
        expose_headers=True,
    )
