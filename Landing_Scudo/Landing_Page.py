"""Scudo WAF Marketing Landing Page & Interactive Security Playground."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.routers import api, web
from scudo_waf import WafMiddleware

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
load_dotenv()

app = FastAPI(title="Scudo WAF", version="1.0.0")

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Dogfooding: protect the landing page with Scudo WAF, excluding the interactive demo analyzer and signed webhooks
WAF_API_KEY = os.environ.get("WAF_API_KEY", "sk_test_default")
app.add_middleware(
    WafMiddleware,
    api_key=WAF_API_KEY,
    exclude_paths=(
        "/health",
        "/api/v1/health",
        "/api/v1/demo/analyze",
        "/api/v1/stripe/webhook",
        "/static",
        "/favicon.ico",
    ),
    expose_headers=True,
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness endpoint for Docker/cloud healthchecks."""
    return {"status": "ok", "service": "scudo-landing", "version": "1.0.0"}


app.include_router(web.router)
app.include_router(api.router)
