"""Web HTML router for the Scudo WAF landing page."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["Pagine Web"])

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get("/", response_class=HTMLResponse)
async def mostra_landing(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@router.get("/terms", response_class=HTMLResponse)
async def mostra_terms(request: Request):
    return templates.TemplateResponse(request=request, name="terms.html")


@router.get("/privacy", response_class=HTMLResponse)
async def mostra_privacy(request: Request):
    return templates.TemplateResponse(request=request, name="privacy.html")
