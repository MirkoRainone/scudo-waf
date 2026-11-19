"""Asynchronous non-blocking telemetry sender with circuit-breaker protection."""

from __future__ import annotations

import logging
import time
from typing import Any

from .config import InspectionResult

logger = logging.getLogger("scudo_waf.telemetry")


def _mask_key(key: str) -> str:
    if len(key) <= 8:
        return "***"
    return f"{key[:6]}***{key[-2:]}"


class TelemetryClient:
    """Fire-and-forget async telemetry shipper with failure circuit breaker."""

    def __init__(
        self,
        url: str,
        api_key: str,
        *,
        timeout: float = 1.5,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ) -> None:
        self.url = url
        self.api_key = api_key
        self.timeout = timeout
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

    def is_circuit_open(self) -> bool:
        """Return ``True`` when telemetry shipping is temporarily paused."""
        return time.monotonic() < self._circuit_open_until

    async def send_event(
        self,
        result: InspectionResult,
        payload_preview: str,
        path: str = "",
        client_ip: str = "",
    ) -> bool:
        """Ship a security event to the configured telemetry collector."""
        if not self.url or self.is_circuit_open():
            return False

        try:
            import httpx
        except ImportError:
            logger.debug("httpx not installed; telemetry shipping disabled.")
            return False

        body: dict[str, Any] = {
            "tipo_attacco": result.category.value,
            "payload_malevolo": payload_preview[:500],
            "risk_score": round(result.risk_score, 4),
            "category": result.category.value,
            "level": result.level,
            "matched_rule": result.matched_rule,
            "request_id": result.request_id,
            "path": path[:200],
            "client_ip": client_ip[:64],
            "blocked": result.blocked,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.url, json=body, headers=headers)
                if resp.status_code >= 400:
                    raise RuntimeError(f"Telemetry endpoint returned HTTP {resp.status_code}")
            self._consecutive_failures = 0
            return True
        except Exception as exc:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold:
                self._circuit_open_until = time.monotonic() + self.cooldown_seconds
                logger.warning(
                    "Telemetry circuit breaker opened for %.0fs (key=%s): %s",
                    self.cooldown_seconds,
                    _mask_key(self.api_key),
                    exc,
                )
            else:
                logger.debug("Telemetry delivery failed (%s): %s", _mask_key(self.api_key), exc)
            return False
