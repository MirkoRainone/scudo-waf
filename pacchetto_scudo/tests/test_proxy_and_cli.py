"""Unit tests for the Scudo Universal Reverse-Proxy Sidecar and CLI."""

from __future__ import annotations

import contextlib
import io
import json
import unittest

import httpx

from scudo_waf import WafConfig, WafMode, create_proxy_app
from scudo_waf.cli import main as cli_main


class TestProxyAndCli(unittest.IsolatedAsyncioTestCase):
    async def test_reverse_proxy_forwards_clean_and_blocks_attacks(self) -> None:
        seen_requests: list[tuple[str, str, str]] = []

        def upstream_handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append((request.method, request.url.path, request.content.decode("utf-8", errors="ignore")))
            return httpx.Response(
                200,
                json={"upstream": "ok", "path": request.url.path},
                headers={"X-Upstream-App": "node-express"},
            )

        mock_transport = httpx.MockTransport(upstream_handler)
        proxy_app = create_proxy_app(
            "http://upstream.internal:3000",
            config=WafConfig(mode=WafMode.BLOCK, rate_limit_per_minute=None),
            transport=mock_transport,
        )

        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://proxyserver") as client:
            # 1. Proxy internal health & stats endpoints
            r_health = await client.get("/_scudo/health")
            self.assertEqual(r_health.status_code, 200)
            self.assertEqual(r_health.json()["service"], "scudo-reverse-proxy")

            r_stats = await client.get("/_scudo/stats")
            self.assertEqual(r_stats.status_code, 200)
            self.assertTrue(r_stats.json()["ml_loaded"])

            # 2. Benign request forwarded to upstream
            r_ok = await client.post("/api/orders", json={"item": "running shoes", "qty": 2})
            self.assertEqual(r_ok.status_code, 200)
            self.assertEqual(r_ok.headers.get("X-Scudo-Proxy"), "v1.0.0")
            self.assertEqual(r_ok.headers.get("X-Scudo-Status"), "allowed")
            self.assertEqual(r_ok.headers.get("X-Upstream-App"), "node-express")
            self.assertEqual(r_ok.json()["path"], "/api/orders")
            self.assertEqual(len(seen_requests), 1)

            # 3. Malicious request blocked BEFORE hitting upstream
            r_blk = await client.get(
                "/api/orders",
                params={"q": "' OR 1=1 --"},
                headers={"Accept": "application/json"},
            )
            self.assertEqual(r_blk.status_code, 403)
            self.assertEqual(r_blk.json()["category"], "sqli")
            # Confirm upstream never received the SQLi request
            self.assertEqual(len(seen_requests), 1)

    def test_cli_scan_and_stats(self) -> None:
        # 1. Clean payload
        buf_ok = io.StringIO()
        with contextlib.redirect_stdout(buf_ok):
            rc_ok = cli_main(["scan", "O'Brien & Sons, 123 Main St", "--json"])
        self.assertEqual(rc_ok, 0)
        parsed_ok = json.loads(buf_ok.getvalue())
        self.assertFalse(parsed_ok["blocked"])

        # 2. Malicious payload with --exit-code and --redact-pii
        buf_atk = io.StringIO()
        with contextlib.redirect_stdout(buf_atk):
            rc_atk = cli_main([
                "scan",
                "' OR 1=1 -- mario@azienda.it",
                "--json",
                "--redact-pii",
                "--exit-code",
            ])
        self.assertEqual(rc_atk, 2)
        parsed_atk = json.loads(buf_atk.getvalue())
        self.assertTrue(parsed_atk["blocked"])
        self.assertEqual(parsed_atk["category"], "sqli")
        self.assertIn("[REDACTED_EMAIL]", parsed_atk["redaction"]["redacted_text"])

        # 3. stats subcommand
        buf_stats = io.StringIO()
        with contextlib.redirect_stdout(buf_stats):
            rc_stats = cli_main(["stats"])
        self.assertEqual(rc_stats, 0)
        stats_data = json.loads(buf_stats.getvalue())
        self.assertTrue(stats_data["ml_loaded"])
        self.assertGreaterEqual(stats_data["unique_samples"], 50_000)


if __name__ == "__main__":
    unittest.main()
