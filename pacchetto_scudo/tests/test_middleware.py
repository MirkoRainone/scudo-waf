"""Full ASGI integration tests for WafMiddleware."""

from __future__ import annotations

import unittest
from typing import Any

import httpx
from fastapi import FastAPI, Request

from scudo_waf import WafMiddleware, WafMode


def _build_app(**middleware_kwargs: Any) -> FastAPI:
    app = FastAPI()
    app.add_middleware(WafMiddleware, **middleware_kwargs)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/search")
    async def search(q: str = "") -> dict[str, str]:
        return {"q": q}

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, Any]:
        payload = await request.json()
        return {"received": payload}

    @app.post("/form")
    async def form_echo(request: Request) -> dict[str, str]:
        body = (await request.body()).decode("utf-8")
        return {"raw": body}

    return app


class TestWafMiddleware(unittest.IsolatedAsyncioTestCase):
    async def test_clean_requests_and_body_replay(self) -> None:
        app = _build_app(expose_headers=True, rate_limit_per_minute=None)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            r_get = await client.get("/search", params={"q": "blue running shoes"})
            self.assertEqual(r_get.status_code, 200)
            self.assertEqual(r_get.json(), {"q": "blue running shoes"})
            self.assertEqual(r_get.headers.get("X-Scudo-Status"), "allowed")
            self.assertIn("X-Scudo-Latency-Ms", r_get.headers)
            self.assertIn("X-Scudo-Request-Id", r_get.headers)

            # Verify JSON body is fully preserved for downstream route
            r_post = await client.post("/echo", json={"email": "mario@example.com", "plan": "pro"})
            self.assertEqual(r_post.status_code, 200)
            self.assertEqual(r_post.json(), {"received": {"email": "mario@example.com", "plan": "pro"}})

    async def test_blocks_attacks_across_vectors_and_content_negotiation(self) -> None:
        app = _build_app(rate_limit_per_minute=None)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Query param SQLi -> HTML response for browser-like Accept
            r1 = await client.get(
                "/search",
                params={"q": "' OR 1=1 --"},
                headers={"Accept": "text/html"},
            )
            self.assertEqual(r1.status_code, 403)
            self.assertIn("text/html", r1.headers.get("content-type", ""))
            self.assertIn("Scudo WAF", r1.text)

            # JSON body XSS -> JSON 403 response
            r2 = await client.post(
                "/echo",
                json={"name": "Mario", "comment": "<script>alert(document.cookie)</script>"},
            )
            self.assertEqual(r2.status_code, 403)
            data = r2.json()
            self.assertEqual(data["category"], "xss")

            # Form body Path Traversal
            r3 = await client.post(
                "/form",
                data={"file": "../../../../etc/passwd"},
                headers={"Accept": "application/json"},
            )
            self.assertEqual(r3.status_code, 403)
            self.assertEqual(r3.json()["category"], "path_traversal")

            # Malicious User-Agent header
            r4 = await client.get(
                "/search",
                params={"q": "shoes"},
                headers={"User-Agent": "<script>alert(1)</script>", "Accept": "application/json"},
            )
            self.assertEqual(r4.status_code, 403)

    async def test_monitor_mode_and_on_block_hook(self) -> None:
        events: list[dict[str, Any]] = []

        def on_block(res: Any, ctx: dict[str, Any]) -> None:
            events.append({"category": res.category.value, "path": ctx["path"], "blocked": res.blocked})

        app = _build_app(mode=WafMode.MONITOR, on_block=on_block, expose_headers=True, rate_limit_per_minute=None)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/search", params={"q": "1; DROP TABLE users; --"})
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.headers.get("X-Scudo-Status"), "monitored")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["category"], "sqli")
        self.assertFalse(events[0]["blocked"])

    async def test_excluded_paths_and_rate_limiting(self) -> None:
        app = _build_app(rate_limit_per_minute=2, exclude_paths=("/health",))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Excluded path bypasses WAF & rate limit
            for _ in range(5):
                r_h = await client.get("/health", params={"q": "' OR 1=1 --"})
                self.assertEqual(r_h.status_code, 200)

            # Normal path hits 429 on 3rd request
            self.assertEqual((await client.get("/search", params={"q": "ok1"})).status_code, 200)
            self.assertEqual((await client.get("/search", params={"q": "ok2"})).status_code, 200)
            r_limited = await client.get(
                "/search",
                params={"q": "ok3"},
                headers={"Accept": "application/json"},
            )
            self.assertEqual(r_limited.status_code, 429)
            self.assertEqual(r_limited.headers.get("Retry-After"), "60")

    def test_validate_key_callback(self) -> None:
        with self.assertRaises(ValueError):
            WafMiddleware(FastAPI(), api_key="bad_key", validate_key=lambda k: k.startswith("sk_live_"))

        with self.assertRaises(ValueError):
            _build_app(api_key="bad_key", validate_key=lambda k: k.startswith("sk_live_")).build_middleware_stack()

        app_ok = _build_app(api_key="sk_live_abc", validate_key=lambda k: k.startswith("sk_live_"))
        app_ok.build_middleware_stack()
        self.assertIsNotNone(app_ok)

    async def test_direct_ip_blocklist_and_allowlist_kwargs(self) -> None:
        events: list[dict[str, Any]] = []

        def on_block(res: Any, ctx: dict[str, Any]) -> None:
            events.append({"category": res.category.value, "client_ip": ctx["client_ip"], "blocked": res.blocked})

        app = _build_app(
            blocklist_ips=frozenset({"203.0.113.99"}),
            allowlist_ips=frozenset({"10.0.0.5"}),
            on_block=on_block,
            rate_limit_per_minute=None,
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            r_blk = await client.get(
                "/search",
                params={"q": "shoes"},
                headers={"X-Forwarded-For": "203.0.113.99", "Accept": "application/json"},
            )
            self.assertEqual(r_blk.status_code, 403)
            self.assertEqual(r_blk.json()["category"], "ip_blocklist")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["client_ip"], "203.0.113.99")
            self.assertTrue(events[0]["blocked"])

            r_allow = await client.get(
                "/search",
                params={"q": "' OR 1=1 --"},
                headers={"X-Forwarded-For": "10.0.0.5"},
            )
            self.assertEqual(r_allow.status_code, 200)


if __name__ == "__main__":
    unittest.main()
