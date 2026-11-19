"""Critical false-positive regression gate across realistic benign HTTP traffic."""

from __future__ import annotations

import unittest

import httpx
from fastapi import FastAPI, Request

from scudo_waf import ScudoEngine, WafConfig, WafMiddleware

BENIGN_TRAFFIC_CORPUS: list[str] = [
    "Hello world, how are you?",
    "O'Brien & Sons, 123 Main St",
    "Please select a size and order now",
    "Via Roma 123/A, Milano",
    "mario.rossi@azienda.it",
    "cerco zaino rosso taglia S",
    "compra scarpe running nero taglia 42 in offerta",
    "Update your shipping address from the account menu",
    "Create a table reservation for 4 guests at 20:00",
    "Drop by our store near Baker Street tomorrow",
    "Where can I find the union jacket in size L?",
    "Check our script for the school theater play",
    "I want to delete my draft comment from the blog post",
    "Explain how SQL inner joins work in Python",
    "Summarize this quarterly financial PDF in 5 bullet points",
    "Good morning team! Let us review PR #412 before 16:00.",
    "D'Angelo & Partners — Invoice 2026-0041/B",
    "L'Aquila, Corso Federico II 84",
    "1 + 1 = 2 and price < 50 and rating > 4",
    "Order SKU-9941/XL placed on 2026-11-19 (qty=2)",
    "How do I center a div using CSS flexbox in React?",
    "Translate this paragraph about renewable energy into Italian",
    "Buongiorno, vorrei modificare l'ordine 44819 spedito a Torino.",
    "Anne-Marie O'Connor <am.oconnor@company.io>",
    "https://www.example.com/products/4812?ref=newsletter&sort=price_asc",
    "1",
    "42",
    "Mario",
    "ok1",
    "true",
    "active",
]


class TestZeroFalsePositives(unittest.IsolatedAsyncioTestCase):
    def test_engine_zero_false_positives(self) -> None:
        engine = ScudoEngine(WafConfig(rate_limit_per_minute=None))
        for text in BENIGN_TRAFFIC_CORPUS:
            with self.subTest(text=text):
                res = engine.inspect(text)
                self.assertFalse(
                    res.blocked,
                    f"False positive on benign text {text!r}: {res.to_dict()}",
                )

    async def test_middleware_zero_false_positives_with_browser_headers(self) -> None:
        app = FastAPI()
        app.add_middleware(WafMiddleware, rate_limit_per_minute=None)

        @app.post("/submit")
        async def submit(request: Request) -> dict[str, object]:
            return {"ok": True, "data": await request.json()}

        @app.get("/search")
        async def search(q: str = "") -> dict[str, str]:
            return {"q": q}

        chrome_ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            for idx, text in enumerate(BENIGN_TRAFFIC_CORPUS):
                with self.subTest(idx=idx, text=text):
                    r_get = await client.get(
                        "/search",
                        params={"q": text},
                        headers={"User-Agent": chrome_ua},
                    )
                    self.assertEqual(r_get.status_code, 200, f"GET FP on {text!r}: {r_get.text}")

                    r_post = await client.post(
                        "/submit",
                        json={"name": "O'Brien", "message": text, "plan": "pro"},
                        headers={"User-Agent": chrome_ua},
                    )
                    self.assertEqual(r_post.status_code, 200, f"POST JSON FP on {text!r}: {r_post.text}")


if __name__ == "__main__":
    unittest.main()
