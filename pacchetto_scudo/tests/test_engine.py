"""Unit tests for ScudoEngine 3-level detection, rate limiting, monitor mode, and fallback."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scudo_waf import ThreatCategory, WafConfig, WafMode, analyze
from scudo_waf.engine import ScudoEngine


class TestScudoEngine(unittest.TestCase):
    def test_three_level_flow_and_cache_hit(self) -> None:
        engine = ScudoEngine(WafConfig(rate_limit_per_minute=None))
        self.assertTrue(engine.ml_loaded)

        # Level 1 Regex hit
        r1 = engine.inspect("' OR 1=1 --")
        self.assertTrue(r1.blocked)
        self.assertEqual(r1.level, "L1-Regex")
        self.assertEqual(r1.category, ThreatCategory.SQLI)

        # Level 3 ML first evaluation on benign -> then Level 2 Cache hit
        benign = "Looking for comfortable blue running shoes size 42"
        r2 = engine.inspect(benign)
        self.assertFalse(r2.blocked)
        self.assertEqual(r2.level, "L3-ML")

        r3 = engine.inspect(benign)
        self.assertFalse(r3.blocked)
        self.assertEqual(r3.level, "L2-Cache")

        # Repeated non-regex ML anomaly should cache as malicious too (use regex_only=False)
        stats = engine.stats()
        self.assertGreaterEqual(stats["total_inspected"], 3)
        self.assertEqual(stats["total_blocked"], 1)

        engine.clear_cache()
        self.assertEqual(engine.stats()["cache_size"], 0)

    def test_monitor_mode_allows_but_flags_threat(self) -> None:
        engine = ScudoEngine(WafConfig(mode=WafMode.MONITOR))
        res = engine.inspect("<script>alert(1)</script>")
        self.assertTrue(res.is_malicious)
        self.assertFalse(res.blocked)
        self.assertEqual(res.mode, WafMode.MONITOR)

    def test_rate_limiting_and_allowlist(self) -> None:
        engine = ScudoEngine(
            WafConfig(
                rate_limit_per_minute=3,
                allowlist_ips=frozenset({"10.0.0.1"}),
            )
        )
        self.assertTrue(engine.check_rate_limit("192.0.2.10"))
        self.assertTrue(engine.check_rate_limit("192.0.2.10"))
        self.assertTrue(engine.check_rate_limit("192.0.2.10"))
        self.assertFalse(engine.check_rate_limit("192.0.2.10"))

        # Allowlisted IP is never throttled
        for _ in range(10):
            self.assertTrue(engine.check_rate_limit("10.0.0.1"))

    def test_graceful_regex_only_fallback_when_models_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ScudoEngine(WafConfig(model_dir=Path(tmpdir)))
            self.assertFalse(engine.ml_loaded)
            atk = engine.inspect("../../../etc/passwd")
            self.assertTrue(atk.blocked)
            self.assertEqual(atk.level, "L1-Regex")
            safe = engine.inspect("Normal request without ML model")
            self.assertFalse(safe.blocked)

    def test_standalone_analyze_helper(self) -> None:
        res_atk = analyze("UNION ALL SELECT username, password FROM users")
        self.assertTrue(res_atk["blocked"])
        self.assertEqual(res_atk["category"], "sqli")

        res_safe = analyze("Via Garibaldi 101, Firenze")
        self.assertFalse(res_safe["blocked"])
        self.assertEqual(res_safe["category"], "none")


if __name__ == "__main__":
    unittest.main()
