"""Unit tests for Scudo WAF input normalization and JSON extraction."""

from __future__ import annotations

import unittest

from scudo_waf.normalizer import extract_values_from_json, normalize_for_regex, normalize_text


class TestNormalizer(unittest.TestCase):
    def test_single_and_double_url_decoding(self) -> None:
        encoded = "%2527%20OR%201%253D1%20--"
        self.assertEqual(normalize_text(encoded), "' OR 1=1 --")

    def test_html_entity_unescaping(self) -> None:
        raw = "&lt;script&gt;alert(1)&lt;/script&gt;"
        self.assertEqual(normalize_text(raw), "<script>alert(1)</script>")

    def test_null_byte_stripping_and_nfkc(self) -> None:
        fullwidth = "\uff1cscript\uff1ealert(1)\x00\uff1c/script\uff1e"
        self.assertEqual(normalize_text(fullwidth), "<script>alert(1)</script>")

    def test_sql_comment_stripping_for_regex(self) -> None:
        obfuscated = "UN/**/ION SEL/*bypass*/ECT username FROM users"
        self.assertEqual(normalize_for_regex(obfuscated), "UNION SELECT username FROM users")

    def test_max_length_truncation(self) -> None:
        long_str = "A" * 500
        self.assertEqual(len(normalize_text(long_str, max_length=120)), 120)

    def test_extract_values_from_json(self) -> None:
        raw = '{"user": {"name": "O\'Brien", "tags": ["vip", "eu"]}, "qty": 2}'
        values = extract_values_from_json(raw)
        self.assertIsNotNone(values)
        assert values is not None
        self.assertIn("O'Brien", values)
        self.assertIn("vip", values)
        self.assertIn("2", values)

    def test_extract_values_non_json_returns_none(self) -> None:
        self.assertIsNone(extract_values_from_json("plain text payload"))
        self.assertIsNone(extract_values_from_json("{not valid json"))


if __name__ == "__main__":
    unittest.main()
