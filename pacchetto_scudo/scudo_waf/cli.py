"""Official CLI for Scudo WAF (scan, stats, and reverse-proxy sidecar)."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from .config import WafConfig, WafMode
from .engine import ScudoEngine
from .pii import redact_sensitive_data
from .proxy import create_proxy_app


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scudo-waf",
        description="Scudo WAF v1.0.0 — Hybrid Web Application & LLM Firewall CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan subcommand
    p_scan = sub.add_parser("scan", help="Inspect a payload or LLM prompt via L1/L2/L3 engine.")
    p_scan.add_argument("payload", help="Text payload or prompt to inspect.")
    p_scan.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output.")
    p_scan.add_argument("--redact-pii", action="store_true", help="Scan and redact PII/secrets preview.")
    p_scan.add_argument(
        "--exit-code",
        action="store_true",
        help="Return exit code 2 when payload is blocked.",
    )

    # stats subcommand
    sub.add_parser("stats", help="Display loaded ML model metadata and engine configuration.")

    # proxy subcommand
    p_proxy = sub.add_parser("proxy", help="Run universal WAF reverse-proxy sidecar in front of any HTTP service.")
    p_proxy.add_argument("--upstream", required=True, help="Target upstream base URL (e.g. http://127.0.0.1:3000).")
    p_proxy.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0).")
    p_proxy.add_argument("--port", type=int, default=8081, help="Bind port (default: 8081).")
    p_proxy.add_argument("--mode", choices=["block", "monitor"], default="block", help="WAF mode.")
    p_proxy.add_argument("--api-key", default="sk_test_default", help="Scudo API key.")
    p_proxy.add_argument("--rate-limit", type=int, default=120, help="Requests/minute per IP (0 to disable).")

    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    engine = ScudoEngine(WafConfig(rate_limit_per_minute=None))
    res = engine.inspect(args.payload)
    out: dict[str, Any] = res.to_dict()

    if args.redact_pii:
        red = redact_sensitive_data(args.payload, redact_pii=True, redact_secrets=True)
        out["redaction"] = red.to_dict()

    if args.as_json:
        print(json.dumps(out, indent=2))
    else:
        verdict = "BLOCKED" if res.blocked else "ALLOWED"
        print(f"[{verdict}] category={res.category.value} level={res.level} score={res.risk_score:.4f} latency={res.latency_ms:.3f}ms")
        if res.matched_rule:
            print(f"  matched_rule: {res.matched_rule}")
        if args.redact_pii and "redaction" in out:
            print(f"  redacted_text: {out['redaction']['redacted_text']}")

    if args.exit_code and res.blocked:
        return 2
    return 0


def _cmd_stats() -> int:
    engine = ScudoEngine(WafConfig(rate_limit_per_minute=None))
    meta = engine.model_metadata
    summary = {
        "version": "1.0.0",
        "ml_loaded": engine.ml_loaded,
        "ml_threshold": engine.ml_threshold,
        "model_name": meta.get("model_name", "unknown"),
        "calibrated_threshold": meta.get("calibrated_threshold", engine.ml_threshold),
        "unique_samples": meta.get("unique_samples"),
        "test_metrics": meta.get("test_metrics"),
    }
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print(
            "Error: 'uvicorn' is required for `scudo-waf proxy`. Install with: pip install 'scudo-waf[proxy]'",
            file=sys.stderr,
        )
        return 1

    rate_limit = None if args.rate_limit <= 0 else args.rate_limit
    cfg = WafConfig(
        api_key=args.api_key,
        mode=WafMode(args.mode),
        rate_limit_per_minute=rate_limit,
        expose_headers=True,
    )
    proxy_app = create_proxy_app(args.upstream, config=cfg)
    uvicorn.run(proxy_app, host=args.host, port=args.port)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for ``scudo-waf``."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "stats":
        return _cmd_stats()
    if args.command == "proxy":
        return _cmd_proxy(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
