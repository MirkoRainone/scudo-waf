# 🛡️ Scudo WAF — AI-Powered Hybrid Web Application & LLM Firewall

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776ab.svg)](https://www.python.org/)
[![Version 1.0.0](https://img.shields.io/badge/version-1.0.0-10b981.svg)](https://pypi.org/project/scudo-waf/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Typing: PEP 561](https://img.shields.io/badge/typing-PEP%20561-blueviolet.svg)](https://peps.python.org/pep-0561/)

**Scudo WAF** (`scudo-waf`) is an **in-memory Hybrid Web Application Firewall**, **LLM Prompt Injection & PII/Secret Guard**, and **Universal Reverse-Proxy Sidecar**. Run sub-millisecond protection inside your Python process (**FastAPI**, **Starlette**, **Flask**, **Django**) or place the `scudo-waf proxy` sidecar in front of any Node.js, Go, PHP, or Java service.

---

## ✨ Key Features (v1.0.0)

- **Multi-Layer Hybrid Engine**:
  - **L0 Blocklist & Rate Limiter**: Explicit per-IP blocklists/allowlists (`403`) and sliding-window per-IP rate limiting (`429 Too Many Requests`).
  - **L1 Structural De-obfuscation & Regex Shield**: Iterative URL/HTML/NFKC normalization, MySQL conditional comment unwrapping (`/*!50000...*/`), smart SQL block comment stripping, inline `0x...` hex & Base64 decoding, covering SQLi, XSS/SSTI, Path Traversal, Command Injection, SSRF, and multilingual Prompt Injection.
  - **L2 Smart TTL Cache**: SHA-256 keyed in-memory decision cache (`~0.05 ms`).
  - **L3 ML Neural Engine**: Dual char/word TF-IDF `FeatureUnion` + `CalibratedLinearSVC` trained on **53,100 strictly unique samples** with calibrated threshold `0.75`.
- **LLM PromptGuard + PII & Secret Redactor**: `@guard.protect` blocks prompt injections, oversized inputs, and exposed secrets (`sk-...`, AWS `AKIA...`, GitHub `ghp_...`, JWTs) while automatically masking emails, Luhn-valid credit cards, IBANs, Italian Codice Fiscale, and phone numbers.
- **Universal Reverse-Proxy Sidecar & CLI**: Official `scudo-waf` CLI (`scan`, `stats`, `proxy`) to inspect payloads or protect any HTTP upstream app without touching application source code.

---

## 🚀 Quick Start

```bash
pip install scudo-waf
# Or include universal reverse-proxy & CLI server support:
pip install "scudo-waf[proxy]"
```

### FastAPI / Starlette

```python
from fastapi import FastAPI
from scudo_waf import WafMiddleware

app = FastAPI()
app.add_middleware(WafMiddleware, expose_headers=True)
```

### LLM PromptGuard with PII Redaction & Secret Leak Blocking

```python
from scudo_waf import PromptGuard, PromptInjectionError

guard = PromptGuard(redact_pii=True, block_secrets=True, max_prompt_chars=4000)

@guard.protect
def ask_llm(prompt: str) -> str:
    # Sensitive emails / credit cards / IBANs are masked to [REDACTED_*] automatically!
    return call_my_model(prompt)
```

### Universal Reverse-Proxy Sidecar & CLI

```bash
scudo-waf scan "' OR 1=1 --" --json
scudo-waf proxy --upstream http://127.0.0.1:3000 --port 8081 --mode block
```

---

## 📊 Verified Holdout Evaluation & Benchmarks (`v1.0.0`)

| Metric | Measured Result |
|--------|-----------------|
| Training Corpus | `53,100` strictly unique samples (`30,000` benign / `23,100` malicious) |
| Selected Model | `CalibratedLinearSVC` (threshold `0.75`) |
| Holdout Accuracy / F1 / ROC-AUC | `1.0000` (`TN=6000, FP=0, FN=0, TP=4620` across `10,620` unseen samples) |
| Hard-Negative Smoke Checks | `24 / 24` Benign Passed (`0` FP) · `12 / 12` Attacks Blocked |
| **L1-Regex / L2-Cache / L3-ML p50** | `0.014 ms` / `0.054 ms` / `4.04 ms` |
| **ASGI Middleware Throughput** | `1,180.7 req/s` (1,000 mixed HTTP requests in `0.85 s`) |

---

## 📄 License

MIT License — Copyright (c) 2026 Mirko Rainone (KShield).
