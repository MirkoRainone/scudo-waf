"""Core 3-level hybrid inspection engine (L0 RateLimit -> L1 Regex -> L2 Cache -> L3 ML)."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from collections import Counter, deque
from pathlib import Path
from typing import Any

import joblib
from cachetools import TTLCache

from .config import InspectionResult, ThreatCategory, WafConfig, WafMode
from .normalizer import normalize_for_regex, normalize_text
from .patterns import match_patterns

logger = logging.getLogger("scudo_waf")

_DEFAULT_MODELS_DIR = Path(__file__).resolve().parent / "models"
_MODEL_CACHE_LOCK = threading.Lock()
_MODEL_ARTIFACT_CACHE: dict[Path, tuple[Any, Any, dict[str, Any]]] = {}


class ScudoEngine:
    """Thread-safe in-memory 3-level WAF detection engine."""

    def __init__(self, config: WafConfig | None = None) -> None:
        self.config = config or WafConfig()
        self._cache_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._stats_lock = threading.Lock()

        self._cache: TTLCache[str, tuple[bool, ThreatCategory, str | None, float]] = TTLCache(
            maxsize=self.config.cache_maxsize,
            ttl=self.config.cache_ttl,
        )
        self._rate_buckets: TTLCache[str, deque[float]] = TTLCache(maxsize=20_000, ttl=60)

        self._vectorizer: Any = None
        self._model: Any = None
        self.model_metadata: dict[str, Any] = {}
        self._model_dir = Path(self.config.model_dir) if self.config.model_dir else _DEFAULT_MODELS_DIR
        self._load_models()

        meta_threshold = self.model_metadata.get("calibrated_threshold")
        if self.config.ml_threshold is not None:
            self.ml_threshold = float(self.config.ml_threshold)
        elif isinstance(meta_threshold, (int, float)):
            self.ml_threshold = float(meta_threshold)
        else:
            self.ml_threshold = 0.72

        self._total_inspected = 0
        self._total_blocked = 0
        self._total_threats = 0
        self._total_latency_ms = 0.0
        self._by_category: Counter[str] = Counter()
        self._by_level: Counter[str] = Counter()

    def _load_models(self) -> None:
        cache_key = self._model_dir.resolve()
        with _MODEL_CACHE_LOCK:
            cached = _MODEL_ARTIFACT_CACHE.get(cache_key)
            if cached is not None:
                self._vectorizer, self._model, cached_meta = cached
                self.model_metadata = dict(cached_meta)
                return

        vec_path = self._model_dir / "traduttore_waf.pkl"
        clf_path = self._model_dir / "cervello_waf.pkl"
        meta_path = self._model_dir / "model_metadata.json"

        loaded_meta: dict[str, Any] = {}
        if meta_path.exists():
            try:
                loaded_meta = json.loads(meta_path.read_text(encoding="utf-8"))
                self.model_metadata = dict(loaded_meta)
            except Exception as exc:
                logger.warning("Could not parse model_metadata.json (%s): %s", meta_path, exc)

        if not (vec_path.exists() and clf_path.exists()):
            logger.warning(
                "ML model artifacts not found in %s; running in L1-Regex-only mode.",
                self._model_dir,
            )
            return

        with _MODEL_CACHE_LOCK:
            cached = _MODEL_ARTIFACT_CACHE.get(cache_key)
            if cached is not None:
                self._vectorizer, self._model, cached_meta = cached
                self.model_metadata = dict(cached_meta)
                return
            try:
                vec = joblib.load(vec_path)
                clf = joblib.load(clf_path)
                self._vectorizer = vec
                self._model = clf
                _MODEL_ARTIFACT_CACHE[cache_key] = (vec, clf, dict(loaded_meta))
                logger.info("Loaded Scudo ML engine from %s", self._model_dir)
            except Exception as exc:
                self._vectorizer = None
                self._model = None
                logger.warning("Failed to load ML models (%s); running in L1-Regex-only mode.", exc)

    @property
    def ml_loaded(self) -> bool:
        """Whether the Level-3 scikit-learn vectorizer and classifier are loaded."""
        return self._vectorizer is not None and self._model is not None

    def is_ip_blocked(self, client_ip: str) -> bool:
        """Return ``True`` if ``client_ip`` is explicitly listed in ``blocklist_ips``."""
        if not client_ip or client_ip in self.config.allowlist_ips:
            return False
        return client_ip in self.config.blocklist_ips

    def check_rate_limit(self, client_ip: str) -> bool:
        """Return ``True`` if ``client_ip`` is within its 60s request budget."""
        limit = self.config.rate_limit_per_minute
        if limit is None or limit <= 0:
            return True
        if client_ip in self.config.allowlist_ips:
            return True

        now = time.monotonic()
        with self._rate_lock:
            bucket = self._rate_buckets.get(client_ip)
            if bucket is None:
                bucket = deque()
                self._rate_buckets[client_ip] = bucket
            while bucket and (now - bucket[0]) >= 60.0:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

    def _predict_ml_score(self, text: str) -> float:
        vec = self._vectorizer.transform([text])
        if hasattr(self._model, "predict_proba"):
            return float(self._model.predict_proba(vec)[0][1])
        if hasattr(self._model, "decision_function"):
            score = float(self._model.decision_function(vec)[0])
            # Logistic sigmoid fallback for non-probabilistic linear models
            import math

            return 1.0 / (1.0 + math.exp(-max(min(score, 50.0), -50.0)))
        pred = self._model.predict(vec)[0]
        return 1.0 if bool(pred) else 0.0

    def _record_stats(self, result: InspectionResult) -> None:
        with self._stats_lock:
            self._total_inspected += 1
            self._total_latency_ms += result.latency_ms
            self._by_level[result.level] += 1
            if result.is_malicious:
                self._total_threats += 1
                self._by_category[result.category.value] += 1
            if result.blocked:
                self._total_blocked += 1

    def _build_result(
        self,
        *,
        is_malicious: bool,
        category: ThreatCategory,
        level: str,
        risk_score: float,
        matched_rule: str | None,
        start_time: float,
        request_id: str,
    ) -> InspectionResult:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        blocked = is_malicious and self.config.mode == WafMode.BLOCK
        result = InspectionResult(
            blocked=blocked,
            is_malicious=is_malicious,
            category=category,
            level=level,
            risk_score=risk_score,
            latency_ms=latency_ms,
            matched_rule=matched_rule,
            request_id=request_id,
            mode=self.config.mode,
        )
        self._record_stats(result)
        return result

    def inspect(
        self,
        text: str,
        *,
        regex_only: bool = False,
        include_prompt_injection: bool | None = None,
    ) -> InspectionResult:
        """Inspect a string payload through L1 Regex -> L2 Cache -> L3 ML."""
        start_time = time.perf_counter()
        request_id = uuid.uuid4().hex[:12]

        use_pi = (
            self.config.inspect_prompt_injection
            if include_prompt_injection is None
            else include_prompt_injection
        )

        normalized = normalize_text(text, max_length=self.config.max_input_length)
        if not normalized:
            return self._build_result(
                is_malicious=False,
                category=ThreatCategory.NONE,
                level="none",
                risk_score=0.0,
                matched_rule=None,
                start_time=start_time,
                request_id=request_id,
            )

        # Level 1: Regex signature shield
        regex_candidate = normalize_for_regex(text, max_length=self.config.max_input_length)
        l1_match = match_patterns(regex_candidate, include_prompt_injection=use_pi)
        if l1_match is not None:
            cat, rule_name = l1_match
            return self._build_result(
                is_malicious=True,
                category=cat,
                level="L1-Regex",
                risk_score=1.0,
                matched_rule=rule_name,
                start_time=start_time,
                request_id=request_id,
            )

        if regex_only:
            return self._build_result(
                is_malicious=False,
                category=ThreatCategory.NONE,
                level="L1-Regex",
                risk_score=0.0,
                matched_rule=None,
                start_time=start_time,
                request_id=request_id,
            )

        # Pure short alphanumeric tokens (e.g. "1", "42", "ok1") cannot form injection syntax
        if len(normalized) <= 4 and normalized.isalnum():
            return self._build_result(
                is_malicious=False,
                category=ThreatCategory.NONE,
                level="L1-Regex",
                risk_score=0.0,
                matched_rule=None,
                start_time=start_time,
                request_id=request_id,
            )

        # Level 2: Smart TTL Cache (keyed by digest of normalized payload)
        cache_key = hashlib.sha256(f"{int(use_pi)}:{normalized}".encode("utf-8", errors="ignore")).hexdigest()
        with self._cache_lock:
            cached = self._cache.get(cache_key)
        if cached is not None:
            is_mal, cat, rule_name, score = cached
            return self._build_result(
                is_malicious=is_mal,
                category=cat,
                level="L2-Cache",
                risk_score=score,
                matched_rule=rule_name,
                start_time=start_time,
                request_id=request_id,
            )

        # Level 3: Local ML Neural Engine
        if self.ml_loaded:
            try:
                prob = self._predict_ml_score(normalized)
                is_mal = prob >= self.ml_threshold
                cat = ThreatCategory.ML_ANOMALY if is_mal else ThreatCategory.NONE
                rule_name = "ml_classifier" if is_mal else None
                with self._cache_lock:
                    self._cache[cache_key] = (is_mal, cat, rule_name, prob)
                return self._build_result(
                    is_malicious=is_mal,
                    category=cat,
                    level="L3-ML",
                    risk_score=prob,
                    matched_rule=rule_name,
                    start_time=start_time,
                    request_id=request_id,
                )
            except Exception as exc:
                logger.warning("Level-3 ML inference error (fail_open=%s): %s", self.config.fail_open, exc)
                if not self.config.fail_open:
                    return self._build_result(
                        is_malicious=True,
                        category=ThreatCategory.ML_ANOMALY,
                        level="L3-Error",
                        risk_score=1.0,
                        matched_rule="fail_closed",
                        start_time=start_time,
                        request_id=request_id,
                    )

        return self._build_result(
            is_malicious=False,
            category=ThreatCategory.NONE,
            level="L1-Regex",
            risk_score=0.0,
            matched_rule=None,
            start_time=start_time,
            request_id=request_id,
        )

    def inspect_prompt(self, prompt: str) -> InspectionResult:
        """Inspect an LLM user prompt for prompt-injection / jailbreak patterns."""
        return self.inspect(prompt, regex_only=False, include_prompt_injection=True)

    def clear_cache(self) -> None:
        """Clear the Level-2 decision cache."""
        with self._cache_lock:
            self._cache.clear()

    def stats(self) -> dict[str, Any]:
        """Return runtime inspection counters and latency metrics."""
        with self._cache_lock:
            cache_size = len(self._cache)
        with self._stats_lock:
            avg_ms = (
                self._total_latency_ms / self._total_inspected
                if self._total_inspected > 0
                else 0.0
            )
            return {
                "total_inspected": self._total_inspected,
                "total_blocked": self._total_blocked,
                "total_threats": self._total_threats,
                "avg_latency_ms": round(avg_ms, 4),
                "by_category": dict(self._by_category),
                "by_level": dict(self._by_level),
                "cache_size": cache_size,
                "ml_loaded": self.ml_loaded,
                "ml_threshold": self.ml_threshold,
                "mode": self.config.mode.value,
            }


_default_engine_lock = threading.Lock()
_default_engine: ScudoEngine | None = None


def get_default_engine() -> ScudoEngine:
    """Return a lazily-initialized process-wide :class:`ScudoEngine`."""
    global _default_engine
    if _default_engine is None:
        with _default_engine_lock:
            if _default_engine is None:
                _default_engine = ScudoEngine()
    return _default_engine


def analyze(text: str) -> dict[str, Any]:
    """Analyze a single string payload using the default engine and return a dict."""
    return get_default_engine().inspect(text).to_dict()
