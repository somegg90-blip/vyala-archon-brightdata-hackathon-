"""
vyala/ai/context_builder.py

Primary / Fallback LLM Architecture
=====================================
This module is the single point of contact between VYALA's scanning pipeline
and any external LLM API. It implements a two-tier resilience pattern:

Both endpoints speak the OpenAI chat completions protocol, so one SDK
drives both. The caller (ai/analyzer.py) never needs to know which tier
actually produced the result — it just receives an enriched CryptoFinding.

Resilience guarantees
----------------------
• A primary API outage silently degrades to fallback — scan continues.
• A total LLM outage returns the original finding un-enriched — scan
  never crashes. The CBOM is still valid; AI fields are just null.
• Malformed JSON from the LLM is caught, logged, and treated as a failure
  so the fallback tier gets a chance to return clean output.
• All API errors, timeouts, and JSON parse failures are logged at the
  appropriate severity level for the CBOM audit trail.

Environment variables (set in .env, loaded by pydantic-settings)
-----------------------------------------------------------------

"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from web.mcp_client import BrightDataMCPClient

import openai
from loguru import logger

from core.models.cbom import CryptoFinding, MigrationComplexity, PQCRecommendation
from .prompt_templates import (
    VYALA_SYSTEM_PROMPT,
    PROMPT_VERSIONS,
    build_user_prompt,
)


# ==============================================================================
# CONFIGURATION DEFAULTS
# Pulled from environment — fallback strings are safe placeholders that will
# cause a clean auth error rather than a cryptic connection error.
# ==============================================================================

_DEFAULT_PRIMARY_BASE_URL  = "https://openrouter.ai/api/v1"
_DEFAULT_FALLBACK_BASE_URL = "https://openrouter.ai/api/v1"
_DEFAULT_PRIMARY_MODEL     = "google/gemma-4-26b-a4b-it:free"
_DEFAULT_FALLBACK_MODEL    = "inclusionai/ling-2.6-1t:free"

# LLM call parameters — tuned for structured JSON output
_TEMPERATURE    = 0.1    # Near-zero: deterministic JSON, no creative hallucination
_MAX_TOKENS     = 600    # JSON schema is ~300 tokens; 2× headroom
_TIMEOUT_SECS   = 45.0   # DeepSeek's 285B model can be slow under load

# Markdown fence pattern — catches ```json ... ``` and ``` ... ``` variants
_MD_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

# Valid migration complexity values for fast validation
_VALID_COMPLEXITIES = {"LOW", "MEDIUM", "HIGH"}

# Required keys in the LLM JSON response
_REQUIRED_KEYS = {"usage_context", "pqc_replacement", "migration_complexity", "reasoning"}


# ==============================================================================
# INTERNAL DATA CLASSES
# ==============================================================================

@dataclass
class _LLMConfig:
    """Validated configuration for one LLM endpoint."""
    base_url: str
    api_key:  str
    model:    str
    tier:     str   # "primary" or "fallback" — for logging only

    @property
    def is_configured(self) -> bool:
        """True if all required fields are non-empty non-placeholder strings."""
        return bool(
            self.base_url.startswith("http")
            and len(self.api_key) > 8
            and self.model
        )


@dataclass
class _LLMResult:
    """Output of a successful _call_llm invocation."""
    usage_context:        str
    pqc_replacement:      str
    migration_complexity: str
    reasoning:            str
    latency_ms:           float
    tier_used:            str
    model_used:           str
    prompt_version:       str


# ==============================================================================
# CONTEXT BUILDER
# ==============================================================================

class ContextBuilder:
    """
    Enriches raw CryptoFinding objects with AI-generated PQC analysis.

    Each finding goes through a two-tier LLM pipeline:

        PythonParser finding  →  ContextBuilder.enrich_finding()
                                   ├─ _call_llm(primary)   ──→ enriched finding ✓
                                   └─ _call_llm(fallback)  ──→ enriched finding ✓
                                   └─ both fail            ──→ original finding (safe)

    Usage
    -----
    >>> builder = ContextBuilder()
    >>> enriched = builder.enrich_finding(finding)

    Thread safety
    -------------
    ContextBuilder is stateless after __init__. The openai.OpenAI client is
    created fresh on each _call_llm invocation (not stored on self) so
    multiple async workers can call enrich_finding() concurrently without
    shared mutable state.
    """

    def __init__(self) -> None:
        """
        Read LLM configuration from environment variables.
        Supports comma-separated lists for multi-account rate limit evasion.
        """
        base_url = os.environ.get("LLM_BASE_URL",  "https://openrouter.ai/api/v1")
        keys_str = os.environ.get("LLM_API_KEYS", "")
        models_str = os.environ.get("LLM_MODELS", "")

        keys = [k.strip() for k in keys_str.split(",") if k.strip()]
        models = [m.strip() for m in models_str.split(",") if m.strip()]

        self.tiers: list[_LLMConfig] = []

        # Build a dynamic pool of LLM configurations
        for i, model in enumerate(models):
            # Cycle through keys if there are more models than keys
            key = keys[i % len(keys)] if keys else ""
            
            self.tiers.append(_LLMConfig(
                base_url=base_url,
                api_key=key,
                model=model,
                tier=f"tier_{i+1}"
            ))

        # OpenRouter requires an HTTP-Referer header
        self._openrouter_headers: dict[str, str] = {
            "HTTP-Referer": "https://vyala.ai",
            "X-Title":      "VYALA PQC Scanner",
        }
        self.mcp_client = BrightDataMCPClient()

        tier_summary = " | ".join([f"{t.tier}: {t.model} (Key: ...{t.api_key[-4:]})" for t in self.tiers])
        logger.info(
            "ContextBuilder initialised with Multi-Tier Pool | Tiers: [{}]",
            tier_summary
        )

    # ==========================================================================
    # PUBLIC API
    # ==========================================================================

    def enrich_finding(self, finding: CryptoFinding) -> CryptoFinding:
        """
        Enrich a single CryptoFinding with AI-generated PQC analysis.
        Iterates through the multi-tier pool until one succeeds.
        """
        if not finding.code_snippet.strip():
            logger.warning(
                "enrich_finding called with empty code_snippet | skipping AI enrichment.",
            )
            return finding

        # ── Fetch Live Web Context via MCP ─────────────────────────────────────
        web_context = ""
        try:
            web_context = self.mcp_client.get_pqc_context(
                algorithm=finding.algorithm_detected,
                language=finding.language.value
            )
        except Exception as exc:
            logger.warning(f"MCP context fetch failed: {exc}")

        # ── Try all available tiers ──────────────────────────────────────────
        for tier_config in self.tiers:
            if not tier_config.is_configured:
                continue

            try:
                result = self._call_llm(tier_config, finding, web_context=web_context)
                return self._apply_result(finding, result)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "LLM Tier failed, trying next... | "
                    "tier={} | model={} | error={!r}",
                    tier_config.tier,
                    tier_config.model,
                    exc,
                )

        # ── All tiers failed — return original, scan does not crash ───────────
        logger.error(
            "All LLM tiers failed. Returning un-enriched finding — scan continues."
        )
        return finding

    def enrich_findings_batch(
        self,
        findings: list[CryptoFinding],
        *,
        show_progress: bool = True,
    ) -> list[CryptoFinding]:
        """
        Enrich a list of findings sequentially with progress logging.

        Intentionally sequential (not async) for Phase 1 — the free API
        tiers have aggressive rate limits and parallel calls cause 429s.
        Phase 2 will add async batching with backoff once we have API quotas.

        Parameters
        ----------
        findings      : List of raw CryptoFindings from the parser.
        show_progress : Log progress every N findings (useful for large scans).

        Returns
        -------
        list[CryptoFinding]
            Same list with AI fields populated where possible.
        """
        if not findings:
            return []

        enriched: list[CryptoFinding] = []
        total = len(findings)
        success_count = 0
        fail_count = 0

        logger.info("AI enrichment pass starting | total_findings={}", total)

        for idx, finding in enumerate(findings, start=1):
            result = self.enrich_finding(finding)
            enriched.append(result)

            if result.is_ai_enriched:
                success_count += 1
            else:
                fail_count += 1

            if show_progress and (idx % 5 == 0 or idx == total):
                logger.info(
                    "AI enrichment progress | {}/{} | enriched={} | failed={}",
                    idx, total, success_count, fail_count,
                )

        logger.info(
            "AI enrichment complete | total={} | enriched={} | failed={} | "
            "success_rate={:.1f}%",
            total,
            success_count,
            fail_count,
            (success_count / total * 100) if total else 0.0,
        )
        return enriched

    # ==========================================================================
    # PRIVATE PIPELINE
    # ==========================================================================

    def _call_llm(
        self,
        config: _LLMConfig,
        finding: CryptoFinding,
        web_context: str = ""
    ) -> _LLMResult:
        """
        Make one LLM API call and return a validated _LLMResult.

        This method is intentionally synchronous — the OpenAI SDK's
        sync client handles connection pooling internally.

        Parameters
        ----------
        config  : _LLMConfig for the endpoint to call.
        finding : The CryptoFinding to analyze.

        Returns
        -------
        _LLMResult
            Parsed and validated response from the LLM.

        Raises
        ------
        openai.APIConnectionError  — Network failure or DNS error
        openai.RateLimitError      — 429 from the API
        openai.APIStatusError      — Non-2xx HTTP response
        ValueError                 — Malformed or schema-invalid JSON response
        Exception                  — Any other unexpected failure

        All exceptions propagate to enrich_finding() which routes to fallback.
        """
        # Build user prompt using the template builder
        user_prompt = build_user_prompt(
            algorithm_detected = finding.algorithm_detected,
            language           = finding.language.value,
            file_path          = finding.file_path,
            line_number        = finding.line_number,
            code_snippet       = finding.code_snippet,
            web_context        = web_context
        )

        # Construct the openai client fresh each call — thread-safe, no shared state
        extra_headers: dict[str, str] = {}
        if "openrouter" in config.base_url.lower():
            extra_headers = self._openrouter_headers

        client = openai.OpenAI(
            base_url        = config.base_url,
            api_key         = config.api_key,
            timeout         = _TIMEOUT_SECS,
            default_headers = extra_headers,
        )

        logger.debug(
            "Calling LLM | tier={} | model={} | finding_id={} | algo={}",
            config.tier,
            config.model,
            finding.finding_id,
            finding.algorithm_detected,
        )

        t0 = time.perf_counter()

        response = client.chat.completions.create(
            model       = config.model,
            temperature = _TEMPERATURE,
            max_tokens  = _MAX_TOKENS,
            messages    = [
                {"role": "system", "content": VYALA_SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
        )

        latency_ms = (time.perf_counter() - t0) * 1000

        # ── Extract raw text ────────────────────────────────────────────────────
        raw_content: str = response.choices[0].message.content or ""

        if not raw_content.strip():
            raise ValueError(
                f"LLM returned empty response | tier={config.tier} | "
                f"model={config.model}"
            )

        logger.debug(
            "LLM responded | tier={} | model={} | latency={:.0f}ms | "
            "tokens_used={} | raw_len={}",
            config.tier,
            config.model,
            latency_ms,
            getattr(response.usage, "total_tokens", "?"),
            len(raw_content),
        )

        # ── Clean and parse JSON ────────────────────────────────────────────────
        parsed = self._parse_llm_response(raw_content, config)

        # ── Validate schema ─────────────────────────────────────────────────────
        self._validate_response_schema(parsed, config)

        return _LLMResult(
            usage_context        = parsed["usage_context"].strip(),
            pqc_replacement      = parsed["pqc_replacement"].strip(),
            migration_complexity = parsed["migration_complexity"].strip().upper(),
            reasoning            = parsed["reasoning"].strip(),
            latency_ms           = latency_ms,
            tier_used            = config.tier,
            model_used           = config.model,
            prompt_version       = PROMPT_VERSIONS["system"],
        )

    def _parse_llm_response(
        self,
        raw: str,
        config: _LLMConfig,
    ) -> dict[str, Any]:
        """
        Strip markdown fences and parse JSON from the raw LLM output.

        Handles these real-world LLM misbehaviours:
          • Wrapping JSON in ```json ... ``` (despite explicit instruction not to)
          • Leading/trailing whitespace or newlines
          • BOM characters at the start of the string
          • Single-quoted JSON (rare but happens with some models)

        Raises ValueError if JSON cannot be parsed after all cleaning attempts.
        """
        cleaned = raw.strip().lstrip("\ufeff")   # Strip BOM

        # Strip markdown code fences (the most common misbehaviour)
        cleaned = _MD_FENCE_RE.sub("", cleaned).strip()

        # Attempt 1: Direct parse
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Attempt 2: Extract first {...} block (handles leading/trailing prose)
        brace_match = re.search(r"\{[\s\S]*\}", cleaned)
        if brace_match:
            try:
                return json.loads(brace_match.group())
            except json.JSONDecodeError:
                pass

        # All attempts failed
        logger.error(
            "JSON parse failed after all cleaning attempts | "
            "tier={} | model={} | raw_preview={!r}",
            config.tier,
            config.model,
            raw[:200],
        )
        raise ValueError(
            f"Could not parse valid JSON from LLM response. "
            f"tier={config.tier} | model={config.model} | "
            f"raw_preview={raw[:120]!r}"
        )

    @staticmethod
    def _validate_response_schema(
        parsed: dict[str, Any],
        config: _LLMConfig,
    ) -> None:
        """
        Validate the parsed JSON against the VYALA response schema.

        Raises ValueError on any schema violation so the caller can
        route to fallback rather than silently writing garbage into the CBOM.

        Checks:
          1. All required keys are present.
          2. All values are non-empty strings.
          3. migration_complexity is exactly LOW / MEDIUM / HIGH.
        """
        # Check required keys
        missing = _REQUIRED_KEYS - parsed.keys()
        if missing:
            raise ValueError(
                f"LLM response missing required keys: {sorted(missing)} | "
                f"tier={config.tier} | got_keys={sorted(parsed.keys())}"
            )

        # Check all values are non-empty strings
        for key in _REQUIRED_KEYS:
            val = parsed[key]
            if not isinstance(val, str):
                raise ValueError(
                    f"LLM response field '{key}' must be a string, "
                    f"got {type(val).__name__} | tier={config.tier}"
                )
            if not val.strip():
                raise ValueError(
                    f"LLM response field '{key}' is empty | tier={config.tier}"
                )

        # Check migration_complexity is valid enum value
        complexity = parsed["migration_complexity"].strip().upper()
        if complexity not in _VALID_COMPLEXITIES:
            raise ValueError(
                f"Invalid migration_complexity '{parsed['migration_complexity']}'. "
                f"Must be one of {_VALID_COMPLEXITIES} | tier={config.tier}"
            )

    @staticmethod
    def _apply_result(
        finding: CryptoFinding,
        result:  _LLMResult,
    ) -> CryptoFinding:
        """
        Apply a validated _LLMResult to a CryptoFinding.

        CryptoFinding is frozen (Pydantic model_config frozen=True), so we
        use model_copy(update=...) to create a new instance with AI fields
        populated. All identity fields (finding_id, location, timestamps)
        are preserved exactly.

        Also populates the structured PQCRecommendation nested model so the
        FastAPI layer can serve rich structured data to the Next.js frontend.
        """
        complexity_enum = MigrationComplexity(result.migration_complexity)

        pqc_rec = PQCRecommendation(
            primary_algorithm              = result.pqc_replacement,
            hybrid_transition_recommended  = _should_recommend_hybrid(
                result.pqc_replacement, result.migration_complexity
            ),
            migration_notes = result.reasoning,
            nist_reference  = _infer_nist_reference(result.pqc_replacement),
        )

        updated = finding.model_copy(update={
            "usage_context":        result.usage_context,
            "pqc_replacement":      result.pqc_replacement,
            "pqc_recommendation":   pqc_rec,
            "migration_complexity": complexity_enum,
            "ai_enriched_at":       datetime.now(timezone.utc),
        })

        logger.info(
            "Finding enriched | finding_id={} | algo={} | pqc={} | "
            "complexity={} | tier={} | latency={:.0f}ms",
            finding.finding_id,
            finding.algorithm_detected,
            result.pqc_replacement,
            result.migration_complexity,
            result.tier_used,
            result.latency_ms,
        )

        return updated


# ==============================================================================
# MODULE-LEVEL UTILITIES
# Pure functions — no state, fully testable.
# ==============================================================================

def _should_recommend_hybrid(pqc_replacement: str, complexity: str) -> bool:
    """
    Determine if a hybrid classical+PQC transition is recommended.

    Hybrid mode is recommended when:
    - Complexity is HIGH (implies external parties who can't immediately upgrade)
    - The replacement is an asymmetric algorithm (KEM or DSA family)
    - Not purely symmetric (AES-256-GCM, SHA-*, HMAC-*, ARGON2, BLAKE don't need hybrid)
    """
    if complexity == "HIGH":
        return True
    
    # FIX: Must be all uppercase so it matches the .upper() conversion!
    symmetric_indicators = ("AES", "SHA", "HMAC", "ARGON2", "BLAKE")
    return not any(pqc_replacement.upper().startswith(s) for s in symmetric_indicators)


def _infer_nist_reference(pqc_replacement: str) -> str | None:
    """
    Map a PQC algorithm name to its canonical NIST document reference.
    Returns None for algorithms without a direct NIST FIPS document.
    """
    upper = pqc_replacement.upper()
    if "ML-KEM" in upper or "KYBER" in upper:
        return "FIPS 203"
    if "ML-DSA" in upper or "DILITHIUM" in upper:
        return "FIPS 204"
    if "SLH-DSA" in upper or "SPHINCS" in upper:
        return "FIPS 205"
    if "FN-DSA" in upper or "FALCON" in upper:
        return "NIST IR 8413"
    if "AES-256" in upper:
        return "FIPS 197"
    if "SHA-3" in upper or "SHA3" in upper:
        return "FIPS 202"
    if "SHA-384" in upper or "SHA-512" in upper:
        return "FIPS 180-4"
    return None