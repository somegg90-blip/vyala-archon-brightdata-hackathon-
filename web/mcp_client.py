"""
vyala_brightdata/web/mcp_client.py

Bright Data MCP Client (Web-Grounded RAG)
==========================================
Gives the AI Oracle live web context before suggesting PQC fixes,
preventing hallucinations by grounding responses in real NIST docs.

FIX (v2):
  The old code called https://api.brightdata.com/serp/req with a POST body —
  that endpoint requires a paid zone setup and returns 400 for most configs.
  
  We now use the SAME proxy approach that works in hunter.py:
    • SERP search  → BRD_SERP_USER/PASS proxy on brd.superproxy.io:22225
    • Page scrape  → BRD_UNLOCKER_USER/PASS proxy on brd.superproxy.io:22225
  
  This is consistent, already proven working, and uses zero extra config.
"""
from __future__ import annotations

import os
import json
import re
from urllib.parse import quote_plus

import httpx
from loguru import logger


# How much scraped text to pass to the LLM (chars). Enough for context,
# small enough not to blow up the token budget.
_MAX_CONTEXT_CHARS = 2000

# High-quality PQC reference URLs — scraped directly when SERP fails
_FALLBACK_NIST_URLS = [
    "https://csrc.nist.gov/projects/post-quantum-cryptography",
    "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf",
]

# Static fallback context keyed by algorithm family
_STATIC_FALLBACK: dict[str, str] = {
    "rsa": (
        "NIST FIPS 203 (ML-KEM / CRYSTALS-Kyber) is the approved replacement for RSA "
        "key encapsulation. NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium) replaces RSA "
        "signatures. NSA CNSA 2.0 mandates migration by 2030. "
        "Hybrid mode (classical + PQC in parallel) is recommended during transition."
    ),
    "ecdsa": (
        "NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium) replaces ECDSA for digital "
        "signatures. FIPS 205 (SLH-DSA / SPHINCS+) is a stateless hash-based "
        "alternative. Both are broken by Shor's algorithm on a sufficiently large "
        "quantum computer."
    ),
    "ec": (
        "Elliptic Curve cryptography (ECDH, ECDSA, ECIES) is vulnerable to Shor's "
        "algorithm. Replace key agreement with ML-KEM-768 (CRYSTALS-Kyber) per "
        "NIST FIPS 203. Replace signatures with ML-DSA-65 (Dilithium) per FIPS 204."
    ),
    "aes": (
        "AES is weakened (not broken) by Grover's algorithm — effective key length is "
        "halved. AES-128 → AES-256 upgrade is sufficient. AES-256 is considered "
        "quantum-safe per NIST SP 800-131A Rev 2."
    ),
    "golang.org/x/crypto": (
        "golang.org/x/crypto provides RSA, ECDSA, and ECDH primitives, all vulnerable "
        "to Shor's algorithm. Replace with golang.org/x/crypto/mlkem (ML-KEM, "
        "available Go 1.23+) for key encapsulation. For signatures use a Dilithium "
        "library such as github.com/cloudflare/circl/sign/dilithium."
    ),
    "pycryptodome": (
        "PyCryptodome's RSA and ECC modules use classical algorithms broken by Shor's "
        "algorithm. Replace RSA with ML-KEM (pip install pyca/cryptography >= 42 with "
        "experimental PQC support) or liboqs-python for CRYSTALS-Kyber."
    ),
    "bouncycastle": (
        "Bouncy Castle provides classical RSA/EC. The Bouncy Castle PQC provider "
        "(bcprov-ext-jdk18on) includes ML-KEM, ML-DSA, and SLH-DSA per NIST FIPS "
        "203/204/205. Migrate to org.bouncycastle:bcpqc-jdk18on."
    ),
    "default": (
        "NIST has standardised three PQC algorithms: ML-KEM (FIPS 203, key "
        "encapsulation), ML-DSA (FIPS 204, signatures), and SLH-DSA (FIPS 205, "
        "stateless hash signatures). NSA CNSA 2.0 requires migration away from "
        "classical asymmetric crypto by 2030. Hybrid classical+PQC mode is "
        "recommended during transition per NIST SP 800-227 (draft)."
    ),
}


class BrightDataMCPClient:
    """
    Web-grounded RAG client for PQC migration context.

    Priority order:
      1. Live SERP search + page scrape via Bright Data proxy (best)
      2. Static fallback context keyed by algorithm family (always works)
    """

    def __init__(self):
        self.serp_user     = os.getenv("BRD_SERP_USER", "")
        self.serp_pass     = os.getenv("BRD_SERP_PASS", "")
        self.unlocker_user = os.getenv("BRD_UNLOCKER_USER", "")
        self.unlocker_pass = os.getenv("BRD_UNLOCKER_PASS", "")
        self.mock_mode     = os.getenv("MOCK_WEB", "true").lower() == "true"

    @property
    def _serp_proxy(self) -> str:
        return f"http://{self.serp_user}:{self.serp_pass}@brd.superproxy.io:22225"

    @property
    def _unlocker_proxy(self) -> str:
        return f"http://{self.unlocker_user}:{self.unlocker_pass}@brd.superproxy.io:22225"

    # ── Public API ────────────────────────────────────────────────────────────

    def get_pqc_context(self, algorithm: str, language: str = "python") -> str:
        """
        Returns a string of PQC migration context for the given algorithm.
        Used by ContextBuilder to ground LLM recommendations in real docs.

        Never raises — always returns something useful (static fallback at worst).
        """
        if self.mock_mode:
            return self._mock_context(algorithm)

        # Try live web search first
        try:
            context = self._live_search(algorithm, language)
            if context and len(context.strip()) > 100:
                logger.info(
                    "MCP Client: got {} chars of live context for {}",
                    len(context), algorithm,
                )
                return context
        except Exception as exc:
            logger.warning("MCP Client live search failed: {} — using fallback", exc)

        # Static fallback — always works, zero credits
        return self._static_fallback(algorithm)

    # ── Live search (proxy-based, consistent with hunter.py) ─────────────────

    def _live_search(self, algorithm: str, language: str) -> str:
        """
        1. Google search via SERP proxy → get top result URL
        2. Scrape that URL via Web Unlocker proxy → return text excerpt
        """
        if not self.serp_user or not self.serp_pass:
            logger.debug("MCP Client: SERP credentials missing, skipping live search")
            return ""

        # Target NIST and authoritative PQC sources specifically
        query = (
            f'"{algorithm}" post-quantum migration '
            f'site:nist.gov OR site:csrc.nist.gov OR site:nvlpubs.nist.gov '
            f'OR site:github.com/open-quantum-safe'
        )
        search_url = (
            f"https://www.google.com/search"
            f"?q={quote_plus(query)}&num=5&gl=us&hl=en"
        )

        logger.info("MCP Client: SERP search for '{}'", algorithm)

        resp = httpx.get(
            search_url,
            proxy=self._serp_proxy,
            headers={"User-Agent": "Mozilla/5.0 (compatible; VyalaBot/1.0)"},
            verify=False,
            timeout=15,
            follow_redirects=True,
        )
        resp.raise_for_status()

        # Extract top URL from SERP response (JSON or HTML fallback)
        top_url = self._extract_top_url(resp)
        if not top_url:
            logger.debug("MCP Client: no usable URL from SERP result")
            return ""

        # Scrape the page
        return self._scrape_page(top_url)

    def _extract_top_url(self, resp: httpx.Response) -> str:
        """Try JSON parsing first, then regex over HTML."""
        try:
            data = resp.json()
            for result in data.get("organic", []):
                link = result.get("link", "")
                # Prefer NIST and OQS links
                if any(domain in link for domain in ["nist.gov", "open-quantum-safe"]):
                    return link
            # Any link is better than nothing
            for result in data.get("organic", []):
                link = result.get("link", "")
                if link.startswith("https://"):
                    return link
        except (json.JSONDecodeError, AttributeError):
            pass

        # HTML fallback — find href values pointing to nist.gov
        nist_pattern = r'href="(https://(?:csrc|nvlpubs)\.nist\.gov/[^"]+)"'
        matches = re.findall(nist_pattern, resp.text)
        if matches:
            return matches[0]

        # Any GitHub/NIST link in raw HTML
        generic = r'https://(?:nist\.gov|csrc\.nist\.gov|github\.com/open-quantum-safe)[^\s"\'<>]+'
        matches = re.findall(generic, resp.text)
        return matches[0] if matches else ""

    def _scrape_page(self, url: str) -> str:
        """Scrape a page via Web Unlocker proxy and return a text excerpt."""
        if not self.unlocker_user or not self.unlocker_pass:
            return ""

        logger.info("MCP Client: scraping context from {}", url)
        try:
            resp = httpx.get(
                url,
                proxy=self._unlocker_proxy,
                headers={"User-Agent": "Mozilla/5.0 (compatible; VyalaBot/1.0)"},
                verify=False,
                timeout=20,
                follow_redirects=True,
            )
            if resp.status_code == 200 and len(resp.text) > 50:
                # Strip HTML tags crudely — good enough for LLM context
                text = re.sub(r"<[^>]+>", " ", resp.text)
                text = re.sub(r"\s+", " ", text).strip()
                return text[:_MAX_CONTEXT_CHARS]
        except Exception as exc:
            logger.warning("MCP Client: page scrape failed for {} | {}", url, exc)
        return ""

    # ── Fallbacks ─────────────────────────────────────────────────────────────

    def _static_fallback(self, algorithm: str) -> str:
        """
        Return pre-written NIST-accurate context.
        Zero credits, zero latency, always available.
        Keyed by algorithm family substring match.
        """
        algo_lower = algorithm.lower()
        for key, context in _STATIC_FALLBACK.items():
            if key in algo_lower:
                logger.debug(
                    "MCP Client: using static fallback context for key='{}'", key
                )
                return context
        return _STATIC_FALLBACK["default"]

    def _mock_context(self, algorithm: str) -> str:
        logger.info("MCP Client: mock context for {}", algorithm)
        return self._static_fallback(algorithm)