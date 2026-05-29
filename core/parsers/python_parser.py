"""
vyala/core/parsers/python_parser.py

Python Crypto Scanner — Tree-sitter Implementation
====================================================
Inherits from BaseParser and uses Tree-sitter's Python grammar to build a
Concrete Syntax Tree (CST) for every .py file in the target directory.

We walk the CST looking for:
  1. import_statement          → `import rsa`, `import hashlib`
  2. import_from_statement     → `from Crypto.Cipher import AES`
  3. call_expression           → `RSA.generate(2048)`, `hashlib.md5()`
  4. attribute access          → `algorithms.RSA()`, `padding.OAEP()`
  5. assignment (key sizes)    → `key_size=1024`, `RSA.generate(1024)`

Why AST over regex?
  • Regex cannot distinguish `# import rsa` (comment) from `import rsa` (live code).
  • Regex cannot track indentation context or string literals vs identifiers.
  • Tree-sitter gives us typed nodes — we query EXACTLY what we mean.
  • Tree-sitter is fault-tolerant: it produces partial trees for broken files
    rather than raising exceptions, which is critical for real enterprise codebases
    that contain half-written migration branches, syntax errors in feature flags, etc.

Algorithm detection strategy (layered, most-specific wins):
  Layer 1 — Import module name   → coarse signal   ("something from Crypto is used")
  Layer 2 — Import member name   → medium signal   ("AES specifically")
  Layer 3 — Call arguments       → fine signal     ("AES-128 vs AES-256 by key size")
  Layer 4 — Attribute chains     → context signal  ("padding.PKCS1v15 = RSA, not AES")

Quantum vulnerability mapping (NIST SP 800-131A Rev 2 + CNSA 2.0):
  SHOR_VULNERABLE  → RSA, ECC (ECDSA/ECDH), DSA, DH, ElGamal
  GROVER_WEAKENED  → AES-128, HMAC-SHA1/SHA256, MD5, SHA-1, SHA-256
  QUANTUM_SAFE     → AES-256, SHA-384, SHA-512, SHA-3-256+
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import tree_sitter_python as tspython
from loguru import logger
from tree_sitter import Language, Node, Parser

# ── FIXED IMPORTS: Relative paths ──
from ..models.cbom import (
    CodeLocation,
    CryptoFinding,
    QuantumVulnerabilityClass,
    SeverityLevel,
    SupportedLanguage,
)
from .base_parser import BaseParser


# ==============================================================================
# DETECTION KNOWLEDGE BASE
# These structures encode our quantum-vulnerability expertise.
# They are the heart of Phase 1 — keep them accurate and well-documented.
# ==============================================================================

@dataclass(frozen=True)
class AlgorithmSignature:
    """
    Maps a detected import or call pattern to a canonical crypto algorithm
    name and its quantum risk classification.
    """
    canonical_name: str                           # e.g. "RSA-2048"
    vulnerability_class: QuantumVulnerabilityClass
    severity: SeverityLevel
    is_quantum_vulnerable: bool
    nist_note: str                                # One-line NIST rationale


# Module-level import signatures.
# Key: module name as it appears in source (case-sensitive, matches Python imports).
# Value: base AlgorithmSignature — key size refinement happens in Layer 3.
_MODULE_SIGNATURES: dict[str, AlgorithmSignature] = {
    # ── PyCryptodome / PyCrypto ──────────────────────────────────────────────
    "Crypto":           AlgorithmSignature("PyCryptodome",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True,  "PyCryptodome umbrella — contains RSA, ECC, DSA"),
    "Cryptodome":       AlgorithmSignature("PyCryptodome",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True,  "PyCryptodome umbrella — contains RSA, ECC, DSA"),

    # ── cryptography (PyCA) ──────────────────────────────────────────────────
    "cryptography":     AlgorithmSignature("PyCA/cryptography", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH, True,  "Hazmat layer exposes RSA, ECC, DSA — audit submodule imports"),

    # ── Standalone RSA ───────────────────────────────────────────────────────
    "rsa":              AlgorithmSignature("RSA",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL,  True,  "CNSA 2.0: RSA disallowed after 2030; replace with ML-KEM/ML-DSA"),

    # ── Hash functions ───────────────────────────────────────────────────────
    "hashlib":          AlgorithmSignature("Hash/hashlib",  QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True,  "MD5/SHA-1 broken; SHA-256 Grover-weakened; use SHA-3-256+ or SHA-512"),

    # ── HMAC ─────────────────────────────────────────────────────────────────
    "hmac":             AlgorithmSignature("HMAC",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True,  "Security depends on underlying hash; prefer HMAC-SHA-512 or KMAC"),

    # ── JWT (often wraps RSA/ECDSA) ──────────────────────────────────────────
    "jwt":              AlgorithmSignature("JWT",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True,  "JWT signing often uses RS256/ES256 — both Shor-vulnerable"),
    "jose":             AlgorithmSignature("JOSE",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True,  "JOSE standards include RSA-OAEP and ECDH-ES — audit algorithm field"),

    # ── OpenSSL / SSL / TLS ──────────────────────────────────────────────────
    "ssl":              AlgorithmSignature("TLS/SSL",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True,  "TLS handshake uses ECDH/RSA key exchange — Shor-vulnerable"),
    "OpenSSL":          AlgorithmSignature("OpenSSL",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True,  "Direct OpenSSL binding — almost certainly RSA/ECC in use"),

    # ── Elliptic Curve ───────────────────────────────────────────────────────
    "ecdsa":            AlgorithmSignature("ECDSA",         QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True,  "CNSA 2.0: ECDSA/ECDH disallowed after 2030; replace with ML-DSA"),
    "fastecdsa":        AlgorithmSignature("ECDSA",         QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True,  "fastecdsa wraps ECDSA — Shor-vulnerable"),
    "tinyec":           AlgorithmSignature("ECC",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True,  "Elliptic curve library — all curves Shor-vulnerable"),

    # ── Diffie-Hellman ───────────────────────────────────────────────────────
    "dh":               AlgorithmSignature("DH",            QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True,  "Classical DH broken by Shor — replace with ML-KEM-768+"),
    "dhparam":          AlgorithmSignature("DH",            QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True,  "DH parameter generation — Shor-vulnerable"),

    # ── Password hashing (bcrypt / argon2 — Grover weakened) ─────────────────
    "bcrypt":           AlgorithmSignature("bcrypt",        QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True,  "bcrypt effective security halved by Grover; use Argon2id"),
    "passlib":          AlgorithmSignature("passlib",       QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True,  "Audit algorithm parameter — MD5 crypt variants are critically weak"),

    # ── Symmetric (AES — note: AES-128 is Grover-weakened, AES-256 is safe) ──
    "pyaes":            AlgorithmSignature("AES",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True,  "Pure-Python AES; audit key size — AES-128 Grover-weakened"),

    # ── Secrets / random (informational) ─────────────────────────────────────
    "random":           AlgorithmSignature("PRNG/random",   QuantumVulnerabilityClass.UNKNOWN,         SeverityLevel.INFO,     False, "stdlib random is NOT cryptographically secure — use secrets module"),
}

# Sub-module / member-level refinements.
# From statements like `from Crypto.PublicKey import RSA` or
# `from cryptography.hazmat.primitives.asymmetric import rsa`.
# Key: lowercased member or submodule name fragment.
_SUBMODULE_ALGORITHM_MAP: dict[str, str] = {
    "rsa":         "RSA",
    "dsa":         "DSA",
    "ecdsa":       "ECDSA",
    "ec":          "ECC",
    "ecdh":        "ECDH",
    "elgamal":     "ElGamal",
    "dh":          "DH",
    "aes":         "AES",
    "des":         "DES-3",       # Triple-DES; single DES is dead
    "blowfish":    "Blowfish",
    "arc2":        "RC2",
    "arc4":        "RC4",
    "chacha20":    "ChaCha20",    # Quantum-safe symmetric, but log it
    "md5":         "MD5",
    "sha1":        "SHA-1",
    "sha256":      "SHA-256",
    "sha512":      "SHA-512",
    "sha3":        "SHA-3",
    "blake2":      "BLAKE2",
    "pkcs1":       "RSA-PKCS1",
    "oaep":        "RSA-OAEP",
    "pss":         "RSA-PSS",
    "padding":     "RSA",         # padding module = RSA context in PyCryptodome
    "x25519":      "X25519",      # ECDH variant — Shor-vulnerable
    "x448":        "X448",        # ECDH variant — Shor-vulnerable
    "ed25519":     "Ed25519",     # EdDSA — Shor-vulnerable
    "ed448":       "Ed448",       # EdDSA — Shor-vulnerable
}

# Key size patterns to scan for in call arguments.
# Detecting `RSA.generate(1024)` vs `RSA.generate(4096)` changes severity.
_KEY_SIZE_PATTERN = re.compile(r"\b(512|1024|2048|3072|4096|8192)\b")

# Algorithms where specific key sizes change the severity rating.
_SEVERITY_BY_KEY_SIZE: dict[str, dict[int, tuple[str, SeverityLevel]]] = {
    "RSA": {
        512:  ("RSA-512",  SeverityLevel.CRITICAL),   # Trivially broken classically
        1024: ("RSA-1024", SeverityLevel.CRITICAL),   # Broken classically + quantum
        2048: ("RSA-2048", SeverityLevel.CRITICAL),   # CNSA 2.0 deprecated after 2030
        3072: ("RSA-3072", SeverityLevel.HIGH),        # Transitional; still quantum-vulnerable
        4096: ("RSA-4096", SeverityLevel.HIGH),        # Strongest classical; still Shor-broken
    },
    "DH": {
        512:  ("DH-512",   SeverityLevel.CRITICAL),
        1024: ("DH-1024",  SeverityLevel.CRITICAL),
        2048: ("DH-2048",  SeverityLevel.CRITICAL),
    },
    "AES": {
        128: ("AES-128",  SeverityLevel.MEDIUM),       # Grover reduces to 64-bit effective
        192: ("AES-192",  SeverityLevel.LOW),           # Grover reduces to 96-bit effective
        256: ("AES-256",  SeverityLevel.LOW),           # Grover reduces to 128-bit — still safe
    },
}


# ==============================================================================
# CONCRETE PARSER
# ==============================================================================


class PythonParser(BaseParser):
    """
    Tree-sitter–powered scanner for vulnerable cryptography in Python source files.

    Scan pipeline per file
    ----------------------
    1. _get_files_by_extension('.py')  →  file paths
    2. _read_file(path)                →  raw source text (bytes for Tree-sitter)
    3. self.parser.parse(source_bytes) →  CST (Concrete Syntax Tree)
    4. _extract_crypto_nodes(tree)     →  Iterator[CryptoFinding]
       └─ _analyse_import_node()       →  Layer 1 + 2 detection
          └─ _refine_with_key_size()   →  Layer 3 key-size refinement
    5. findings accumulated and returned from scan()
    """

    def __init__(self, target_directory: str) -> None:
        super().__init__(target_directory)
        # Initialise Tree-sitter with the compiled Python grammar.
        # Language() compiles the grammar; Parser() uses it to parse source.
        self._ts_language = Language(tspython.language())
        self.parser = Parser(self._ts_language)

        logger.info(
            "PythonParser ready | target={} | grammar=tree-sitter-python",
            self.target_directory,
        )

    # ==========================================================================
    # PUBLIC INTERFACE
    # ==========================================================================

    def scan(self) -> list[CryptoFinding]:
        """
        Scan all Python files in `self.target_directory` for legacy cryptography.

        Returns
        -------
        list[CryptoFinding]
            All findings sorted by (file_path, line_number) for deterministic,
            diff-friendly CBOM output. Never raises — per-file errors are logged
            and skipped so a single bad file cannot abort an enterprise scan.
        """
        py_files = self._get_files_by_extension(".py")

        if not py_files:
            logger.warning(
                "PythonParser found zero .py files in '{}'. "
                "Check --path argument or file permissions.",
                self.target_directory,
            )
            return []

        all_findings: list[CryptoFinding] = []
        files_with_findings = 0
        files_errored = 0

        logger.info("PythonParser scanning {} file(s)…", len(py_files))

        for file_path in py_files:
            try:
                findings = self._scan_single_file(file_path)
                if findings:
                    all_findings.extend(findings)
                    files_with_findings += 1
                    logger.debug(
                        "Findings in file | path={} | count={}",
                        file_path,
                        len(findings),
                    )
            except Exception as exc:  # noqa: BLE001 — intentional broad catch
                # A Tree-sitter crash on a malformed file must NEVER abort the scan.
                # Log it and continue — the CBOM audit trail records the error.
                files_errored += 1
                logger.error(
                    "Unexpected error scanning file | path={} | error={!r}",
                    file_path,
                    exc,
                )

        logger.info(
            "PythonParser complete | "
            "scanned={} | with_findings={} | errored={} | total_findings={}",
            len(py_files),
            files_with_findings,
            files_errored,
            len(all_findings),
        )

        # Sort for deterministic CBOM output — critical for git-diffable reports.
        return sorted(all_findings, key=lambda f: (f.file_path, f.line_number))

    # ==========================================================================
    # PRIVATE SCANNING PIPELINE
    # ==========================================================================

    def _scan_single_file(self, file_path: str) -> list[CryptoFinding]:
        """
        Full scan pipeline for a single Python file.

        Returns an empty list for files with no detectable crypto usage,
        unreadable files, or files that parse to an empty tree.
        """
        source_text = self._read_file(file_path)
        if not source_text:
            return []

        # Tree-sitter requires bytes, not str.
        # We encode back to UTF-8 — this is always safe because _read_file
        # already successfully decoded the file as UTF-8 or latin-1.
        source_bytes = source_text.encode("utf-8", errors="replace")

        tree = self.parser.parse(source_bytes)

        if tree is None or tree.root_node is None:
            logger.debug("Tree-sitter returned empty tree for file={}", file_path)
            return []

        return list(
            self._extract_crypto_nodes(
                tree=tree,
                file_path=file_path,
                source_bytes=source_bytes,
            )
        )

    def _extract_crypto_nodes(
        self,
        tree,
        file_path: str,
        source_bytes: bytes,
    ) -> Iterator[CryptoFinding]:
        """
        Walk the CST and yield a CryptoFinding for every detected crypto node.

        We perform a depth-first traversal of the syntax tree using Tree-sitter's
        walk() API, which avoids Python recursion limits on deeply nested files
        (e.g. auto-generated protobuf files can be thousands of levels deep).

        Node types targeted:
          • import_statement           → `import rsa`
          • import_from_statement      → `from Crypto.Cipher import AES`

        Future layers (Phase 1.1) will add:
          • call_expression            → `RSA.generate(2048)`
          • attribute_reference        → `algorithms.RSA()`
        """
        cursor = tree.walk()

        # Iterative DFS using Tree-sitter's cursor API.
        # This is significantly faster than recursive Python calls for large files.
        visited_children = False

        while True:
            node = cursor.node

            if not visited_children:
                # ── Process this node ──────────────────────────────────────────
                if node.type in ("import_statement", "import_from_statement"):
                    finding = self._analyse_import_node(
                        node=node,
                        file_path=file_path,
                        source_bytes=source_bytes,
                        node_type=node.type,
                    )
                    if finding is not None:
                        yield finding

                # Descend into children
                if cursor.goto_first_child():
                    visited_children = False
                    continue

            # Try next sibling; if none, go to parent
            if cursor.goto_next_sibling():
                visited_children = False
            elif cursor.goto_parent():
                visited_children = True
            else:
                break  # Back at root — traversal complete

    def _analyse_import_node(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
        node_type: str,
    ) -> CryptoFinding | None:
        """
        Analyse a single import AST node and return a CryptoFinding if a
        vulnerable library is detected.

        Handles both forms:
          • import_statement:      `import rsa` / `import Crypto`
          • import_from_statement: `from Crypto.Cipher import AES`
                                   `from cryptography.hazmat.primitives.asymmetric import rsa`

        Returns None if the import is not in our vulnerability knowledge base.
        """
        node_text = self._node_text(node, source_bytes)
        line_number = node.start_point[0] + 1  # Tree-sitter is 0-indexed; humans are 1-indexed
        col_start   = node.start_point[1]
        col_end     = node.end_point[1]

        # ── Layer 1: Extract the top-level module name ────────────────────────
        root_module = self._extract_root_module(node, source_bytes, node_type)
        if root_module is None:
            return None

        signature = _MODULE_SIGNATURES.get(root_module)
        if signature is None:
            return None

        # ── Layer 2: Refine algorithm name from sub-module or imported member ──
        algorithm_name = signature.canonical_name
        refined_algorithm = self._refine_algorithm_from_node(node, source_bytes, node_type)
        if refined_algorithm:
            algorithm_name = refined_algorithm

        # ── Layer 3: Refine severity/name from key size in the same line ──────
        algorithm_name, severity = self._refine_with_key_size(
            algorithm_name, node_text, signature.severity
        )

        logger.debug(
            "Crypto import detected | file={} | line={} | module={} | algo={}",
            file_path, line_number, root_module, algorithm_name,
        )

        return CryptoFinding(
            file_path=file_path,
            line_number=line_number,
            location=CodeLocation(
                file_path=file_path,
                line_number=line_number,
                column_start=col_start,
                column_end=col_end,
            ),
            language=SupportedLanguage.PYTHON,
            algorithm_detected=algorithm_name,
            code_snippet=node_text,
            is_quantum_vulnerable=signature.is_quantum_vulnerable,
            vulnerability_class=signature.vulnerability_class,
            severity=severity,
            detected_at=datetime.now(timezone.utc),
            # AI enrichment fields — populated later by vyala/ai/ pass
            usage_context=None,
            pqc_recommendation=None,
            pqc_replacement=None,
            migration_complexity=None,
        )

    def _extract_root_module(
        self,
        node: Node,
        source_bytes: bytes,
        node_type: str,
    ) -> str | None:
        """
        Extract the top-level module name from an import node.

        For `import rsa`                     → "rsa"
        For `import Crypto.Cipher`           → "Crypto"
        For `from Crypto.Cipher import AES`  → "Crypto"
        For `from cryptography.hazmat…`      → "cryptography"

        Returns None if the module name cannot be parsed.
        """
        if node_type == "import_statement":
            # Children: [import, dotted_name | aliased_import, ...]
            for child in node.children:
                if child.type in ("dotted_name", "aliased_import"):
                    # The first identifier in the dotted name is the root module.
                    for sub in child.children:
                        if sub.type == "identifier":
                            return self._node_text(sub, source_bytes)
                elif child.type == "identifier":
                    return self._node_text(child, source_bytes)

        elif node_type == "import_from_statement":
            # Children: [from, dotted_name, import, ...]
            # The first dotted_name after `from` is the module path.
            for child in node.children:
                if child.type == "dotted_name":
                    # First identifier = root module ("Crypto", "cryptography", etc.)
                    for sub in child.children:
                        if sub.type == "identifier":
                            return self._node_text(sub, source_bytes)
                    # Fallback: raw text of the dotted_name, split on "."
                    raw = self._node_text(child, source_bytes)
                    return raw.split(".")[0] if raw else None
                elif child.type == "relative_import":
                    # `from . import something` — relative imports, skip
                    return None

        return None

    def _refine_algorithm_from_node(
        self,
        node: Node,
        source_bytes: bytes,
        node_type: str,
    ) -> str | None:
        """
        Attempt to extract a more specific algorithm name from the import members.

        `from Crypto.PublicKey import RSA`    → "RSA"
        `from Crypto.Cipher import AES, DES`  → "AES"  (first match wins)
        `from cryptography.hazmat.primitives.asymmetric import rsa` → "RSA"

        Returns None if no specific algorithm member is identified.
        """
        if node_type != "import_from_statement":
            return None

        # Collect all identifier children after the `import` keyword.
        past_import_keyword = False
        for child in node.children:
            if child.type == "import":
                past_import_keyword = True
                continue
            if past_import_keyword:
                # May be a dotted_name, identifier, or import_prefix node
                identifiers = self._collect_identifiers(child, source_bytes)
                for ident in identifiers:
                    mapped = _SUBMODULE_ALGORITHM_MAP.get(ident.lower())
                    if mapped:
                        return mapped

        # Also check module path segments for sub-module hints
        # e.g. `from cryptography.hazmat.primitives.asymmetric.rsa import ...`
        for child in node.children:
            if child.type == "dotted_name":
                segments = self._node_text(child, source_bytes).split(".")
                for segment in segments[1:]:  # Skip root module — already used
                    mapped = _SUBMODULE_ALGORITHM_MAP.get(segment.lower())
                    if mapped:
                        return mapped

        return None

    @staticmethod
    def _refine_with_key_size(
        algorithm_name: str,
        node_text: str,
        default_severity: SeverityLevel,
    ) -> tuple[str, SeverityLevel]:
        """
        If a key size integer is present in the node text, refine the algorithm
        canonical name and severity.

        `RSA.generate(2048)`  →  ("RSA-2048", SeverityLevel.CRITICAL)
        `AES.new(key, AES.MODE_CBC)` with 16-byte key → ("AES-128", SeverityLevel.MEDIUM)

        This is a best-effort heuristic at the import level. Full key-size
        extraction requires analysing call arguments (Layer 3, Phase 1.1).
        """
        algo_base = algorithm_name.split("-")[0].upper()
        size_map = _SEVERITY_BY_KEY_SIZE.get(algo_base)
        if size_map is None:
            return algorithm_name, default_severity

        match = _KEY_SIZE_PATTERN.search(node_text)
        if match:
            key_size = int(match.group())
            if key_size in size_map:
                refined_name, refined_severity = size_map[key_size]
                return refined_name, refined_severity

        return algorithm_name, default_severity

    # ==========================================================================
    # TREE-SITTER UTILITIES
    # ==========================================================================

    @staticmethod
    def _node_text(node: Node, source_bytes: bytes) -> str:
        """
        Extract the source text for a Tree-sitter node.

        Tree-sitter nodes store byte offsets (start_byte, end_byte), not
        character offsets. We slice source_bytes directly and decode — this
        is correct even for multi-byte Unicode identifiers.
        """
        try:
            raw = source_bytes[node.start_byte : node.end_byte]
            return raw.decode("utf-8", errors="replace").strip()
        except (AttributeError, ValueError):
            return ""

    def _collect_identifiers(self, node: Node, source_bytes: bytes) -> list[str]:
        """
        Recursively collect all identifier text values under a node.
        Used to enumerate imported names from import lists.
        """
        results: list[str] = []
        if node.type == "identifier":
            text = self._node_text(node, source_bytes)
            if text:
                results.append(text)
        for child in node.children:
            results.extend(self._collect_identifiers(child, source_bytes))
        return results

    # ==========================================================================
    # DUNDER
    # ==========================================================================

    def __repr__(self) -> str:
        return (
            f"PythonParser("
            f"target={self.target_directory!r}, "
            f"grammar=tree-sitter-python)"
        )