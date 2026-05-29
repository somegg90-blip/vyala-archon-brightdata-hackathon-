"""
vyala/core/parsers/js_parser.py

JavaScript / TypeScript Crypto Scanner — Tree-sitter Implementation
=====================================================================
Handles both .js and .ts (and .jsx / .tsx) files using the JavaScript
grammar. TypeScript is a strict superset of JavaScript — the JS grammar
parses valid TypeScript with minor gaps (type annotations are treated as
unknown nodes and skipped, which is correct behavior for us).

Target crypto surfaces:
  1. Node.js crypto module       — require('crypto') / import crypto from 'crypto'
  2. Web Crypto API              — crypto.subtle.*, SubtleCrypto
  3. node-forge                  — forge.pki.rsa, forge.md.*
  4. jsrsasign                   — KEYUTIL, KJUR.crypto
  5. jose / jsonwebtoken         — JWT signing, RSA/ECDSA
  6. bcrypt / bcryptjs / argon2
  7. elliptic                    — EC operations
  8. crypto-js                   — CryptoJS.AES, CryptoJS.MD5
  9. tls / https modules         — secureContext, TLSSocket
 10. Algorithm string literals   — "RSA-OAEP", "ECDH", "AES-CBC"

Detection layers:
  Layer 1 — import/require       → library present
  Layer 2 — member expressions   → crypto.createHash("md5")
  Layer 3 — string literals      → algorithm name in crypto context
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator

import tree_sitter_javascript as tsjavascript
from loguru import logger
from tree_sitter import Language, Node, Parser

from ..models.cbom import (
    CodeLocation,
    CryptoFinding,
    QuantumVulnerabilityClass,
    SeverityLevel,
    SupportedLanguage,
)
from .base_parser import BaseParser


# ==============================================================================
# JS/TS CRYPTO KNOWLEDGE BASE
# ==============================================================================

# Module/package names that signal crypto usage
# Key: lowercased module name fragment
_MODULE_SIGNATURES: dict[str, tuple[str, QuantumVulnerabilityClass, SeverityLevel, bool]] = {
    # Node.js built-ins
    "crypto":           ("Node-crypto",   QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "tls":              ("TLS",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "https":            ("HTTPS/TLS",     QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.MEDIUM,   True),

    # JWT libraries
    "jsonwebtoken":     ("JWT",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "jose":             ("JOSE",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "jwk-to-pem":       ("RSA-JWK",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # RSA / ECC libraries
    "node-rsa":         ("RSA",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "node-forge":       ("RSA/ECC/DES",   QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "jsrsasign":        ("RSA/ECDSA",     QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "elliptic":         ("ECC",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "eccrypto":         ("ECC",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # Symmetric / general
    "crypto-js":        ("CryptoJS",      QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "aes-js":           ("AES",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),

    # Password hashing
    "bcrypt":           ("bcrypt",        QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "bcryptjs":         ("bcrypt",        QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "argon2":           ("Argon2",        QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.LOW,      False),

    # SSH
    "ssh2":             ("SSH",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "node-ssh":         ("SSH",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),

    # OpenPGP
    "openpgp":          ("PGP/RSA",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
}

# Web Crypto API and Node.js crypto algorithm string literals
# These appear in: crypto.subtle.generateKey({name: "RSA-OAEP", ...})
#                  crypto.createHash("sha256")
#                  crypto.createCipheriv("aes-256-cbc", ...)
_ALGORITHM_STRING_MAP: dict[str, tuple[str, QuantumVulnerabilityClass, SeverityLevel, bool]] = {
    # Web Crypto API algorithm names (object name field)
    "rsa-oaep":         ("RSA-OAEP",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rsassa-pkcs1-v1_5":("RSA-PKCS1",     QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rsa-pss":          ("RSA-PSS",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdsa":            ("ECDSA",         QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdh":             ("ECDH",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # Node.js createHash / createCipheriv algorithm strings
    "md5":              ("MD5",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha1":             ("SHA-1",         QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha-1":            ("SHA-1",         QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha256":           ("SHA-256",       QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "sha-256":          ("SHA-256",       QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "sha512":           ("SHA-512",       QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),
    "aes-128-cbc":      ("AES-128-CBC",   QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "aes-128-gcm":      ("AES-128-GCM",   QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "aes-256-cbc":      ("AES-256-CBC",   QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.LOW,      False),
    "aes-256-gcm":      ("AES-256-GCM",   QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),
    "des":              ("DES",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "des-cbc":          ("DES-CBC",       QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "des-ede3":         ("3DES",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH,     True),
    "rc4":              ("RC4",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),

    # JWT algorithms (appear in sign/verify options)
    "rs256":            ("RSA-SHA256",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rs384":            ("RSA-SHA384",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rs512":            ("RSA-SHA512",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "es256":            ("ECDSA-SHA256",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "es384":            ("ECDSA-SHA384",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "es512":            ("ECDSA-SHA512",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ps256":            ("RSA-PSS-SHA256",QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # Named curves
    "p-256":            ("ECC-P256",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "p-384":            ("ECC-P384",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "p-521":            ("ECC-P521",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "secp256k1":        ("ECC-secp256k1", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
}

# Node.js crypto method names that indicate crypto context
_CRYPTO_METHOD_NAMES = frozenset({
    "createhash", "createhmac", "createcipher", "createcipheriv",
    "createdecipher", "createdecipheriv", "createsign", "createverify",
    "generatekeypair", "generatekeypairsync", "generatekey", "generatekeysync",
    "publicencrypt", "privateencrypt", "publicdecrypt", "privatedecrypt",
    "sign", "verify", "generatekey", "importkey", "exportkey", "derivekey",
    "derivebits", "encrypt", "decrypt", "digest",
})


# ==============================================================================
# JS/TS PARSER
# ==============================================================================

class JavaScriptParser(BaseParser):
    """
    Tree-sitter–powered scanner for vulnerable cryptography in JS/TS source files.
    Handles: .js, .jsx, .ts, .tsx, .mjs, .cjs
    """

    # TypeScript extensions handled by the JS grammar
    _EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]

    def __init__(self, target_directory: str) -> None:
        super().__init__(target_directory)
        self._ts_language = Language(tsjavascript.language())
        self.parser = Parser(self._ts_language)
        logger.info(
            "JavaScriptParser ready | target={} | grammar=tree-sitter-javascript",
            self.target_directory,
        )

    def scan(self) -> list[CryptoFinding]:
        all_files = list(self._iter_files_by_extensions(self._EXTENSIONS))
        if not all_files:
            logger.warning("JavaScriptParser found zero JS/TS files in '{}'.", self.target_directory)
            return []

        all_findings: list[CryptoFinding] = []
        logger.info("JavaScriptParser scanning {} file(s)…", len(all_files))

        for file_path in all_files:
            try:
                findings = self._scan_single_file(file_path)
                all_findings.extend(findings)
            except Exception as exc:
                logger.error("JS/TS parse error | path={} | error={!r}", file_path, exc)

        logger.info("JavaScriptParser complete | total_findings={}", len(all_findings))
        return sorted(all_findings, key=lambda f: (f.file_path, f.line_number))

    def _scan_single_file(self, file_path: str) -> list[CryptoFinding]:
        source_text = self._read_file(file_path)
        if not source_text:
            return []

        source_bytes = source_text.encode("utf-8", errors="replace")
        tree = self.parser.parse(source_bytes)
        if tree is None or tree.root_node is None:
            return []

        # Detect language from extension
        language = SupportedLanguage.TYPESCRIPT if file_path.endswith((".ts", ".tsx")) \
                   else SupportedLanguage.JAVASCRIPT

        return list(self._extract_crypto_nodes(tree, file_path, source_bytes, language))

    def _extract_crypto_nodes(
        self,
        tree,
        file_path: str,
        source_bytes: bytes,
        language: SupportedLanguage,
    ) -> Iterator[CryptoFinding]:
        cursor = tree.walk()
        visited_children = False

        while True:
            node = cursor.node

            if not visited_children:
                # ES6 imports: import crypto from 'crypto'
                if node.type == "import_statement":
                    finding = self._analyse_import(node, file_path, source_bytes, language)
                    if finding:
                        yield finding

                # CommonJS require: require('crypto'), require('jsonwebtoken')
                elif node.type == "call_expression":
                    finding = self._analyse_require(node, file_path, source_bytes, language)
                    if finding:
                        yield finding

                # String literals — algorithm names in crypto context
                elif node.type == "string":
                    finding = self._analyse_string_literal(node, file_path, source_bytes, language)
                    if finding:
                        yield finding

                if cursor.goto_first_child():
                    visited_children = False
                    continue

            if cursor.goto_next_sibling():
                visited_children = False
            elif cursor.goto_parent():
                visited_children = True
            else:
                break

    def _analyse_import(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
        language: SupportedLanguage,
    ) -> CryptoFinding | None:
        node_text = self._node_text(node, source_bytes)
        # Extract quoted module name
        module_name = self._extract_quoted_string(node_text)
        if not module_name:
            return None

        return self._match_module(module_name, node, file_path, source_bytes, language)

    def _analyse_require(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
        language: SupportedLanguage,
    ) -> CryptoFinding | None:
        node_text = self._node_text(node, source_bytes)
        if not node_text.startswith("require("):
            return None

        module_name = self._extract_quoted_string(node_text)
        if not module_name:
            return None

        return self._match_module(module_name, node, file_path, source_bytes, language)

    def _match_module(
        self,
        module_name: str,
        node: Node,
        file_path: str,
        source_bytes: bytes,
        language: SupportedLanguage,
    ) -> CryptoFinding | None:
        lower = module_name.lower()
        for key, sig in _MODULE_SIGNATURES.items():
            if key == lower or lower.endswith(f"/{key}"):
                canonical, vuln_class, severity, is_vuln = sig
                line_number = node.start_point[0] + 1
                return CryptoFinding(
                    file_path=file_path,
                    line_number=line_number,
                    location=CodeLocation(
                        file_path=file_path,
                        line_number=line_number,
                        column_start=node.start_point[1],
                        column_end=node.end_point[1],
                    ),
                    language=language,
                    algorithm_detected=canonical,
                    code_snippet=self._node_text(node, source_bytes),
                    is_quantum_vulnerable=is_vuln,
                    vulnerability_class=vuln_class,
                    severity=severity,
                    detected_at=datetime.now(timezone.utc),
                )
        return None

    def _analyse_string_literal(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
        language: SupportedLanguage,
    ) -> CryptoFinding | None:
        raw = self._node_text(node, source_bytes)
        algo_str = raw.strip("\"'`").lower()

        sig = _ALGORITHM_STRING_MAP.get(algo_str)
        if sig is None:
            return None

        if not self._is_in_crypto_context(node, source_bytes):
            return None

        canonical, vuln_class, severity, is_vuln = sig
        line_number = node.start_point[0] + 1
        context_text = self._get_statement_text(node, source_bytes)

        return CryptoFinding(
            file_path=file_path,
            line_number=line_number,
            location=CodeLocation(
                file_path=file_path,
                line_number=line_number,
                column_start=node.start_point[1],
                column_end=node.end_point[1],
            ),
            language=language,
            algorithm_detected=canonical,
            code_snippet=context_text or raw,
            is_quantum_vulnerable=is_vuln,
            vulnerability_class=vuln_class,
            severity=severity,
            detected_at=datetime.now(timezone.utc),
        )

    def _is_in_crypto_context(self, node: Node, source_bytes: bytes) -> bool:
        """Check ancestors for crypto method calls."""
        current = node.parent
        for _ in range(5):
            if current is None:
                break
            if current.type in ("call_expression", "new_expression",
                                  "member_expression", "arguments"):
                text = self._node_text(current, source_bytes).lower()
                for method in _CRYPTO_METHOD_NAMES:
                    if method in text:
                        return True
                # Check for Web Crypto API pattern: {name: "RSA-OAEP"}
                if "name" in text and current.type in ("object", "pair"):
                    return True
            current = current.parent
        return False

    def _get_statement_text(self, node: Node, source_bytes: bytes) -> str:
        current = node.parent
        for _ in range(4):
            if current is None:
                break
            if current.type in ("expression_statement", "variable_declaration",
                                  "lexical_declaration", "call_expression"):
                return self._node_text(current, source_bytes)
            current = current.parent
        return self._node_text(node, source_bytes)

    @staticmethod
    def _extract_quoted_string(text: str) -> str | None:
        match = re.search(r"""['"`]([^'"`]+)['"`]""", text)
        return match.group(1) if match else None

    @staticmethod
    def _node_text(node: Node, source_bytes: bytes) -> str:
        try:
            return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()
        except (AttributeError, ValueError):
            return ""

    def __repr__(self) -> str:
        return f"JavaScriptParser(target={self.target_directory!r}, grammar=tree-sitter-javascript)"