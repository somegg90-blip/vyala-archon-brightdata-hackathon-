"""
vyala/core/parsers/csharp_parser.py

C# Crypto Scanner — Tree-sitter Implementation
===============================================
Scans C# source files for quantum-vulnerable cryptographic primitives.

Target crypto surfaces:
  1. System.Security.Cryptography (BCL)   — RSACryptoServiceProvider, AesCryptoServiceProvider
  2. BouncyCastle.NetCore                 — Org.BouncyCastle.*
  3. Microsoft.AspNetCore.DataProtection  — IDataProtector
  4. System.IdentityModel.Tokens.Jwt      — JWT / JwtSecurityTokenHandler
  5. Pkcs11Interop / hardware tokens
  6. SignalR / ASP.NET Core identity
  7. .NET new-style crypto                — RandomNumberGenerator, RSA.Create(), ECDsa.Create()

Why C# matters for VYALA:
  • Azure cloud services — C# is Microsoft's native cloud language
  • .NET banking APIs — virtually all UK / European bank APIs
  • Windows enterprise systems — Active Directory, ADFS, certificate stores
  • Healthcare: HL7/FHIR .NET SDK used in NHS, Epic integrations

Detection strategy:
  Layer 1 — using directives             → namespace present
  Layer 2 — object_creation_expression  → new RSACryptoServiceProvider(2048)
  Layer 3 — invocation_expression       → RSA.Create(), CryptoConfig.CreateFromName("SHA1")
  Layer 4 — string_literal              → algorithm names in factory methods
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator

import tree_sitter_c_sharp as tscsharp
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
# C# CRYPTO KNOWLEDGE BASE
# ==============================================================================

# Namespace using directives
_NAMESPACE_SIGNATURES: dict[str, tuple[str, QuantumVulnerabilityClass, SeverityLevel, bool]] = {
    "System.Security.Cryptography":              ("DotNet-Crypto",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "System.Security.Cryptography.X509Certificates": ("X509/PKI",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "Org.BouncyCastle":                          ("BouncyCastle.Net", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "System.IdentityModel.Tokens.Jwt":           ("JWT/RSA",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "Microsoft.IdentityModel.Tokens":            ("MSAL-Tokens",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "System.Net.Security":                       ("TLS/SSL",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "Microsoft.AspNetCore.DataProtection":       ("DataProtection",   QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
}

# Class/type names that are instantiated or called directly
# Maps type name (lowercased) → crypto signature
_CLASS_SIGNATURES: dict[str, tuple[str, QuantumVulnerabilityClass, SeverityLevel, bool]] = {
    # RSA
    "rsacryptoserviceprovider":  ("RSA",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rsacng":                    ("RSA",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rsa":                       ("RSA",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # DSA
    "dsacryptoserviceprovider":  ("DSA",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "dsacng":                    ("DSA",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "dsa":                       ("DSA",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # ECC
    "ecdsacng":                  ("ECDSA",        QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdsaopenssl":              ("ECDSA",        QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdsa":                     ("ECDSA",        QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdhcng":                   ("ECDH",         QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdh":                      ("ECDH",         QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # Symmetric (Grover weakened)
    "aescryptoserviceprovider":  ("AES",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "aescng":                    ("AES",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "aesmanaged":                ("AES",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "aes":                       ("AES",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),

    # Legacy symmetric — broken
    "descryptoserviceprovider":  ("DES",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "tripledescryptoserviceprovider": ("3DES",    QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH,     True),
    "tripleDES":                 ("3DES",         QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH,     True),
    "rc2cryptoserviceprovider":  ("RC2",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "rijndaelmanaged":           ("AES-Rijndael", QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),

    # Hash
    "md5cryptoserviceprovider":  ("MD5",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "md5":                       ("MD5",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha1managed":               ("SHA-1",        QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha1cryptoserviceprovider": ("SHA-1",        QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha256managed":             ("SHA-256",      QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "sha256":                    ("SHA-256",      QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "sha384managed":             ("SHA-384",      QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),
    "sha512managed":             ("SHA-512",      QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),

    # HMAC
    "hmacmd5":                   ("HMAC-MD5",     QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "hmacsha1":                  ("HMAC-SHA1",    QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH,     True),
    "hmacsha256":                ("HMAC-SHA256",  QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "hmacsha384":                ("HMAC-SHA384",  QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),
    "hmacsha512":                ("HMAC-SHA512",  QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),

    # TLS
    "sslstream":                 ("TLS/SSL",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "x509certificate":           ("X509/RSA",     QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "x509certificate2":          ("X509/RSA",     QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
}

# Algorithm string literals for CryptoConfig.CreateFromName() and similar
_ALGORITHM_STRING_MAP: dict[str, tuple[str, QuantumVulnerabilityClass, SeverityLevel, bool]] = {
    "rsa":          ("RSA",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "dsa":          ("DSA",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdsa":        ("ECDSA",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "md5":          ("MD5",      QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha1":         ("SHA-1",    QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha-1":        ("SHA-1",    QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha256":       ("SHA-256",  QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "sha-256":      ("SHA-256",  QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "aes":          ("AES",      QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "3des":         ("3DES",     QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH,     True),
    "des":          ("DES",      QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "rc2":          ("RC2",      QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "rs256":        ("RSA-SHA256", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rs512":        ("RSA-SHA512", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "es256":        ("ECDSA-SHA256", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
}

_KEY_SIZE_PATTERN = re.compile(r'\b(512|1024|2048|3072|4096)\b')

_CRYPTO_CONTEXT_METHODS = frozenset({
    "create", "createfromname", "getinstance", "generate",
    "sign", "verify", "encrypt", "decrypt", "computehash",
    "transformfinalblock", "importpkcs8privatekey", "importsubjectpublickeyinfo",
})


# ==============================================================================
# C# PARSER
# ==============================================================================

class CSharpParser(BaseParser):
    """
    Tree-sitter–powered scanner for vulnerable cryptography in C# source files.
    Handles: .cs
    """

    def __init__(self, target_directory: str) -> None:
        super().__init__(target_directory)
        self._ts_language = Language(tscsharp.language())
        self.parser = Parser(self._ts_language)
        logger.info(
            "CSharpParser ready | target={} | grammar=tree-sitter-c-sharp",
            self.target_directory,
        )

    def scan(self) -> list[CryptoFinding]:
        cs_files = self._get_files_by_extension(".cs")
        if not cs_files:
            logger.warning("CSharpParser found zero .cs files in '{}'.", self.target_directory)
            return []

        all_findings: list[CryptoFinding] = []
        logger.info("CSharpParser scanning {} file(s)…", len(cs_files))

        for file_path in cs_files:
            try:
                findings = self._scan_single_file(file_path)
                all_findings.extend(findings)
            except Exception as exc:
                logger.error("C# parse error | path={} | error={!r}", file_path, exc)

        logger.info("CSharpParser complete | total_findings={}", len(all_findings))
        return sorted(all_findings, key=lambda f: (f.file_path, f.line_number))

    def _scan_single_file(self, file_path: str) -> list[CryptoFinding]:
        source_text = self._read_file(file_path)
        if not source_text:
            return []
        source_bytes = source_text.encode("utf-8", errors="replace")
        tree = self.parser.parse(source_bytes)
        if tree is None or tree.root_node is None:
            return []
        return list(self._extract_crypto_nodes(tree, file_path, source_bytes))

    def _extract_crypto_nodes(
        self,
        tree,
        file_path: str,
        source_bytes: bytes,
    ) -> Iterator[CryptoFinding]:
        cursor = tree.walk()
        visited_children = False

        while True:
            node = cursor.node

            if not visited_children:
                # using System.Security.Cryptography;
                if node.type == "using_directive":
                    finding = self._analyse_using(node, file_path, source_bytes)
                    if finding:
                        yield finding

                # new RSACryptoServiceProvider(2048)
                elif node.type == "object_creation_expression":
                    finding = self._analyse_object_creation(node, file_path, source_bytes)
                    if finding:
                        yield finding

                # RSA.Create(), ECDSA.Create(), MD5.Create()
                elif node.type == "invocation_expression":
                    finding = self._analyse_invocation(node, file_path, source_bytes)
                    if finding:
                        yield finding

                # String literals in crypto context
                elif node.type == "string_literal":
                    finding = self._analyse_string_literal(node, file_path, source_bytes)
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

    def _analyse_using(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
    ) -> CryptoFinding | None:
        using_text = self._node_text(node, source_bytes)
        for ns, sig in _NAMESPACE_SIGNATURES.items():
            if ns in using_text:
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
                    language=SupportedLanguage.CSHARP if hasattr(SupportedLanguage, 'CSHARP')
                             else SupportedLanguage.UNKNOWN,
                    algorithm_detected=canonical,
                    code_snippet=using_text,
                    is_quantum_vulnerable=is_vuln,
                    vulnerability_class=vuln_class,
                    severity=severity,
                    detected_at=datetime.now(timezone.utc),
                )
        return None

    def _analyse_object_creation(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
    ) -> CryptoFinding | None:
        node_text = self._node_text(node, source_bytes)
        # Extract type name from: new RSACryptoServiceProvider(...)
        type_match = re.match(r'new\s+([A-Za-z0-9_<>]+)', node_text)
        if not type_match:
            return None

        type_name = type_match.group(1).lower()
        sig = _CLASS_SIGNATURES.get(type_name)
        if sig is None:
            return None

        canonical, vuln_class, severity, is_vuln = sig
        line_number = node.start_point[0] + 1

        # Key size refinement
        canonical, severity = self._refine_with_key_size(canonical, node_text, severity)

        return CryptoFinding(
            file_path=file_path,
            line_number=line_number,
            location=CodeLocation(
                file_path=file_path,
                line_number=line_number,
                column_start=node.start_point[1],
                column_end=node.end_point[1],
            ),
            language=SupportedLanguage.CSHARP if hasattr(SupportedLanguage, 'CSHARP')
                     else SupportedLanguage.UNKNOWN,
            algorithm_detected=canonical,
            code_snippet=node_text[:200],
            is_quantum_vulnerable=is_vuln,
            vulnerability_class=vuln_class,
            severity=severity,
            detected_at=datetime.now(timezone.utc),
        )

    def _analyse_invocation(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
    ) -> CryptoFinding | None:
        node_text = self._node_text(node, source_bytes)
        # Match: RSA.Create(), ECDSA.Create(), MD5.Create(), AesCng.Create()
        class_call_match = re.match(r'([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\s*\(', node_text)
        if not class_call_match:
            return None

        class_name = class_call_match.group(1).lower()
        method_name = class_call_match.group(2).lower()

        sig = _CLASS_SIGNATURES.get(class_name)
        if sig is None:
            return None
        if method_name not in _CRYPTO_CONTEXT_METHODS:
            return None

        canonical, vuln_class, severity, is_vuln = sig
        line_number = node.start_point[0] + 1
        canonical, severity = self._refine_with_key_size(canonical, node_text, severity)

        return CryptoFinding(
            file_path=file_path,
            line_number=line_number,
            location=CodeLocation(
                file_path=file_path,
                line_number=line_number,
                column_start=node.start_point[1],
                column_end=node.end_point[1],
            ),
            language=SupportedLanguage.CSHARP if hasattr(SupportedLanguage, 'CSHARP')
                     else SupportedLanguage.UNKNOWN,
            algorithm_detected=canonical,
            code_snippet=node_text[:200],
            is_quantum_vulnerable=is_vuln,
            vulnerability_class=vuln_class,
            severity=severity,
            detected_at=datetime.now(timezone.utc),
        )

    def _analyse_string_literal(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
    ) -> CryptoFinding | None:
        raw = self._node_text(node, source_bytes)
        algo_str = raw.strip('"').lower()

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
            language=SupportedLanguage.CSHARP if hasattr(SupportedLanguage, 'CSHARP')
                     else SupportedLanguage.UNKNOWN,
            algorithm_detected=canonical,
            code_snippet=context_text or raw,
            is_quantum_vulnerable=is_vuln,
            vulnerability_class=vuln_class,
            severity=severity,
            detected_at=datetime.now(timezone.utc),
        )

    def _is_in_crypto_context(self, node: Node, source_bytes: bytes) -> bool:
        current = node.parent
        for _ in range(4):
            if current is None:
                break
            text = self._node_text(current, source_bytes).lower()
            for method in _CRYPTO_CONTEXT_METHODS:
                if method in text:
                    return True
            if current.type in ("argument_list", "invocation_expression"):
                return True
            current = current.parent
        return False

    def _get_statement_text(self, node: Node, source_bytes: bytes) -> str:
        current = node.parent
        for _ in range(4):
            if current is None:
                break
            if current.type in ("expression_statement", "local_declaration_statement",
                                  "invocation_expression"):
                return self._node_text(current, source_bytes)
            current = current.parent
        return self._node_text(node, source_bytes)

    @staticmethod
    def _refine_with_key_size(
        algorithm_name: str,
        context_text: str,
        default_severity: SeverityLevel,
    ) -> tuple[str, SeverityLevel]:
        algo_base = algorithm_name.split("-")[0].upper()
        size_map = {
            "RSA": {
                512:  ("RSA-512",  SeverityLevel.CRITICAL),
                1024: ("RSA-1024", SeverityLevel.CRITICAL),
                2048: ("RSA-2048", SeverityLevel.CRITICAL),
                3072: ("RSA-3072", SeverityLevel.HIGH),
                4096: ("RSA-4096", SeverityLevel.HIGH),
            },
        }
        if algo_base not in size_map:
            return algorithm_name, default_severity
        match = _KEY_SIZE_PATTERN.search(context_text)
        if match:
            key_size = int(match.group())
            if key_size in size_map[algo_base]:
                return size_map[algo_base][key_size]
        return algorithm_name, default_severity

    @staticmethod
    def _node_text(node: Node, source_bytes: bytes) -> str:
        try:
            return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()
        except (AttributeError, ValueError):
            return ""

    def __repr__(self) -> str:
        return f"CSharpParser(target={self.target_directory!r}, grammar=tree-sitter-c-sharp)"