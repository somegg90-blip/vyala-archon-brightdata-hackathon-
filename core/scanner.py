"""
vyala_brightdata/core/scanner.py

The engine wrapper that bridges FastAPI to the Vyala parsing & AI core.

FIXES (v0.1.1)
--------------
1. Frozen Pydantic bug: ScanMetadata is frozen — we NEVER mutate it in-place.
   All updates go through model_copy(update={...}) which creates a new instance.
2. Dependency file gap: Added DependencyParser to scan .txt/.json/.toml etc.
   If only dep files are found (no source), languages_scanned gets UNKNOWN.
"""
import time
import importlib
from loguru import logger

from .models.cbom import CBOMReport, ScanMetadata, CBOMStatus, SupportedLanguage
from .parsers.python_parser import PythonParser
from .parsers.dependency_parser import DependencyParser  # NEW
from .ai.context_builder import ContextBuilder


def _dynamic_parser_import(module_name, class_names):
    """Try to import a parser class from a module, trying multiple class names."""
    try:
        mod = importlib.import_module(module_name, __package__)
        for cname in class_names:
            if hasattr(mod, cname):
                return getattr(mod, cname)
    except Exception as e:
        logger.warning(f"Parser import failed: {module_name} ({e})")
    return None


# Map: (module, [possible class names], SupportedLanguage)
_PARSER_CONFIGS = [
    (".parsers.js_parser",     ["JavaScriptParser", "JavascriptParser", "JsParser"], SupportedLanguage.JAVASCRIPT),
    (".parsers.java_parser",   ["JavaParser"],                                        SupportedLanguage.JAVA),
    (".parsers.go_parser",     ["GoParser"],                                          SupportedLanguage.GO),
    (".parsers.csharp_parser", ["CSharpParser", "CsharpParser"],                     SupportedLanguage.CSHARP),
]


class VyalaEngine:
    def __init__(self):
        self.ai_builder = ContextBuilder()

    def scan_local_target(self, target_name: str, target_path: str) -> CBOMReport:
        start_time = time.time()

        # ── Build initial (frozen) metadata ───────────────────────────────────
        # ScanMetadata is frozen=True. We NEVER assign to its fields directly.
        # Use model_copy(update={...}) every time we need to change something.
        metadata = ScanMetadata(
            project_name=target_name,
            scan_root=target_path,
            scanned_by="vyala-brightdata/0.1.1",
            languages_scanned=[],   # filled in below via model_copy
            files_scanned=0,
        )

        report = CBOMReport(
            project_name=target_name,
            metadata=metadata,
            status=CBOMStatus.SCANNING,
        )

        try:
            all_findings = []
            scanned_languages: list[SupportedLanguage] = []
            files_scanned = 0

            # ── 1. Tree-sitter source parsers ──────────────────────────────────

            # Python (statically imported — always available)
            try:
                py_parser = PythonParser(target_directory=target_path)
                py_findings = py_parser.scan()
                if py_findings:
                    all_findings.extend(py_findings)
                    scanned_languages.append(SupportedLanguage.PYTHON)
                    files_scanned += len(py_findings)
                    logger.info(f"PythonParser: {len(py_findings)} finding(s).")
            except Exception as e:
                logger.warning(f"PythonParser failed: {e}")

            # Other language parsers (dynamically imported)
            for mod, class_names, lang_enum in _PARSER_CONFIGS:
                ParserClass = _dynamic_parser_import(mod, class_names)
                if ParserClass is None:
                    logger.warning(
                        f"{lang_enum.name} parser not available — skipping."
                    )
                    continue
                try:
                    parser_instance = ParserClass(target_directory=target_path)
                    findings = parser_instance.scan()
                    if findings:
                        all_findings.extend(findings)
                        scanned_languages.append(lang_enum)
                        files_scanned += len(findings)
                        logger.info(
                            f"{ParserClass.__name__}: {len(findings)} finding(s)."
                        )
                except Exception as e:
                    logger.warning(f"{ParserClass.__name__} failed: {e}")

            # ── 2. Dependency file parser (NEW — handles .txt, .json, etc.) ───
            try:
                dep_parser = DependencyParser(target_directory=target_path)
                dep_findings = dep_parser.scan()
                if dep_findings:
                    all_findings.extend(dep_findings)
                    logger.info(
                        f"DependencyParser: {len(dep_findings)} finding(s) "
                        f"in dependency/manifest files."
                    )
            except Exception as e:
                logger.warning(f"DependencyParser failed: {e}")

            # ── 3. Determine languages_scanned ────────────────────────────────
            # FIX: if no source code was found but we DID find dep-file findings,
            # mark the scan as UNKNOWN so the report isn't silently empty.
            if not scanned_languages and all_findings:
                scanned_languages = [SupportedLanguage.UNKNOWN]
                logger.info(
                    "No source code found; findings came from dependency files only. "
                    "Marking language as UNKNOWN."
                )

            # ── 4. Attach findings to report ──────────────────────────────────
            report.findings = all_findings

            # ── FIX: use model_copy — NEVER mutate a frozen model directly ────
            report.metadata = report.metadata.model_copy(
                update={
                    "languages_scanned": scanned_languages,
                    "files_scanned": files_scanned,
                }
            )

            # ── 5. AI enrichment ──────────────────────────────────────────────
            if all_findings:
                logger.info(
                    f"Starting AI enrichment for {len(all_findings)} findings."
                )
                try:
                    enriched_findings = self.ai_builder.enrich_findings_batch(all_findings)
                    report.findings = enriched_findings
                except Exception as e:
                    logger.warning(f"AI enrichment failed (keeping raw findings): {e}")

            # ── 6. Finalise ───────────────────────────────────────────────────
            report.status = CBOMStatus.COMPLETE
            report.metadata = report.metadata.model_copy(
                update={"scan_duration_seconds": time.time() - start_time}
            )

            logger.success(
                f"Scan complete | findings={len(report.findings)} | "
                f"languages={[l.value for l in scanned_languages]} | "
                f"duration={report.metadata.scan_duration_seconds:.2f}s"
            )

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            report.status = CBOMStatus.FAILED
            report.error_message = str(e)

        return report