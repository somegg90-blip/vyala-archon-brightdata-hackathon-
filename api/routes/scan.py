from asyncio.log import logger
import shutil
import tempfile
from core.models.cbom import CBOMReport, CBOMStatus, ScanMetadata
from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from core.scanner import VyalaEngine
import os
from web.hunter import BrightDataHunter

router = APIRouter()


class ScanRequest(BaseModel):
    target: str              # e.g., "test_target" or "stripe.com"
    scan_type: str = "local" # "local" | "web"


@router.post("/domain", status_code=200)
async def scan_domain(request: ScanRequest):
    """
    Endpoint to trigger the Vyala Agent.
    Mode 'local': Scans a local folder in the repo (Dry Run).
    Mode 'web':   Uses Bright Data to hunt the open web (Uses Credits!).
    """
    engine = VyalaEngine()

    if request.scan_type == "local":
        # ── DRY RUN MODE ──────────────────────────────
        # Assumes you have a folder named request.target in your root directory
        scan_path = os.path.abspath(request.target)

        if not os.path.exists(scan_path):
            raise HTTPException(
                status_code=404,
                detail=f"Local folder '{request.target}' not found."
            )

        report = engine.scan_local_target(request.target, scan_path)
        return report.model_dump()

    elif request.scan_type == "web":
        # ── LIVE BRIGHT DATA MODE ─────────────────────
        hunter = BrightDataHunter()
        temp_dir = hunter.discover_and_extract(request.target)

        try:
            if not os.listdir(temp_dir):
                logger.warning(f"No web dependencies found for {request.target}")
                metadata = ScanMetadata(
                    project_name=request.target,
                    scan_root="web_scan",
                    scanned_by="vyala-brightdata/0.1.0"
                )
                empty_report = CBOMReport(
                    project_name=request.target,
                    metadata=metadata,
                    status=CBOMStatus.COMPLETE,
                    error_message="No external dependencies found on the open web."
                )
                return empty_report.model_dump()

            report = engine.scan_local_target(request.target, temp_dir)
            return report.model_dump()

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scan_type '{request.scan_type}'. Use 'local' or 'web'."
        )


@router.post("/upload", status_code=200)
async def scan_uploaded_file(file: UploadFile = File(...)):
    """
    Accepts a single source file uploaded from the browser.
    Writes it to a secure temp directory, scans it, then cleans up.
    """
    engine = VyalaEngine()

    with tempfile.TemporaryDirectory() as temp_dir:
        safe_name = os.path.basename(file.filename or "uploaded_file")
        file_path = os.path.join(temp_dir, safe_name)

        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)

        report = engine.scan_local_target(safe_name, temp_dir)
        return report.model_dump()