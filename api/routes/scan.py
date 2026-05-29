from asyncio.log import logger
import shutil

from core.models.cbom import CBOMReport, CBOMStatus, ScanMetadata
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from core.scanner import VyalaEngine
import os

from web.hunter import BrightDataHunter

router = APIRouter()

class ScanRequest(BaseModel):
    target: str             # e.g., "test_target" or "stripe.com"
    scan_type: str = "local" # "local" for testing, "web" for Bright Data

@router.post("/domain", status_code=200)
async def scan_domain(request: ScanRequest):
    """
    Endpoint to trigger the Vyala Agent.
    Mode 'local': Scans a local folder in the repo (Dry Run).
    Mode 'web': Uses Bright Data to hunt the open web (Uses Credits!).
    """
    engine = VyalaEngine()
    
    if request.scan_type == "local":
        # ── DRY RUN MODE ──────────────────────────────
        # Assumes you have a folder named request.target in your root directory
        scan_path = os.path.abspath(request.target)
        
        if not os.path.exists(scan_path):
            raise HTTPException(status_code=404, detail=f"Local folder '{request.target}' not found.")
            
        report = engine.scan_local_target(request.target, scan_path)
        return report.model_dump()
        
    elif request.scan_type == "web":
        # ── LIVE BRIGHT DATA MODE ─────────────────────
        hunter = BrightDataHunter()
        temp_dir = hunter.discover_and_extract(request.target)
        
        try:
            # Check if we actually found any files
            if not os.listdir(temp_dir):
                 logger.warning(f"No web dependencies found for {request.target}")
                 # Return a clean, empty CBOM report instead of a 404 error!
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