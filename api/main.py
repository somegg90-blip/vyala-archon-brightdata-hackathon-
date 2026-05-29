from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import scan
from dotenv import load_dotenv # <-- ADD THIS

# <-- ADD THIS LINE RIGHT HERE
load_dotenv() 

# Only define 'app' ONCE
app = FastAPI(
    title="Vyala Bright Data Agent",
    version="0.1.0",
    description="Post-Quantum Cryptography Supply Chain Threat Hunter"
)

# Allow Next.js frontend to communicate with this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Fine for the hackathon!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# ADD THIS ROOT ROUTE TO FIX THE 404
# ==========================================
@app.get("/")
def read_root():
    return {
        "status": "Vyala Archon Backend is alive!",
        "docs": "/docs"
    }
# ==========================================

app.include_router(scan.router, prefix="/api/scan", tags=["Scan"])