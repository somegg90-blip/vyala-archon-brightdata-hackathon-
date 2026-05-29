from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import scan
from dotenv import load_dotenv # <-- ADD THIS

# <-- ADD THIS LINE RIGHT HERE
load_dotenv() 

app = FastAPI(
    title="Vyala Bright Data Agent",
    version="0.1.0",
    description="Post-Quantum Cryptography Supply Chain Threat Hunter"
)

app = FastAPI(
    title="Vyala Bright Data Agent",
    version="0.1.0",
    description="Post-Quantum Cryptography Supply Chain Threat Hunter"
)

# Allow Next.js frontend to communicate with this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to your Vercel URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router, prefix="/api/scan", tags=["Scan"])