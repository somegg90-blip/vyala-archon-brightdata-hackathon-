# 🐯 Vyala Archon
### Autonomous Post-Quantum Cryptography Threat Intelligence Agent

> *"Quantum computers will break RSA. We find your exposure before they do."*

[![Built with Bright Data](https://img.shields.io/badge/Powered%20by-Bright%20Data-orange)](https://brightdata.com)
[![NIST PQC Compliant](https://img.shields.io/badge/NIST-PQC%20Compliant-blue)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## 🎯 What is Vyala Archon?

Vyala Archon is an **autonomous threat intelligence agent** that scans any company's public GitHub repositories for classical cryptographic vulnerabilities — RSA, ECDSA, AES-128 — and recommends **NIST-approved Post-Quantum Cryptography (PQC) replacements** before quantum computers make them obsolete.

You type a domain. Vyala does the rest.

```
stripe.com → 🔍 Hunt → 📥 Scrape → 🔬 Parse → 🤖 AI Enrich → 📋 CBOM Report
```

---

## ⚡ The Problem

| Algorithm | Quantum Attack | Status |
|-----------|---------------|--------|
| RSA-2048 | Shor's Algorithm | 💀 Broken |
| ECDSA / ECDH | Shor's Algorithm | 💀 Broken |
| AES-128 | Grover's Algorithm | ⚠️ Weakened |
| AES-256 | Grover's Algorithm | ✅ Safe |
| SHA-256 | Grover's Algorithm | ⚠️ Weakened |

The US Government (NSA CNSA 2.0) mandates migration away from classical asymmetric crypto **by 2030**. Most enterprises have no idea where their crypto debt is buried across hundreds of repositories.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     VYALA ARCHON                            │
│                                                             │
│  ┌──────────────┐    ┌─────────────────┐    ┌───────────┐  │
│  │  Bright Data │    │  Scanning Engine │    │  AI Pool  │  │
│  │              │    │                  │    │           │  │
│  │  SERP API    │───▶│  Tree-sitter AST │───▶│ 6 Models  │  │
│  │  Web Unlocker│    │  Dependency Parse│    │ 5 Accounts│  │
│  └──────────────┘    └─────────────────┘    └───────────┘  │
│         │                    │                    │         │
│         ▼                    ▼                    ▼         │
│    GitHub URLs          CryptoFindings       CBOM Report    │
│    Raw File DL          RSA/ECDSA/AES        PQC Guidance   │
└─────────────────────────────────────────────────────────────┘
```

**Flow:**
1. **Bright Data SERP API** → searches Google for target company's GitHub repos
2. **Bright Data Web Unlocker** → downloads raw source + dependency files (bypasses bot detection, CAPTCHAs, rate limits)
3. **Tree-sitter parsers** → AST-level scan of `.py`, `.js`, `.java`, `.go` source files
4. **DependencyParser** → regex scan of `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, `Cargo.toml`, etc.
5. **Multi-Tier LLM Pool** → 6 models across 5 OpenRouter accounts enrich each finding with PQC recommendations
6. **CBOM Report** → structured Crypto Bill of Materials output

---

## 🛡️ What It Detects

### Source Code (Tree-sitter AST)
- Python: `rsa`, `cryptography`, `pycryptodome`, `ecdsa`, `pyopenssl`
- JavaScript: `node-rsa`, `elliptic`, `node-forge`, `jsencrypt`
- Java: Bouncy Castle, JCE RSA/EC usage
- Go: `crypto/rsa`, `crypto/ecdsa`, `golang.org/x/crypto`

### Dependency Files (DependencyParser)
- `requirements.txt` / `pyproject.toml` / `setup.cfg`
- `package.json` / `yarn.lock` / `package-lock.json`
- `pom.xml` / `build.gradle` / `gradle/libs.versions.toml`
- `go.mod` / `Cargo.toml` / `composer.json`

### PQC Replacements Recommended (NIST Standards)
| Classical | Quantum Attack | NIST Replacement |
|-----------|---------------|-----------------|
| RSA (key exchange) | Shor | ML-KEM-768 / CRYSTALS-Kyber (FIPS 203) |
| ECDSA (signatures) | Shor | ML-DSA-65 / Dilithium (FIPS 204) |
| RSA (signatures) | Shor | SLH-DSA / SPHINCS+ (FIPS 205) |
| AES-128 | Grover | AES-256 upgrade |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ (for frontend)
- Bright Data account ([sign up](https://brightdata.com))
- OpenRouter account ([sign up](https://openrouter.ai))

### Backend Setup

```bash
git clone https://github.com/YOUR_USERNAME/vyala-archon
cd vyala-archon

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your credentials (see Environment Variables section)

# Run the API
uvicorn api.main:app --reload --port 8000
```

### Frontend Setup

```bash
cd frontend   # or wherever your Next.js app lives
npm install
npm run dev   # runs on http://localhost:3000
```

### Test with Mock Mode (zero credits)

```bash
# In .env, set:
MOCK_WEB=true

# Then invoke a scan — generates synthetic crypto findings locally
```

---

## 🌍 Bright Data Integration

Bright Data is the **core infrastructure** of Vyala Archon — not optional.

| Bright Data Product | How Vyala Uses It |
|--------------------|------------------|
| **SERP API** | Searches Google `site:github.com/{company}` to discover repos containing crypto code |
| **Web Unlocker** | Downloads raw source files from `raw.githubusercontent.com` bypassing GitHub rate limits and bot detection |
| **MCP Client** | Fetches live NIST documentation to ground AI recommendations in real standards |

Without Bright Data:
- GitHub blocks automated scraping after ~60 requests/hour
- Google blocks search automation without residential proxies
- The agent cannot discover or download target files at all

---

## 📁 Project Structure

```
vyala-archon/
├── api/
│   ├── main.py              # FastAPI app entry point
│   ├── routes/              # API route handlers
│   └── schemas.py           # Request/response schemas
├── core/
│   ├── models/
│   │   └── cbom.py          # Pydantic v2 CBOM data models
│   ├── parsers/
│   │   ├── base_parser.py   # Abstract base + file walking utilities
│   │   ├── python_parser.py
│   │   ├── js_parser.py
│   │   ├── java_parser.py
│   │   ├── go_parser.py
│   │   ├── csharp_parser.py
│   │   └── dependency_parser.py  # Manifest file scanner
│   ├── ai/
│   │   ├── context_builder.py    # Multi-tier LLM pool
│   │   ├── analyzer.py
│   │   └── prompt_templates.py
│   └── scanner.py           # VyalaEngine orchestrator
├── web/
│   ├── hunter.py            # Bright Data SERP + Web Unlocker
│   ├── mcp_client.py        # Web-grounded RAG for PQC context
│   └── supply_chain.py
├── frontend/                # Next.js dashboard
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## 🔐 Environment Variables

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

See `.env.example` for all required variables with descriptions.

---

## 📊 CBOM Report Schema

Every scan produces a **Crypto Bill of Materials** following emerging CBOM standards:

```json
{
  "report_id": "uuid-v4",
  "project_name": "stripe.com",
  "status": "COMPLETE",
  "total_findings": 7,
  "quantum_vulnerable_count": 6,
  "critical_findings_count": 3,
  "algorithms_detected": ["RSA/EC", "AES-128", "ECDSA"],
  "severity_breakdown": {
    "CRITICAL": 3, "HIGH": 2, "MEDIUM": 2, "LOW": 0
  },
  "findings": [
    {
      "algorithm_detected": "RSA/EC (golang.org/x/crypto)",
      "severity": "CRITICAL",
      "vulnerability_class": "SHOR_VULNERABLE",
      "pqc_recommendation": {
        "primary_algorithm": "ML-KEM-768 (CRYSTALS-Kyber)",
        "nist_reference": "FIPS 203",
        "hybrid_transition_recommended": true
      },
      "migration_complexity": "HIGH"
    }
  ]
}
```

---

## 🏆 Hackathon

Built for the **Bright Data Web Data UNLOCKED Hackathon** (May 25–30, 2026).

**Track:** Security & Compliance

**Bright Data products used:** SERP API, Web Unlocker

---

## 📜 License

MIT — see [LICENSE](LICENSE)

---

## 🔗 References

- [NIST FIPS 203 — ML-KEM (CRYSTALS-Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA (SPHINCS+)](https://csrc.nist.gov/pubs/fips/205/final)
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [Bright Data Documentation](https://docs.brightdata.com)
