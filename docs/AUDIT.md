# Vulture-AI Repository Audit

## 1. Repository File Tree
```
.
├── app.py
├── banner.py
├── chatbot
│   ├── LLM_DECISION.md
│   ├── requirements.txt
│   ├── test_results.md
│   └── vulture_chatbot.py
├── Dockerfile
├── IMPLEMENTATION.md
├── index.html
├── main.py
├── README.md
├── RENDER.md
├── render.yaml
├── requirements.txt
├── ROADMAP.md
├── scannner.py
├── scan_results.json
├── script.js
├── services.py
├── static
│   ├── assets
│   │   ├── index-8Qd0ELNU.css
│   │   └── index-C-gE9_I9.js
│   ├── index.html
│   ├── script.js
│   ├── style.css
│   ├── styles.css
│   └── vulture-logo.jpg
├── styles.css
├── test_server.py
├── vulmap-pro
│   ├── backend
│   │   ├── config.py
│   │   ├── db
│   │   ├── Dockerfile
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── requirements.txt
│   │   ├── routes
│   │   ├── scan_results.json
│   │   ├── tests
│   │   └── vulture_chatbot.py
│   ├── banner.py
│   ├── docker-compose.yml
│   ├── frontend
│   │   ├── Dockerfile
│   │   ├── index.html
│   │   ├── package.json
│   │   ├── package-lock.json
│   │   ├── postcss.config.js
│   │   ├── public
│   │   ├── src
│   │   ├── tailwind.config.js
│   │   ├── tsconfig.json
│   │   ├── tsconfig.node.json
│   │   ├── vite.config.d.ts
│   │   ├── vite.config.js
│   │   └── vite.config.ts
│   ├── main.py
│   ├── README.md
│   ├── scanner
│   │   ├── cve_matcher.py
│   │   ├── __init__.py
│   │   ├── models.py
│   │   └── scanner.py
│   ├── scannner.py
│   ├── services.py
│   └── test_server.py
└── vulture_chatbot.py
```

## 2. Python Files Analysis
- **`app.py`**: Legacy Flask backend serving the React SPA. Key functions: `create_scan_entry()`, `api_scans()`, `api_chat()`. **Status: MOCK/SIMULATED** (`create_scan_entry` generates dummy data via `SERVICE_CATALOG`).
- **`banner.py`**: Grabs TCP banners and detects software versions. Key functions: `grab_banner()`, `detect_software_version()`. **Status: REAL**.
- **`main.py`**: CLI script connecting to `banner.py` to scan ports on a given target. Key functions: `scan_port()`. **Status: REAL**.
- **`scannner.py`**: Minimal helper file containing `create_result(port, service, banner, software, version)` for structuring data. **Status: REAL** (structuring function only).
- **`services.py`**: Dictionary of common ports mapping to service names. **Status: MOCK/STATIC** (hard-coded dictionary `SERVICES`).
- **`vulture_chatbot.py`** (exists in root, `/chatbot`, and `/vulmap-pro/backend`): Uses LiteLLM to respond to scan-related queries. Key functions: `ensure_sample_scan_data()`, `chat()`, `analyze()`. **Status: SIMULATED** (creates and uses `scan_results.json` containing 3 mock vulnerabilities).
- **`vulmap-pro/backend/main.py`**: New FastAPI backend entrypoint defining CORS and mounting routers. **Status: REAL**.
- **`vulmap-pro/backend/config.py`**: Application configuration via `pydantic-settings` containing DB URL and NVD API settings. **Status: REAL**.
- **`vulmap-pro/backend/routes/scans.py`**: Scan endpoints initiating background `nmap` tasks. Key functions: `create_scan()`, `_execute_scan_task()`. **Status: REAL** (attempts to execute actual Nmap scan).
- **`vulmap-pro/backend/routes/chat.py`**: Chat endpoint for FastAPI backend. **Status: SIMULATED/MOCK FALLBACK** (contains a `DEFAULT_SCAN` dictionary with 3 mock CVEs and returns a hard-coded generic response if LiteLLM fails).
- **`vulmap-pro/backend/db/models.py`**: SQLAlchemy ORM classes (`Scan`, `Host`, `Port`, `Vulnerability`, `CPECache`). **Status: REAL**.
- **`vulmap-pro/backend/tests/*.py`**: Unit tests for FastAPI backend (CVE matching, Nmap parsing). **Status: MOCK** (mocked network responses via fake `requests.Session`).

## 3. Template/Static Files Analysis
- **`index.html`** / **`static/index.html`**: The UI for the Vulture AI dashboard. Displays scanning progress and data tables. **Displays SIMULATED findings** (driven by JavaScript logic).
- **`script.js`** / **`static/script.js`**: Frontend logic. Contains vast amounts of hard-coded data (`CVE_DB`, `SIM_NET`, `HOST_PORTS`) and simulates a network scan deterministically. **Displays entirely SIMULATED findings** presented as real scanning actions.

## 4. Hard-Coded / Mocked Vulnerabilities List
- **`script.js`**: Contains a curated `CVE_DB` of 29 real CVE IDs (e.g. `CVE-2021-41773`, `CVE-2022-22965`) matched deterministically against a mocked `SIM_NET` of 10 IPs (e.g., `192.168.1.10`) with `HOST_PORTS` mapping open ports and fake banners.
- **`app.py`**: Contains `SERVICE_CATALOG` with 10 hard-coded CVEs (`CVE-2021-41773`, `CVE-2021-23017`, `CVE-2018-15473`, etc.). Generates "scans" via deterministic IP hashing.
- **`scan_results.json`** / **`vulmap-pro/backend/scan_results.json`**: Contains exactly 3 mocked findings: `VULN-001` (CVE-2023-34362), `VULN-002` (CVE-2024-21413), and `VULN-003` (N/A).
- **`vulture_chatbot.py`**: Generates `scan_results.json` dynamically with the exact 3 findings listed above via `ensure_sample_scan_data()`.
- **`vulmap-pro/backend/routes/chat.py`**: Hard-codes a fallback `DEFAULT_SCAN` identical to the 3 findings from `scan_results.json`. Returns a hard-coded AI string response if exceptions occur.

## 5. Dependencies
From `requirements.txt` (root):
- `litellm>=1.50`
- `flask>=3.0`
- `flask-cors`

From `vulmap-pro/backend/requirements.txt`:
- `fastapi==0.115.0`
- `uvicorn[standard]==0.30.6`
- `sqlalchemy==2.0.36`
- `pydantic==2.9.2`
- `pydantic-settings==2.5.2`
- `python-nmap==0.7.1`
- `requests==2.32.3`
- `python-dotenv==1.0.1`
- `pytest==8.3.3`
- `litellm`

## 6. Python and Flask Version
- **Python version**: 3.14.7
- **Flask version**: 3.1.3

## 7. Tests Status
Executed via `pytest tests/` inside `/vulmap-pro/backend`:
- 19 test items collected.
- **Result**: 1 failed, 18 passed.
- **Failing test**: `tests/test_nmap_parser.py::test_xml_without_target_argument_still_parses` (AssertionError: `assert '' == '10.0.0.5'`).

## 8. Simulated Data Flagging
**FLAG:** Multiple files display simulated data to users as if it were real.
- **`script.js` / `index.html`**: The UI animates a progress bar and outputs console-like messages (`Probing 192.168.1.10...`) giving the illusion of a live scan, but actually loads deterministic mock data from `SIM_NET` and `HOST_PORTS`.
- **`app.py`**: The `POST /api/scans` endpoint appears to process targets but immediately returns deterministic mock entries generated by `create_scan_entry()`.

## 9. Migration Risks (Renaming `scannner.py` -> `scanner.py`)
- `scannner.py` currently only defines `create_result(port, service, banner, software, version)`. None of the analyzed files in the root directly `import scannner`. 
- **Major Risk**: However, the new backend (`vulmap-pro/backend/routes/scans.py`) imports a package named `scanner`:
  - `from scanner import cve_matcher`
  - `from scanner.scanner import run_scan`
  There is already a `scanner` directory inside `vulmap-pro/` which represents this package (`vulmap-pro/scanner`).
- Renaming the root `scannner.py` to `scanner.py` will introduce a namespace conflict with the existing `vulmap-pro/scanner` package structure, potentially causing `ModuleNotFoundError` or unexpected shadowing when Python attempts to resolve imports.
