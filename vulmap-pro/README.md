# Vulmap Pro

A vulnerability scanner combining a **FastAPI** backend, a **React + Vite + Tailwind** frontend, and an **Nmap-powered** scanning engine. Discovered services are matched against the **NVD API** to surface known CVEs.

> ⚠️ **Security-first design.** The scanner enforces a strict target allowlist (loopback + RFC1918 by default), strict IP/CIDR validation as a command-injection guardrail, and pydantic-settings-based secret loading with `.env` files kept out of version control.

> 📝 **Project location.** This implementation lives under `D:\harness\vulmap-pro\` rather than `d:\vulmap pro\` so the development sandbox can write to it. The layout and filenames inside are unchanged from the original spec.

---

## Layout

```
vulmap-pro/
├── backend/              FastAPI app
│   ├── config.py         pydantic-settings config + allowlist validation
│   ├── main.py           entrypoint + CORS
│   ├── db/               SQLAlchemy models + session
│   ├── routes/           /scans, /hosts endpoints
│   ├── tests/            pytest suite (parser + matcher + target validation)
│   ├── Dockerfile
│   └── requirements.txt
├── scanner/              scan engine
│   ├── scanner.py        Nmap wrapper + XML parser (testable without Nmap)
│   ├── cve_matcher.py    normalization + CPE construction + NVD query + cache
│   └── models.py         dataclasses
├── frontend/             React + Vite + Tailwind
│   └── src/components/   Dashboard, ScanHistory, HostTable, SeverityBadge
├── docker-compose.yml
└── .gitignore
```

---

## Setup

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
cp .env.example .env            # then edit NVD_API_KEY etc.
```

### Frontend

```bash
cd frontend
npm install
npm run dev                     # http://localhost:5173
```

The Vite dev server proxies `/api/*` to the FastAPI backend on port 8000 (see `vite.config.ts`).

### Run backend

```bash
cd backend
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Visit http://localhost:8000/docs for the OpenAPI UI.

### Run tests

```bash
cd backend
pytest -q
```

---

## Security model

### Scanning scope

`backend/config.py` defines `Settings.allowed_networks()`. It always includes:

- `127.0.0.0/8` (loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC1918)

You can extend it with the `ALLOWED_TARGETS` env var (comma-separated CIDRs/IPs). Any target outside the resolved allowlist is rejected with HTTP 403 by `POST /scans`. The same check is enforced inside `scanner.scanner.run_scan` as a defense-in-depth guard before any subprocess invocation.

### Command-injection guardrail

`is_target_allowed(target)` validates that the string parses as an IP or CIDR via `ipaddress.ip_network/ip_address` before it is ever passed to the Nmap subprocess. Free-form text, shell metacharacters, and unresolved hostnames are rejected with `ValueError`.

### Secret handling

`pydantic-settings` loads `NVD_API_KEY`, `DB_URL`, `ALLOWED_TARGETS`, etc. from `.env`. The `.env` file is listed in `.gitignore` and the repo ships only `.env.example`.

---

## Architecture notes

### Scan state machine

`Scan.state` is one of `queued`, `running`, `completed`, `failed`, with explicit forward transitions enforced by `Scan.transition_to`. The frontend polls `GET /scans/{id}` every 2s while non-terminal and uses the state to decide whether to keep polling.

### CVE matching & known limitations

`scanner/cve_matcher.py` does three things:

1. **Normalization.** Distro/patch suffixes (`Ubuntu-4ubuntu0.5`, `5.7.33-0ubuntu0.16.04.1`, `p1`, `.el8`, …) are stripped, leaving the upstream numeric core (`8.2`, `2.4.41`, `5.7.33`).
2. **CPE construction.** Produces a primary CPE 2.3 URI plus a stripped-product fallback so `Apache httpd` and `apache` both get tried.
3. **NVD query.** Uses the v2.0 endpoint with `cpeName=...`, falling back to `apiKey` if provided.

> **CPE-matching accuracy.** Service-version strings from Nmap don't map cleanly to CPE identifiers. The same software can have multiple vendor/product spellings, and version strings often need normalization. False positives/negatives are expected. A demo host with "unknown" or unmatched CVEs is a realistic and defensible result.

### Caching

NVD responses are persisted in the `cpe_cache` table, keyed by CPE 2.3 URI. Default TTL is 7 days. The cache also acts as the **fallback path** when the NVD API is unreachable mid-scan: stale cache entries are served rather than failing the scan.

### Concurrency

The MVP supports concurrent scans by virtue of FastAPI's threadpool-backed `BackgroundTasks`. Each scan is its own subprocess; SQLite writes are isolated per session via `session_scope`.

---

## API surface

| Method | Path                                | Purpose                              |
| ------ | ----------------------------------- | ------------------------------------ |
| GET    | `/health`                           | Liveness check                       |
| POST   | `/scans`                            | Queue a new scan (body: `{target}`)  |
| GET    | `/scans`                            | List recent scans (summary)          |
| GET    | `/scans/{id}`                       | Scan detail + explicit state         |
| GET    | `/hosts?scan_id={n}`                | List hosts (optionally per scan)     |
| GET    | `/hosts/{id}/vulnerabilities`       | CVEs for one host                    |
| GET    | `/hosts/vulnerabilities?scan_id={n}`| All CVEs in a scan, sorted by CVSS    |

---

## Failure paths (manual verification)

The verification plan covers three scenarios — all of which the app handles gracefully:

1. **Target unreachable / down.** `POST /scans 127.0.0.1` against a host with no services → scan transitions to `completed` with 0 hosts, the UI shows *"Scan completed with 0 hosts"*.
2. **NVD unreachable / rate-limited.** Network failures on `requests.get` log a warning and return an empty CVE list per port; stale cache entries are served; the scan completes normally.
3. **Service with no CPE match.** Ports simply render *"no known CVEs"* in the `HostTable`. No crashes, no broken pages.

---

## Future work

- Optional PostgreSQL via `docker-compose.yml` (falls back to SQLite in dev).
- Per-user authentication and scan quotas.
- Active vs. passive service fingerprinting for trickier CPE matching.
- Continuous re-scan scheduling with diff reports.
