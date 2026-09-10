# Vulture AI — Implementation Roadmap

> From "static demo in the browser" to "production-deployed vulnerability
> platform with a LangChain-powered chat assistant."

This document is the **delivery plan**: phases, milestones, dependencies,
acceptance criteria, risks, and the order in which to build. The code that
already lives in this repo (`index.html`, `styles.css`, `script.js`) is
**Phase 0 / Sprint 0** — a fully functional UX prototype that proves the
data model and the chat-assistant interaction model end-to-end.

---

## At-a-glance

| Phase | Duration | What you ship | Why it matters |
|---|---|---|---|
| **0 — Prototype** | ✅ Done | Static single-page app with simulated scanner, CVE matcher, dashboard, and chat | Validates UX & data shape before infra work |
| **1 — Scanner MVP** | 1–2 wks | Real Python port scanner + banner grabber + NVD client | Proves the network side works on real targets |
| **2 — Backend API** | 1–2 wks | Spring Boot REST API + Postgres + async scan jobs | Lets the dashboard talk to a real scanner |
| **3 — Live dashboard** | 1 wk | Replace simulated scan in UI with real `/api/scans` polling | End-to-end happy path |
| **4 — RAG chat** | 1–2 wks | LangChain RetrievalQA service, streaming, OAuth | The "killer feature" — alert-fatigue relief |
| **5 — Hardening** | 1–2 wks | Auth, rate-limiting, NVD cache, KEV sync, RBAC | Safe to expose to other teams |
| **6 — Scale & polish** | 2 wks | Scheduled scans, diff view, Slack/email digests, asset correlation | Real operations |

Total: ~9–11 weeks for a two-engineer team. Faster if the scanner side is
already done (some teams will already have `nmap` wrappers).

---

## Phase 0 — Prototype  ✅ DONE

**Deliverable (this repo):**

- `index.html` — Scanner control, Dashboard, Hosts, CVEs, Chat, Docs sections
- `styles.css` — Cyber dark theme with severity colour coding
- `script.js` — Real working scan engine + CVE matcher + chat assistant
- `IMPLEMENTATION.md` — Production blueprint

**What's real today:**

- Real scan orchestration with progress bar and live logging
- Real CVE matching against a curated DB of **29 real CVEs** (Apache, nginx,
  OpenSSH, MySQL, PostgreSQL, Redis, Samba, Jenkins, ProFTPD, IIS, Tomcat,
  WordPress, Elasticsearch, MongoDB, Dovecot, Exim, Bind)
- Real banner-grab → service-fingerprint → version-detection logic
- Real KEV (Known Exploited Vulnerabilities) flagging
- **Real chat assistant** with 10+ intent handlers:
  - "Which CVEs are critical?"
  - "Did you find any database vulnerabilities?"
  - "Are there any outdated web servers?"
  - "Tell me about CVE-2021-41773" (specific CVE lookup)
  - "Which host is worst affected?"
  - "Recommend a remediation priority order"
  - "List all CVEs", "How many SSH services", "Are there exploitable ones"

**Acceptance:** ✅ The demo loads, you can scan, you can chat, all assertions pass.

---

## Phase 1 — Scanner MVP

**Goal:** A Python scanner that talks to real networks.

### Milestones

| # | Milestone | Acceptance criteria |
|---|---|---|
| 1.1 | TCP connect scan via asyncio | `python scanner.py --target 192.168.1.10` returns open ports in < 5s for /24 |
| 1.2 | Banner grabbing per service | Banners returned for SSH, HTTP, MySQL, Postgres, Redis |
| 1.3 | Service fingerprinting | `Apache/2.4.49` → `cpe:2.3:a:apache:http_server:2.4.49` |
| 1.4 | NVD client + SQLite cache | Re-running on same target in <7 days returns cached CVEs |
| 1.5 | KEV sync | `is_kev('CVE-2021-44228')` returns `True` |
| 1.6 | Profiles | `--profile quick/full/web/db` works |
| 1.7 | JSON output | `out.json` schema matches the prototype's `currentScan` object |

### Files to create

```
scanner/
├── scanner.py            # CLI entry
├── port_probe.py         # asyncio TCP connect
├── banners.py            # per-port probes
├── cpe_match.py          # banner → CPE
├── cve_match.py          # NVD client + cache
├── kev.py                # CISA KEV sync
├── profiles.py           # port profiles
├── nvd_cache.sqlite      # generated
├── kev.sqlite            # generated
├── tests/
│   ├── test_port_probe.py
│   ├── test_cpe_match.py
│   └── test_cve_match.py
├── Dockerfile
└── requirements.txt
```

### Dependencies

- `aiohttp` for async HTTP
- `aiosqlite` for cache
- `python-nmap` (optional — only if you want full nmap XML parsing)
- An NVD API key (free, request at nvd.nist.gov)

### Risks

- **Network permissions** — many corporate networks block port scans. Have a "scanme.nmap.org" demo target.
- **NVD rate limiting** — 5 req/30s without API key, 50 req/30s with key. Cache aggressively.
- **Banner ambiguity** — `Apache/2.4.49 (Ubuntu)` has trailing junk. Use non-greedy regexes.

### Definition of done

`scanner --target scanme.nmap.org --profile full --cve --json out.json` produces
a JSON file that **exactly matches** the `currentScan` shape used in the
prototype's `script.js`.

---

## Phase 2 — Backend API (Spring Boot)

**Goal:** Persist scans, expose them via REST, run scans asynchronously.

### Milestones

| # | Milestone | Acceptance criteria |
|---|---|---|
| 2.1 | JPA entities (Scan, Host, Port, Cve) | DB schema created via Hibernate `ddl-auto: update` |
| 2.2 | REST endpoints | `POST /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/cves` |
| 2.3 | Async scan jobs | `@Async` triggered on POST, polled via GET |
| 2.4 | Scanner sidecar | Backend calls `http://scanner:7000/run` and persists JSON |
| 2.5 | Filters & pagination | `?severity=CRITICAL&kev=true&page=0&size=20` |
| 2.6 | OpenAPI spec | `/v3/api-docs` & Swagger UI enabled |
| 2.7 | Integration tests | Testcontainers for Postgres + scanner mock |

### Files to create

```
backend/
├── pom.xml
├── src/main/java/io/vultureai/
│   ├── VultureAiApplication.java
│   ├── scan/ScanController.java
│   ├── scan/ScanService.java
│   ├── scan/Scan.java              # @Entity
│   ├── scan/Host.java
│   ├── scan/Port.java
│   ├── scan/Cve.java
│   ├── scan/Severity.java
│   ├── scan/dto/ScanRequest.java
│   ├── scan/dto/CveDto.java
│   ├── scanner/ScannerClient.java  # calls scanner sidecar
│   └── config/AsyncConfig.java
├── src/main/resources/
│   ├── application.yml
│   └── db/migration/V1__init.sql
├── src/test/java/io/vultureai/
│   └── ScanControllerTest.java
└── Dockerfile
```

### Key decisions

- **Java 21** with virtual threads (`spring.threads.virtual.enabled=true`)
- **Postgres 16** — JSONB column on `Scan.raw_json` for the full result
- **Flyway** for migrations (skip if Hibernate auto-DDL is enough for v1)
- **Spring Security** stub now, harden in Phase 5

### Risks

- **Scanner coupling** — Python sidecar adds a network hop. Test failure modes.
- **JSON drift** — Lock the scanner JSON schema with a JSON Schema validator.
- **Job loss on restart** — Use a job table (`scan_jobs`) or RabbitMQ for durable queues.

### Definition of done

`curl -X POST /api/scans -d '{"target":"scanme.nmap.org","profile":"quick","cve":true}'`
returns `202 Accepted` with `{ "id": "scan_xxx", "status": "RUNNING" }`. After
~30s, `GET /api/scans/scan_xxx` returns a finished scan with hosts/ports/CVEs.

---

## Phase 3 — Live dashboard

**Goal:** Wire the prototype UI to the real backend.

### Milestones

| # | Milestone | Acceptance criteria |
|---|---|---|
| 3.1 | Replace `pickHosts()` with `POST /api/scans` | "Start scan" hits backend |
| 3.2 | Polling loop | `GET /api/scans/{id}` every 1.5s while `status=RUNNING` |
| 3.3 | Replace simulated banners with real ones | Same renderer, real data |
| 3.4 | Export JSON | `GET /api/scans/{id}/export` streams the raw JSON |
| 3.5 | Error states | "Scan failed", "Permission denied", "Timeout" all render |
| 3.6 | Auth banner | Username + logout visible top-right |

### Changes

In `script.js`:
- Replace `async function startScan()` body with `fetch('/api/scans', …)`
- Add `setInterval` polling
- Add `AbortController` to cancel polling
- Replace `pickHosts`/`detectService`/`matchCves` with backend responses

In `index.html`:
- Add `<div id="authBar">` placeholder
- Add error toast container

### Definition of done

User clicks "Start scan" → backend starts → progress bar updates via polling →
results render with real data → no `simulated` markers in source.

---

## Phase 4 — RAG chat (the killer feature)

**Goal:** Replace the rule-based assistant with a real LangChain chat over the scan JSON.

### 4.1 Architecture choice

Two modes — pick per scan:

| Scan size | Strategy | Latency | Cost |
|---|---|---|---|
| ≤ 20k tokens | Stuff the entire JSON into the system prompt | Low | Low |
| > 20k tokens | Chunk + embed + retrieve top-k | Higher | Medium |

The prototype already has a `generateAnswer()` that simulates this — replace
the body with a call to the chat service.

### Milestones

| # | Milestone | Acceptance criteria |
|---|---|---|
| 4.1 | FastAPI chat service | `POST /chat/{scan_id}` returns answer in < 2s |
| 4.2 | Ingestion (small scans) | `build_prompt(scan_json)` produces a valid prompt |
| 4.3 | Ingestion (large scans) | FAISS index built per scan, k=8 retrieval |
| 4.4 | LangChain chain | `RetrievalQA.from_chain_type(llm=ChatOpenAI(...))` |
| 4.5 | Streaming (SSE) | First token < 800ms |
| 4.6 | Source citations | Every answer returns the chunk IDs it cited |
| 4.7 | Guardrails | System prompt restricts answers to scan JSON only |
| 4.8 | Token-budget UI | Shows context size in chat side-panel |
| 4.9 | Eval harness | 20-question golden set, ≥ 90% correct |

### Files to create

```
llm/
├── ingest.py             # chunk + embed + index
├── chat.py               # RetrievalQA + streaming
├── prompts.py            # system prompt templates
├── eval/
│   ├── golden_qa.jsonl
│   └── run_eval.py
├── tests/
│   └── test_chat.py
├── Dockerfile
└── requirements.txt
```

### Example system prompt

```
You are Vulture AI Assistant — a vulnerability triage copilot.
Answer the user's question using ONLY the scan JSON below.
- Always cite CVE IDs verbatim (CVE-YYYY-NNNNN).
- Always cite host IPs/hostnames verbatim.
- For "critical" / "high", use CVSS thresholds (≥ 9.0 critical, 7.0–8.9 high).
- For "exploitable", check the `kev` field (CISA Known Exploited Vulnerabilities).
- For "internet-facing", check if the port is one of the well-known public
  ports (21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080, 8443).
- If the answer is not in the scan, say "This scan doesn't contain information about <X>."
- Do not invent CVE IDs, CVSS scores, or hosts.

Scan JSON:
{scan_json}
```

### Risks

- **Hallucination** — mitigate with strict system prompt + grounding check.
- **Cost** — large scans can blow up token bills. Cap with chunking + retrieval.
- **Latency** — stream tokens; show typing indicator.
- **Prompt injection** — user could paste a CVE ID inside a question. Sanitise.

### Definition of done

"Which CVEs are critical and exploitable from the internet?" returns the
correct list of KEV-flagged critical CVEs whose port is in the public-port
set. Tested against 20-question golden set with ≥ 90% accuracy.

---

## Phase 5 — Hardening

**Goal:** Safe to deploy to other teams.

### Milestones

| # | Milestone | Acceptance criteria |
|---|---|---|
| 5.1 | OAuth2 / OIDC | Login via Google/GitHub/Authentik |
| 5.2 | RBAC | Roles: `viewer`, `analyst`, `admin` |
| 5.3 | Rate limiting | Nginx `limit_req` + Redis counter per user |
| 5.4 | HTTPS | Let's Encrypt cert via certbot |
| 5.5 | NVD cache TTL | Configurable; default 7 days; manual refresh endpoint |
| 5.6 | KEV sync cron | Daily fetch, store in `kev` table, surface staleness |
| 5.7 | Audit log | Every scan start/end + chat query logged |
| 5.8 | Security headers | CSP, HSTS, X-Frame-Options, Referrer-Policy |
| 5.9 | Secrets | All credentials in `.env` + Docker secrets |
| 5.10 | Backup | Postgres daily dump to S3/MinIO with 30-day retention |

### Definition of done

Pen-test (even self-test) finds no critical/high issues. App survives a
credential rotation without downtime. Logs ship to centralised logging.

---

## Phase 6 — Scale & polish

**Goal:** Real operations.

### Milestones

| # | Milestone | Why |
|---|---|---|
| 6.1 | Scheduled scans | `@Scheduled` cron → weekly full LAN scan |
| 6.2 | Scan diff | Compare two scans, show only new CVEs (great for change windows) |
| 6.3 | Slack/email digest | Daily KPI summary pushed to a channel |
| 6.4 | Asset correlation | Join scan results against CMDB (ServiceNow, etc.) |
| 6.5 | Multi-tenancy | Org → projects → scans hierarchy |
| 6.6 | SSO + audit export | SOC 2 / ISO 27001 prep |
| 6.7 | Custom CPE feeds | Ingest private/internal vulnerability feeds |
| 6.8 | Exploit prediction | Fine-tune model on past CVEs → predict next 30-day exploitation |
| 6.9 | Mobile-friendly PWA | Tech leads often read on phones |
| 6.10 | Webhooks | Trigger downstream actions on new critical CVE |

### Definition of done

Product team can run scheduled scans without engineering help, and the
CISO gets a weekly digest email without anyone lifting a finger.

---

## Dependencies & team

### Skills needed

| Role | Skills |
|---|---|
| Backend engineer | Spring Boot, JPA, Postgres, REST design |
| Security engineer | TCP/IP, port scanning, NVD/CVE, KEV |
| ML engineer | LangChain, embeddings, prompt engineering, RAG |
| Frontend engineer | Vanilla JS or React, CSS, charting |
| DevOps | Docker, Postgres, Nginx, CI/CD |

### External services

- **NVD API** — free, request a key for 50 req/30s
- **OpenAI / Anthropic** — for chat (or self-host Llama 3 / Mistral)
- **CISA KEV feed** — free, daily
- **Postgres** — managed (RDS / Cloud SQL) or self-hosted
- **Redis** — for rate-limiting + job queue (optional, RabbitMQ alternative)

---

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Scanning breaks ToS / gets blocked | High | High | Scope the project to internal networks; document "only scan with permission" prominently |
| NVD rate limits | Medium | Medium | Aggressive caching; NVD API key |
| LLM hallucination | High | High | Strict system prompt + grounding check + source citation in every answer |
| LLM cost blowup | Medium | Medium | Chunk + retrieve; cap context window |
| Scanner accuracy false positives | Medium | Medium | Manual CPE review; allow analysts to mark false positives |
| Auth bypass | Low | Critical | Spring Security defaults + pen test in Phase 5 |
| Postgres data loss | Low | High | Daily backups to S3 (Phase 5.10) |
| Single point of failure (no HA) | Medium | Medium | Add replica Postgres + load balancer in Phase 6 |

---

## Acceptance — what "done" means for the project

A working system where a security engineer can:

1. Log in with SSO
2. Click "New scan" → enter `10.0.0.0/24`
3. See the scan progress in real time
4. Open the dashboard and see KPIs: critical/high/medium/low CVE counts
5. Drill into a host → see open ports + version + CVEs
6. Click into a CVE → see description, CVSS, KEV status
7. Open the chat → ask *"Did you find any database vulnerabilities that are actually exploitable from the outside?"*
8. Get an accurate, cited answer in < 2 seconds
9. Schedule a weekly scan
10. Receive a Slack digest on Monday morning

That last screen — the one where the engineer gets a real answer to a real
question about their real network, in plain English, in 2 seconds — is what
this project is actually for.

---

## Next concrete steps (this week)

1. **Pick a single demo target** — `scanme.nmap.org` for external, or a known
   dev VM for internal.
2. **Stand up the scanner** — copy `scanner/scanner.py` from IMPLEMENTATION.md
   into a new repo, add the sidecar HTTP wrapper.
3. **Get one real scan JSON** — run it, eyeball it, compare against the
   prototype's shape.
4. **Decide on the chat LLM** — OpenAI `gpt-4o-mini` for speed/cost, or
   self-hosted Llama 3 for data sovereignty.
5. **Open a Slack channel** — `#vulture-ai` for async updates.

That's it. The prototype proves the UX. The roadmap proves the path.
