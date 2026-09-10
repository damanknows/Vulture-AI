# Vulture AI — Implementation Path

> A vulnerability scanner + dashboard with an interactive **"Chat with your scan"** assistant.
> This document is the production blueprint — the rest of the repo is a working demo.

---

## TL;DR

```
Scanner (Python/Java)  →  Spring Boot API  →  Dashboard UI  +  LangChain chat
        │                       │                    │
        ▼                       ▼                    ▼
   Open ports +          PostgreSQL         KPIs / hosts / CVEs
   banners + CVEs        + scan jobs        + chat assistant
```

The whole stack is **stateless front-end** + **REST API** + **background scan
workers**. Each piece is independently deployable, and the chat is a standard
RAG (Retrieval Augmented Generation) pipeline so the LLM never hallucinates
about findings it hasn't seen.

---

## 1. Scanner (`scanner/`)

A port-and-banner scanner that runs against one host, a CIDR, or a list.

### 1.1. Tech choices

| Approach | Language | Pros | Cons |
|---|---|---|---|
| Pure sockets | Python | Zero deps, easy to read | Slower, no SYN scan |
| `python-nmap` | Python | Wraps nmap → full power | Requires nmap binary |
| Java NIO | Java | Fast, integrates with backend | More boilerplate |
| `masscan` shim | Any | Fastest port scan | Banner grab separate |

**Recommended:** `python-nmap` for accuracy + a pure-socket fallback for
environments without nmap.

### 1.2. File layout

```
scanner/
├── scanner.py          # main entry: --target --profile --cve --json out.json
├── port_probe.py       # TCP connect scans (concurrent via asyncio)
├── banners.py          # banner grabbing per-service
├── cpe_match.py        # banner → (vendor, product, version)
├── cve_match.py        # NVD API lookup, CVE cache (SQLite)
├── kev.py              # CISA KEV feed sync
└── profiles.py         # port profiles (quick, full, web, db)
```

### 1.3. Core scanner (`scanner.py`)

```python
#!/usr/bin/env python3
"""
Vulture AI — TCP connect scan + banner grab + CVE matching.
Usage:
  python scanner.py --target 192.168.1.10 --profile full --cve --json out.json
"""
import argparse, asyncio, json
from datetime import datetime
from port_probe import scan_ports
from banners import grab_banner
from cpe_match import identify
from cve_match import lookup_cves

async def scan_host(host, profile, do_cve):
    ports = await scan_ports(host, profile.ports, timeout=profile.timeout)
    results = []
    for port, proto in ports:
        banner = await grab_banner(host, port, proto)
        ident = identify(port, banner)
        cves = await lookup_cves(ident) if do_cve and ident else []
        results.append({
            "port": port, "protocol": proto, "banner": banner,
            "detected": ident, "cves": cves,
        })
    return {"host": host, "ports": results}

async def main(args):
    targets = expand_targets(args.target)   # single / CIDR / list
    profile = load_profile(args.profile)
    tasks = [scan_host(t, profile, args.cve) for t in targets]
    hosts = await asyncio.gather(*tasks)
    out = {
        "id": f"scan_{int(datetime.utcnow().timestamp())}",
        "started_at": datetime.utcnow().isoformat() + "Z",
        "target": args.target,
        "profile": args.profile,
        "hosts": hosts,
    }
    if args.json:
        with open(args.json, "w") as f: json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--profile", default="full", choices=["quick","full","web","db"])
    p.add_argument("--cve", action="store_true")
    p.add_argument("--json", default=None)
    asyncio.run(main(p.parse_args()))
```

### 1.4. Port probe (`port_probe.py`)

```python
import asyncio

async def tcp_connect(host, port, timeout=0.3):
    try:
        fut = asyncio.open_connection(host, port)
        r, w = await asyncio.wait_for(fut, timeout=timeout)
        w.close()
        return True
    except Exception:
        return False

async def scan_ports(host, ports, timeout=0.3, concurrency=200):
    sem = asyncio.Semaphore(concurrency)
    async def probe(p):
        async with sem:
            return p if await tcp_connect(host, p, timeout) else None
    results = await asyncio.gather(*(probe(p) for p in ports))
    return [(p, "tcp") for p in results if p]
```

### 1.5. Banner grab (`banners.py`)

```python
import asyncio

PROBES = {
    80:   b"HEAD / HTTP/1.0\r\nUser-Agent: VultureAI\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\nUser-Agent: VultureAI\r\n\r\n",  # then TLS wrap
    22:   None,         # server speaks first
    25:   b"EHLO vulnscan\r\n",
    3306: None,         # MySQL handshake banner
    5432: None,         # PostgreSQL error message
    6379: b"PING\r\n",
}

async def grab_banner(host, port, proto, timeout=2.0):
    probe = PROBES.get(port)
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        if probe:
            w.write(probe); await w.drain()
        data = await asyncio.wait_for(r.read(512), timeout)
        w.close()
        return data.decode(errors="ignore").strip()
    except Exception:
        return None
```

### 1.6. CPE matching (`cpe_match.py`)

```python
import re

# Each rule: regex over banner -> (vendor, product, version regex group)
FINGERPRINTS = [
    (r"SSH-2\.0-OpenSSH_(\d+\.\d+(?:\.\d+)?)", "openbsd", "openssh", 1),
    (r"Apache/(\d+\.\d+\.\d+)",                "apache",  "http_server", 1),
    (r"nginx/(\d+\.\d+\.\d+)",                 "nginx",   "nginx",       1),
    (r"PostgreSQL (\d+\.\d+\.\d+)",            "postgresql","postgresql", 1),
    # ...add as needed
]

def identify(port, banner):
    if not banner: return None
    for rx, vendor, product, vidx in FINGERPRINTS:
        m = re.search(rx, banner, re.I)
        if m:
            version = m.group(vidx) if m.group(vidx) else "unknown"
            cpe = f"cpe:2.3:a:{vendor}:{product}:{version}"
            return {"vendor": vendor, "product": product, "version": version, "cpe": cpe}
    return None
```

### 1.7. CVE matching against NVD (`cve_match.py`)

```python
import aiosqlite, aiohttp, asyncio

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE = "nvd_cache.sqlite"

async def lookup_cves(ident):
    cpe = ident["cpe"]
    async with aiosqlite.connect(CACHE) as db:
        cur = await db.execute("SELECT payload FROM cves WHERE cpe=? AND fetched > datetime('now','-7 day')", (cpe,))
        row = await cur.fetchone()
        if row:
            return json.loads(row[0])
    # cache miss — query NVD (rate-limited: 5 req / 30s without API key)
    params = {"cpeName": cpe, "resultsPerPage": 20}
    async with aiohttp.ClientSession() as s:
        async with s.get(NVD, params=params, headers={"apiKey": NVD_API_KEY}) as r:
            data = await r.json()
    vulns = []
    for v in data.get("vulnerabilities", []):
        cve = v["cve"]
        metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
        cvss = metrics[0]["cvssData"]["baseScore"] if metrics else 0.0
        severity = metrics[0]["cvssData"]["baseSeverity"] if metrics else "INFO"
        vulns.append({
            "id": cve["id"], "cvss": cvss, "severity": severity,
            "desc": cve["descriptions"][0]["value"],
            "cpe": cpe,
        })
    async with aiosqlite.connect(CACHE) as db:
        await db.execute("INSERT OR REPLACE INTO cves(cpe, fetched, payload) VALUES (?, datetime('now'), ?)",
                         (cpe, json.dumps(vulns)))
        await db.commit()
    await asyncio.sleep(6)   # respect NVD rate limits
    return vulns
```

### 1.8. CISA KEV sync (`kev.py`)

```python
import aiohttp, aiosqlite, json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

async def sync_kev():
    async with aiohttp.ClientSession() as s:
        async with s.get(KEV_URL) as r:
            data = await r.json()
    async with aiosqlite.connect("kev.sqlite") as db:
        await db.execute("CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY)")
        await db.executemany("INSERT OR REPLACE INTO kev(cve) VALUES (?)",
                             [(v["cveID"],) for v in data["vulnerabilities"]])
        await db.commit()

def is_kev(cve_id):
    # ... query sqlite
```

---

## 2. Backend — Spring Boot (`backend/`)

### 2.1. `pom.xml`

```xml
<dependencies>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId></dependency>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>
  <dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId></dependency>
  <dependency><groupId>org.projectlombok</groupId><artifactId>lombok</artifactId></dependency>
</dependencies>
```

### 2.2. Entities

```java
@Entity @Data class Scan {
    @Id String id;
    String target;
    String profile;
    Instant startedAt;
    Instant finishedAt;
    @Enumerated(EnumType.STRING) Status status;
    @OneToMany(mappedBy = "scan") List<Host> hosts;
}
@Entity @Data class Host {
    @Id @GeneratedValue Long id;
    @ManyToOne Scan scan;
    String ip; String hostname; String os;
    @OneToMany(mappedBy = "host") List<Port> ports;
}
@Entity @Data class Port {
    @Id @GeneratedValue Long id;
    @ManyToOne Host host;
    Integer port; String protocol; String service; String banner;
    @OneToMany(mappedBy = "port") List<Cve> cves;
}
@Entity @Data class Cve {
    @Id String id;
    @ManyToOne Port port;
    Double cvss;
    @Enumerated(EnumType.STRING) Severity severity;
    String description; String cpe; Boolean kev;
}
```

### 2.3. REST controller

```java
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
class ScanController {
    private final ScanService scans;

    @PostMapping("/scans")
    public ResponseEntity<Scan> create(@RequestBody ScanRequest req) {
        return ResponseEntity.accepted().body(scans.start(req));
    }

    @GetMapping("/scans/{id}")
    public Scan get(@PathVariable String id) { return scans.get(id); }

    @GetMapping("/scans/{id}/cves")
    public List<CveDto> cves(@PathVariable String id,
                             @RequestParam(required=false) Severity severity,
                             @RequestParam(required=false) Boolean kev) {
        return scans.cves(id, severity, kev);
    }
}
```

### 2.4. Async scan job

```java
@Service @RequiredArgsConstructor
class ScanService {
    private final ScanRepo scanRepo; private final RestTemplate http = new RestTemplate();

    @Async
    public Scan start(ScanRequest req) {
        Scan s = Scan.start(req);
        scanRepo.save(s);
        // call scanner container, stream result back
        String json = http.postForObject("http://scanner:7000/run", req, String.class);
        persist(s, json);
        s.finish(); scanRepo.save(s);
        return s;
    }
}
```

Run the Python scanner as a sidecar container (Flask/FastAPI) that the
Spring Boot service calls over HTTP — keeps language choice flexible.

---

## 3. Frontend dashboard (`frontend/`)

The frontend is a small SPA. Two options:

- **Vanilla HTML/CSS/JS** — this repo, zero build step, fast to deploy.
- **React + Recharts + TanStack Query** — better for larger teams.

### 3.1. API integration

```js
async function startScan(target, profile) {
  const res = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, profile, cve: true }),
  });
  return res.json();   // { id, status: "RUNNING" }
}

// Poll while running
const poll = setInterval(async () => {
  const scan = await fetch(`/api/scans/${id}`).then(r => r.json());
  renderDashboard(scan);
  if (scan.status !== "RUNNING") clearInterval(poll);
}, 1500);
```

### 3.2. KPI cards, charts, host table

Same data shape as in this demo's `script.js` — replace the simulated
scan engine with real `fetch` calls to the backend.

---

## 4. Chat with your scan (LangChain RAG)

The "Chat with your scan" panel turns the JSON report into an interactive
chatbot. Two implementations, depending on scan size:

| Scan size | Strategy |
|---|---|
| Small (≤ ~20k tokens) | Stuff the entire scan JSON into the system prompt |
| Large (> ~20k tokens) | Chunk scan into sections, embed with OpenAI / HF, store in FAISS or ChromaDB, retrieve top-k per question |

### 4.1. Ingestion — small scans (`llm/ingest.py`)

```python
from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
import json

SYSTEM = """You are Vulture AI Assistant. Answer ONLY using the scan
JSON below. If the user asks something outside the scan, say so.
Always cite CVEs by ID and hosts by IP/hostname.

Scan JSON:
{scan}
"""

def make_chain():
    return ChatPromptTemplate.from_messages([
        ("system", SYSTEM),
        ("human", "{question}"),
    ]) | ChatOpenAI(model="gpt-4o-mini", temperature=0)
```

### 4.2. Ingestion — large scans (`llm/ingest_rag.py`)

```python
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.document_loaders import JSONLoader

def build_index(scan_json_path):
    docs = JSONLoader(scan_json_path, jq_schema=".hosts[]").load()
    chunks = RecursiveCharacterTextSplitter(chunk_size=600, chunk_overlap=80).split_documents(docs)
    return FAISS.from_documents(chunks, OpenAIEmbeddings())
```

### 4.3. Chat endpoint

```python
from fastapi import FastAPI
from langchain.chains import RetrievalQA
from langchain.chat_models import ChatOpenAI

app = FastAPI()
INDEX = None  # populated on scan finish

@app.post("/chat/{scan_id}")
async def chat(scan_id: str, body: dict):
    qa = RetrievalQA.from_chain_type(
        llm=ChatOpenAI(model="gpt-4o-mini", temperature=0),
        retriever=INDEX.as_retriever(k=8),
        return_source_documents=True,
    )
    out = qa(body["question"])
    return {"answer": out["result"],
            "sources": [d.page_content for d in out["source_documents"]]}
```

### 4.4. Why this is good UX

The chat lets engineers ask the questions they actually have:

- *"Which CVEs are critical and exploitable from the internet?"*
- *"Did you find any database vulnerabilities?"*
- *"What's the worst affected host?"*
- *"Recommend a remediation priority order"*

Instead of reading a 50-page PDF and a giant JSON blob.

### 4.5. Guardrails

- System prompt restricts answers to the scan JSON.
- The LLM **never** scans, runs code, or makes network calls.
- Rate-limit by user / API key (Nginx limit_req + per-user counter in Redis).
- Stream responses (SSE) for low time-to-first-token.

---

## 5. Containerise (`docker-compose.yml`)

```yaml
version: "3.9"
services:
  scanner:
    build: ./scanner
    environment:
      - NVD_API_KEY=${NVD_API_KEY}
    ports: ["7000:7000"]

  backend:
    build: ./backend
    depends_on: [postgres, scanner]
    environment:
      - SPRING_DATASOURCE_URL=jdbc:postgresql://postgres/vulnscan
      - SCANNER_URL=http://scanner:7000

  frontend:
    build: ./frontend
    ports: ["8080:80"]

  chat:
    build: ./llm
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    depends_on: [backend]

  postgres:
    image: postgres:16
    volumes: ["pgdata:/var/lib/postgresql/data"]

volumes:
  pgdata:
```

Front everything with **Nginx + Let's Encrypt**.

---

## 6. Security & legal

- ⚠️ Only scan systems you own or have **written permission** to test.
- Add an auth layer (OAuth2 / OIDC) in front of the dashboard.
- Restrict the chat endpoint per-user; rate-limit with Redis.
- The scanner container should run with `network_mode: host` only when
  explicitly opted in (most users will run it against internal subnets).
- Never log full banner content into public-facing logs.

---

## 7. Repo layout (target)

```
vulnscan/
├── scanner/          # Python port + banner + CVE engine
├── backend/          # Spring Boot REST API
├── frontend/         # This dashboard (or React)
├── llm/              # LangChain chat service
├── docker-compose.yml
├── README.md
└── IMPLEMENTATION.md
```

---

## 8. Stretch goals

- **Scheduling** — kick off weekly scans via `@Scheduled` or a cron sidecar.
- **Diff** — compare two scans and surface only the *new* CVEs (huge for change windows).
- **Slack / email digest** — push the daily KPI summary to a channel.
- **Asset correlation** — join scan results against your CMDB.
- **Exploit prediction** — fine-tune a model to predict which CVE is *most likely* to be exploited in the next 30 days.
