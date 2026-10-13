# 1. PROJECT TITLE AND OVERVIEW

**Vulture-AI**
An AI-Assisted Vulnerability Analysis and Prioritization System.

In modern application security, teams face vulnerability overload. Standard vulnerability scanners generate thousands of alerts, often lacking the contextual intelligence required for effective remediation. Vulture-AI addresses this by integrating network observations (e.g., Nmap), authoritative vulnerability intelligence (NVD CVSS), exploit prediction metrics (FIRST EPSS), and known exploitation status (CISA KEV) into a unified analysis pipeline. 

The project features a deterministic scoring heuristic—the Vulture Risk Score (VRS)—and an AI assistant that provides evidence-grounded explanations for its prioritizations.

# 2. PROJECT STATUS

| Feature Area | Status | Implementation Details |
|---|---|---|
| **Deterministic Risk Scoring (VRS)** | Implemented and Tested | Pure mathematical evaluation; handles missing EPSS data via explicit fallback policies. |
| **CVE Enrichment & Matching** | Implemented and Tested | Dynamically maps product banners to NVD CPEs and fetches EPSS/KEV metadata. |
| **Evidence-Grounded AI (RAG)** | Implemented and Tested | Validates AI JSON outputs against schema and intercepts prompt injections. |
| **Experiment Metrics & Baselines** | Implemented and Tested | Fully reproducible evaluation pipeline (NDCG, Spearman). |
| **Frontend Dashboard** | Implemented but Not Fully Validated | React SPA hosted via Flask; real-world usability testing is pending. |
| **Real Scanner Orchestration** | Implemented but Not Fully Validated | `nmap` executes synchronously; lacking concurrency and celery worker queues. |
| **Vector DB Semantic Search** | Planned | Retrieval currently defaults to exact-match and keyword fallback. |

# 3. RESEARCH MOTIVATION AND OBJECTIVES

Conventional vulnerability prioritization heavily relies on the Common Vulnerability Scoring System (CVSS). However, CVSS purely measures technical severity, failing to capture real-world remediation priorities. By combining EPSS (threat probability), CISA KEV (confirmed exploitation), network exposure, and asset criticality, security teams can focus on vulnerabilities that pose an immediate risk.

Furthermore, traditional LLM security assistants are prone to hallucinating CVE metrics, generating misleading remediation advice. AI explanations must be transparently grounded in verifiable evidence.

**Research Hypothesis:** 
Integrating contextual threat intelligence (EPSS, KEV, exposure context) with a deterministic weighting heuristic (VRS) yields a higher monotonic rank correlation with expert prioritization rubrics than CVSS alone, and schema-constrained Retrieval-Augmented Generation (RAG) significantly reduces LLM factual hallucinations in security analysis.

*(Note: This is a proposed hypothesis being evaluated for submission to the 7th International Conference on Computing and Informatics, ICCI 2026. It is not an established conclusion.)*

# 4. KEY FEATURES

*   **Network Scanning & Service Identification:** (Verified) Executes Nmap via subprocess, parsing XML outputs to normalize service names and versions.
*   **CVE Enrichment & Affected-Version Matching:** (Verified) Integrates local caching for NVD API 2.0 CPE matches.
*   **CVSS, EPSS, and KEV Integration:** (Verified) Fetches and attaches contextual threat intelligence safely.
*   **Vulture Risk Score (VRS):** (Verified) Deterministic ranking logic decoupled from the LLM.
*   **Retrieval-Augmented Explanations:** (Verified) Pydantic-constrained LLM output guaranteeing evidence linkage.
*   **Evidence Validation:** (Verified) Blocks prompt injections smuggled in network banners and numerical hallucinations.
*   **Dashboard and Flask API:** (Verified) SPA fallback served via Flask root routing (`/`).
*   **Ollama Integration:** (Verified) Uses `litellm` router targeting local `llama3.2` instances.

# 5. SYSTEM ARCHITECTURE

```mermaid
flowchart TD
    A[Authorized Target] -->|Nmap Scan| B(Network Observations)
    B -->|Banner Extraction| C(Service/Version Identification)
    C -->|NVD / CPE Match| D(CVE Enrichment)
    D -->|FIRST & CISA Fetch| E(Threat Intel Integration)
    E --> F{Risk Scoring Engine}
    F -->|Vulture Risk Score| G(Deterministic Priority)
    G --> H[Retrieval-Augmented Explanation]
    H -->|Schema Validation| I[Evidence-Grounded AI Output]
    I --> J[Flask API / Dashboard]
```
*(Verified implementation of data flow)*

# 6. VULTURE RISK SCORE

The Vulture Risk Score (VRS) is an experimental prioritization heuristic defined on a `0 - 100` scale:

`VRS = 100 × (wC*C + wE*E + wK*K + wN*N + wA*A)`

**Experimental Components & Weights (vrs-v1):**
*   **C (CVSS Normalized):** `cvss_score / 10.0` (w = 0.25)
*   **E (EPSS Probability):** `0.0` to `1.0` (w = 0.20)
*   **K (KEV Status):** `1.0` if listed, else `0.0` (w = 0.20)
*   **N (Network Exposure):** `0.0` to `1.0` (w = 0.20)
*   **A (Asset Criticality):** `0.0` to `1.0` (w = 0.15)

**Missing Data Policy:**
*   Missing CVSS voids the score entirely (returns `None` / `Unavailable`).
*   Missing EPSS defaults to `0.0`.
*   Missing Exposure/Criticality defaults to `0.5`.
*   All missing derivations are appended to an `uncertainties` array in the final payload.

**Bucket Thresholds:** 
If `K == 1.0` (KEV listed), the finding is aggressively bucketed as `urgent` overriding the numeric VRS during final tie-break sorting. *Note: VRS does not prove active exploitation or compromise.*

# 7. TECHNOLOGY STACK

*   **Languages:** Python 3.10+, JavaScript
*   **Backend Framework:** Flask, Flask-CORS
*   **AI/LLM Runtime:** LiteLLM, Ollama (`llama3.2`)
*   **Network Scanning:** Nmap (XML Parsing)
*   **Threat Intel APIs:** NVD API 2.0, FIRST EPSS API, CISA KEV JSON Feed
*   **Testing & Metrics:** Pytest, Numpy

# 8. REPOSITORY STRUCTURE

```
Vulture-AI/
├── app.py                     # Main Flask Application
├── scanner.py                 # Nmap subprocess execution & allowlists
├── cve_matcher.py             # NVD CPE normalization and matching
├── threat_intel.py            # EPSS/KEV fetching with backoff logic
├── risk_engine.py             # VRS deterministic scoring heuristics
├── retrieval.py               # RAG evidence formatting & querying
├── evidence_validator.py      # LLM output and injection validator
├── vulture_chatbot.py         # LiteLLM router and Pydantic constraints
├── models.py                  # Dataclass definitions
├── REPRODUCIBILITY.md         # Academic reproducibility constraints
├── generate_data.py           # Benchmark dataset integrity & schema validator
├── data/
│   └── benchmark/cves.csv     # 41 real public CVE records with NVD, EPSS, KEV, and SSVC labels
├── experiments/
│   ├── run_baselines.py       # Computes baseline rankings (CVSS, EPSS, KEV, Combo, VRS)
│   ├── run_ablation.py        # Evaluates weight renormalization and bucket override ablations
│   ├── compute_metrics.py     # Computes NDCG@10, P@10, R@10, and mid-rank Spearman rho
│   ├── make_tables.py         # Generates publication LaTeX tables and empirical ranking scatter plots
│   ├── reproduce_all.py       # Unified end-to-end reproducible experiment runner with provenance manifest
│   └── evaluate_rag.py        # Validates LLM outputs against 4 RAG modes
├── tests/                     # Comprehensive integration and unit test suite
└── static/                    # Compiled React frontend SPA
```

# 9. INSTALLATION AND CONFIGURATION

1. **Clone the repository:**
   ```bash
   git clone https://github.com/damanknows/Vulture-AI.git
   cd Vulture-AI
   ```

2. **Setup virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables Configuration:**
   ```bash
   export NVD_API_KEY="<your_nvd_api_key_here>"
   export VULTURE_ALLOWED_TARGETS="127.0.0.1, 10.0.0.5" # Strictly enforce target allowlist
   export VULTURE_CORS_ORIGINS="http://localhost:3000, http://localhost:5000"
   export MODEL_NAME="ollama/llama3.2"
   ```

5. **Start Application:**
   ```bash
   python app.py
   ```

6. **Running the Test Suite:**
   ```bash
   PYTHONPATH=. pytest tests/ -v
   ```

7. **Running Academic Experiments:**
   ```bash
   python experiments/run_baselines.py
   python experiments/run_ablation.py
   python experiments/compute_metrics.py
   python experiments/evaluate_rag.py
   ```

# 10. SAFE USAGE

**Warning:** Scanning external assets without explicit permission is illegal. Vulture-AI implements a strict server-side `VULTURE_ALLOWED_TARGETS` allowlist. By default, attempting to scan loopback, RFC1918, or public IPs will return a security rejection unless specifically configured.

The included Flask server acts as a development runner. Do not deploy this application publicly without migrating to a production WSGI runner (e.g., Gunicorn) and properly securing network firewalls.

# 11. API DOCUMENTATION

| Route | Method | Payload | Description |
|---|---|---|---|
| `/health` | GET | None | Verified application up-status. |
| `/api/scans` | POST | `{"target": "127.0.0.1"}` | Initiates synchronous Nmap scan (if target is authorized). |
| `/api/scans` | GET | None | Fetches historical scan summaries. |
| `/api/scans/<id>` | GET | None | Fetches detailed scan payload by ID. |
| `/api/hosts/vulnerabilities` | GET | `?scan_id=<id>` | Fetches all detected CVEs across hosts. |
| `/api/chat` | POST | `{"question": "..."}` | Queries the LLM using RAG on recent findings. Returns priority and explanation JSON. |
| `/api/analyze` | POST | None | Shortcut to trigger high-level RAG analysis of the most recent scan context. |

# 12. RESEARCH METHODOLOGY

To evaluate the mathematical behavior and prioritization quality of the proposed Vulture Risk Score (VRS) heuristic, the experimental pipeline compares rankings across five baseline methods and five ablation variants on identical records:

**Baseline Methods:**
1. **CVSS-only baseline**: Ranks findings strictly by CVSS base score descending.
2. **EPSS-only baseline**: Ranks findings strictly by FIRST EPSS probability descending.
3. **KEV-first baseline**: Prioritizes CISA KEV known exploited vulnerabilities first, sorted by CVSS.
4. **CVSS + EPSS + KEV baseline**: Equal-weight combination (1/3 each) of the three vulnerability metrics.
5. **Vulture-AI (VRS Proposed)**: Proposed context-aware formula with KEV urgent bucket policy override.

**Ablation Variants (Proportional Renormalization Policy):**
*   **VRS (No EPSS)**: $w_E = 0$, remaining weights proportionally rescaled ($w_j' = w_j / \sum_{k \neq E} w_k$).
*   **VRS (No KEV Weight)**: $w_K = 0$, remaining weights proportionally rescaled.
*   **VRS (No Context / Tech-only)**: $w_N = 0, w_A = 0$, weights proportionally rescaled across $C, E, K$.
*   **VRS (No Bucket Override)**: Full weights ($w_C=0.25, w_E=0.20, w_K=0.20, w_N=0.20, w_A=0.15$), but ranked strictly by continuous numerical VRS score without the categorical KEV-first bucket override (`use_buckets=False`).

**Evaluation Metrics:**
*   `NDCG@10`: Normalized Discounted Cumulative Gain at $K=10$ using exponential graded relevance $\sum_{i=1}^{10} \frac{2^{rel_i} - 1}{\log_2(i+1)}$ normalized by ideal DCG@10.
*   `Precision@10` & `Recall@10`: Top-10 retrieval evaluated at two explicit decision thresholds:
    - Primary Threshold ($\tau = 3$, Act / Emergency Remediation, $N_{\text{relevant}} = 15$).
    - Secondary Threshold ($\tau = 2$, Actionable / Act or Attend, $N_{\text{relevant}} = 27$).
*   `Spearman Rank Correlation (rho)`: Monotonic rank correlation using fractional mid-ranks for ties and Pearson correlation of ranks, with strict population validation.
*   **Deterministic Tie-Breaking**: All methods enforce strict secondary sorting by primary CVE ID ascending.

**Dataset & Independent Labels:** `data/benchmark/cves.csv` contains 41 real, publicly documented vulnerabilities with official NIST NVD CVSS scores, live FIRST EPSS probabilities, and CISA KEV listings. Reference priorities (1–41) and relevance grades (3=Act, 2=Attend, 1=Track, 0=Defer) are categorized according to **CISA SSVC (Stakeholder-Specific Vulnerability Categorization)** guidelines.

# 13. EXPERIMENTAL RESULTS

The following table was generated automatically by `experiments/compute_metrics.py` against the real public vulnerability benchmark (41 records, frozen 2026-10-14).

| Model | NDCG@10 | P@10 (Act) | R@10 (Act) | P@10 (Actionable) | R@10 (Actionable) | Spearman |
|---|---|---|---|---|---|---|
| **CVSS-only** | 0.7563 | 0.6000 | 0.4000 | 1.0000 | 0.3704 | 0.7357 |
| **EPSS-only** | 0.9217 | 0.8000 | 0.5333 | 1.0000 | 0.3704 | 0.8237 |
| **KEV-first** | 0.7945 | 0.7000 | 0.4667 | 1.0000 | 0.3704 | 0.8247 |
| **CVSS+EPSS+KEV** | 0.9513 | 0.9000 | 0.6000 | 1.0000 | 0.3704 | 0.8800 |
| **VRS Proposed** | **1.0000** | **1.0000** | **0.6667** | **1.0000** | **0.3704** | **0.9488** |
| VRS (No EPSS) | 1.0000 | 1.0000 | 0.6667 | 1.0000 | 0.3704 | 0.9575 |
| VRS (No KEV) | 0.9581 | 0.9000 | 0.6000 | 1.0000 | 0.3704 | 0.9451 |
| VRS (No Context) | 0.9513 | 0.9000 | 0.6000 | 1.0000 | 0.3704 | 0.8782 |
| VRS (No Bucket Override) | 1.0000 | 1.0000 | 0.6667 | 1.0000 | 0.3704 | 0.9535 |

**Key Findings:**
1. **CVSS Misses Active Exploitation**: CVSS-only achieves P@10=0.60 and R@10=0.40, ranking unexploited critical vulnerabilities (e.g. XZ Utils backdoor, CVE-2024-3094) above lower-CVSS actively exploited services (e.g. Apache 2.4.49 path traversal, CVE-2021-41773).
2. **Context & Policy Override Benefit**: VRS Proposed achieves NDCG@10=1.0000 and P@10=1.0000, successfully surfacing all emergency remediation items in the top tier. Ablating environmental context (`VRS No Context`) drops Spearman correlation from 0.9488 to 0.8782.
3. **Score-Only vs. Bucket Override**: Ranking purely by continuous numerical score (`VRS No Bucket Override`) yields NDCG@10=1.0000 and Spearman=0.9535, confirming that the linear weighting formula itself surfaces critical KEV vulnerabilities even without the categorical urgent bucket override.

# 14. REPRODUCIBILITY

Vulture-AI guarantees algorithmic determinism across the entire pipeline.
*   **Dataset Integrity**: `data/benchmark/cves.csv` evaluates to SHA-256 `e2a3419a46f33b0e71bfc607a4031955d57b7188d56f1c635024219374177fc8` (verified by `python generate_data.py`).
*   **Unified Reproduction Command**: Run the end-to-end pipeline in a single step:
    ```bash
    python experiments/reproduce_all.py
    ```
*   **Individual Experiment Execution**:
    ```bash
    python experiments/run_baselines.py
    python experiments/run_ablation.py
    python experiments/compute_metrics.py
    python experiments/make_tables.py
    pytest -v
    ```
*   **Reproducibility Manifest**: Detailed runtime provenance, software versions, and configuration settings are saved automatically to `experiments/results/reproducibility_manifest.json`.

# 15. LIMITATIONS AND THREATS TO VALIDITY

1.  **Construct Circularity / Heuristic Alignment:** The SSVC ground-truth labels are derived from decision trees considering exploitation state (correlated with KEV and EPSS), exposure ($N$), and mission impact ($C$ and $A$). Consequently, the high correlation between VRS and reference labels reflects **construct consistency / heuristic alignment** with SSVC triage logic, rather than independent empirical proof of breach prevention.
2.  **Dataset Size & Generalization:** The benchmark contains 41 representative public CVEs. While covering diverse ecosystems and missing-data edge cases, performance differences demonstrate component sensitivity within this sample and cannot prove universal generalization or statistical causality.
3.  **Temporal Dynamics:** EPSS probabilities represent a rolling 30-day forecast and fluctuate daily. This benchmark captures a snapshot frozen on **2026-10-14**.
4.  **Service Banner Uncertainty:** Exact NVD CPE mapping relies entirely on Nmap accurately extracting non-obfuscated service strings. Failures in version discovery fall back to inaccurate candidate matches.
5.  **Scanner Concurrency:** `nmap` executes as a blocking subprocess on the API main thread, risking thread starvation under high load.

# 16. ROADMAP

* [x] Integration and correctness.
* [x] Risk-engine testing.
* [x] RAG evidence evaluation.
* [x] Benchmark quality (Synthetic testing).
* [x] Baseline comparison & Statistical analysis.
* [x] Security hardening (CORS, Request Limits, Target Verification).
* [ ] Real scanner validation against large-scale enterprise subnets.
* [ ] Background queue orchestration (e.g., Celery/Redis).
* [ ] Research paper preparation.

# 17. CONTRIBUTION AND TESTING

Contributors are encouraged to run the extensive test suite prior to submitting pull requests. Ensure your virtual environment is active and execute:
```bash
PYTHONPATH=. pytest tests/ -v
```
If introducing new ablations, please execute the `compute_metrics.py` script and submit the modified JSON outputs.

# 18. REFERENCES

*   NVD Vulnerability APIs: https://nvd.nist.gov/developers/vulnerabilities
*   FIRST EPSS API: https://www.first.org/epss/api
*   CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
*   Nmap Security Scanner: https://nmap.org/
*   Ollama: https://ollama.com/

# 19. LICENSE AND ACKNOWLEDGMENTS

This repository currently does not contain an explicitly specified License file (`LICENSE`). Please contact the repository owner regarding distribution or academic reproduction rights. 

# 20. CONTACT AND CITATION

**Owner:** damanknows
**Repository:** https://github.com/damanknows/Vulture-AI

*Suggested Citation (Pre-print format):*
> damanknows. (2026). Vulture-AI: AI-Assisted Vulnerability Analysis and Prioritization System. GitHub Repository. https://github.com/damanknows/Vulture-AI
