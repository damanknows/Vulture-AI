# Citation Integrity Audit — Vulture-AI (ICCI 2026)

**Date:** 2026-11-27  
**Bibliography:** `revision/ICCI2026_revision/references_revised.bib` (`18` cited entries; all `18` verified to have a DOI or stable URL).

---

## 1. Newly Added Section II-B References (Direct Verification)

| Ref | Bib Key | Title, Authors, Venue, Year | Verified DOI / URL | Claim in Manuscript (§II-B) & Verification |
|---|---|---|---|---|
| [10] | `shimizu2026chaining` | *Vulnerability Management Chaining: An Integrated Framework for Efficient Cybersecurity Risk Prioritization*, Naoyuki Shimizu & Masaki Hashimoto, *IEEE Access*, vol. 14, pp. 31407–31424, 2026 | `doi: 10.1109/ACCESS.2026.3665768` / `https://arxiv.org/abs/2506.01220` | **Claim:** *"chains CISA KEV, EPSS thresholds, and CVSS severity into a staged decision tree to filter scanner backlogs"*. **Verified:** Crossref + arXiv abstract confirm a two-stage decision tree applying KEV membership / EPSS $\ge 0.088$ filtering followed by CVSS $\ge 7.0$ severity assessment. |
| [11] | `scott2025context` | *A Novel Vulnerability Prioritization Model for Workstation Endpoints with Context Intelligence*, Logan Scott & Jeremy Cohen, *IEEE ICCST*, pp. 1–6, 2025 | `doi: 10.1109/ICCST63435.2025.11293920` | **Claim:** *"combine internal endpoint attributes (privilege, protective controls, exposure) with EPSS and KEV"*. **Verified:** Crossref + Semantic Scholar abstract confirm workstation endpoint context (asset exposure, user privilege levels, active endpoint protection controls) combined with EPSS and CISA KEV. |
| [12] | `alhaddad2025llmssvc` | *Prompting the Priorities: A First Look at Evaluating LLMs for Vulnerability Triage and Prioritization*, Osama Al Haddad, Muhammad Ikram, Ejaz Ahmed, Young Lee, arXiv:2510.18508, 2025 | `https://arxiv.org/abs/2510.18508` | **Claim:** *"prompt LLMs to predict SSVC decision points directly and report a tendency toward risk over-prediction"*. **Verified:** arXiv abstract confirms evaluating 4 LLMs on SSVC decision points and states *"all models tended to over-predict risk."* |

---

## 2. Reviewer 2 Flagged Entries
- **CVSS v2 guide vs IEEE S&P 2006 (`mell2007cvss2`):** Kept separate (`Mell, Peter and Scarfone, Karen and Romanosky, Sasha`, *A Complete Guide to the Common Vulnerability Scoring System Version 2.0*, 2007, `https://www.first.org/cvss/v2/guide`), not merged with any IEEE S&P 2006 entry (and unused in the revised manuscript, which cites CVSS v3.1 `first2019cvss` and CVSS v4.0 `first2023cvss4`).
- **SSVC white paper (`spring2020ssvc`) & CISA SSVC guide (`cisa2024ssvc`):** Author spelling confirmed as `Hatleback, Eric`, report `CMU/SEI-2019-TR-005`, year `2019`, URL `https://insights.sei.cmu.edu/library/prioritizing-vulnerability-response-a-stakeholder-specific-vulnerability-categorization/`. CISA SSVC guide (`cisa2024ssvc`, `https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc`) is cited alongside `spring2020ssvc`.

---

## 3. Complete Bibliography Verification Table (All Cited Entries)

| Ref | Bib Key | DOI / Stable URL | Supported Claim |
|---|---|---|---|
| [1] | `first2019cvss` | `https://www.first.org/cvss/v3.1/specification-document` | CVSS v3.1 base severity under worst-case assumptions (§I, §II-A) |
| [2] | `first2023cvss4` | `https://www.first.org/cvss/v4.0/specification-document` | CVSS v4.0 Base/Threat/Environmental groups; Base not complete risk (§I, Table I, §II-A) |
| [3] | `first2024epss` | `https://www.first.org/epss/faq` | EPSS 30-day exploitation probability forecast (§I, Table I, §II-A) |
| [4] | `jacobs2021epss` | `doi: 10.1145/3436242` | EPSS methodology paper (§I, Table I, §II-A) |
| [5] | `cisa2024kev` | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | CISA KEV catalog of confirmed active exploitation (§I, Table I, §II-A) |
| [6] | `spring2020ssvc` | `https://insights.sei.cmu.edu/library/prioritizing-vulnerability-response-a-stakeholder-specific-vulnerability-categorization/` | SEI SSVC decision tree framework (§I, Table I, §II-A, §V-B) |
| [7] | `cisa2024ssvc` | `https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc` | CISA SSVC guide and tree (§I, Table I, §II-A, §V-B) |
| [8] | `greshake2023indirect` | `doi: 10.1145/3605764.3623985` | Indirect prompt injection via retrieved text (§I, §II-C) |
| [9] | `cisa2021bod` | `https://www.cisa.gov/binding-operational-directive-22-01` | BOD 22-01 establishing KEV (Table I) |
| [10] | `shimizu2026chaining` | `doi: 10.1109/ACCESS.2026.3665768` | Staged KEV/EPSS/CVSS decision tree (§II-B) |
| [11] | `scott2025context` | `doi: 10.1109/ICCST63435.2025.11293920` | Workstation endpoint context + EPSS/KEV (§II-B) |
| [12] | `alhaddad2025llmssvc` | `https://arxiv.org/abs/2510.18508` | LLM SSVC prediction & risk over-prediction (§II-B) |
| [13] | `lewis2020rag` | `https://arxiv.org/abs/2005.11401` | Retrieval-augmented generation (§II-C) |
| [14] | `liu2024formalizing` | `https://arxiv.org/abs/2310.12815` | Prompt injection formalization/benchmarking (§II-C) |
| [15] | `hines2024spotlighting` | `https://arxiv.org/abs/2403.14720` | Spotlighting defense (§II-C) |
| [16] | `chen2024struq` | `https://arxiv.org/abs/2402.06363` | StruQ defense (§II-C) |
| [17] | `chen2024secalign` | `https://arxiv.org/abs/2410.05451` | SecAlign defense (§II-C) |
| [18] | `nvd2023` | `https://nvd.nist.gov/` | NVD vulnerability records (§IV-E) |
