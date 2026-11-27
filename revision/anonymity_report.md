# Double-Blind Anonymity Audit Report — Vulture-AI (ICCI 2026)

**Date:** 2026-11-27  
**Target URL:** `https://anonymous.4open.science/r/Vulture-AI`  
**Branch:** `fix/final-pass`

---

## Audit Checklist

| Item | Status | Findings & Remediation |
|---|---|---|
| **1. `final_submission/` upload package** | **PASS** | Inspected `Vulture_AI_ICCI2026_Anonymous_Submission.pdf`, `manuscript_revised.tex`, `references_revised.bib`, `fig1.pdf`, `UPLOAD_MANIFEST.md`. Zero author names, emails, GitHub usernames, local paths, or credentials (`pdfinfo` Author: `Anonymous Author(s)`). |
| **2. Python source, `README.md`, `requirements*.txt`** | **PASS** | `git grep` across all `.py`, `README.md`, and `requirements*.txt` found zero author names, emails, usernames, or local paths. |
| **3. Tracked markdown logs (`PHASE2_*.md`)** | **PASS (Remediated)** | Found 4 occurrences of `/home/daman/Projects/vulture` in `PHASE2_EXECUTION_LOG.md` (lines 13, 96, 112) and `PHASE2_IMPLEMENTATION_REPORT.md` (line 413). Replaced all 4 with `<repo_root>`. |
| **4. Secrets / API keys / tokens** | **PASS** | `git grep` for `ghp_`, `sk-`, `AKIA` across tracked files (excluding `data/` and `revision/`) returned `0` matches. |
| **5. `.git/config` (local only)** | **PASS (Local)** | `.git/config` is not tracked in git; contains `git@github.com:damanknows/Vulture-AI.git` locally. |
| **6. `git log` author/committer metadata** | **REMEDIATION REQUIRED ON PUBLISH** | Local `git log` commits carry `damanknows <damanlovedeeps@gmail.com>`. Anonymous GitHub (`4open.science`) strips/anonymizes git history when configured, or the repository must be re-published from a single squashed anonymous commit. |
| **7. Live `anonymous.4open.science/r/Vulture-AI` fetch** | **UNVERIFIED (Must Re-publish / Confirm)** | `GET https://anonymous.4open.science/r/Vulture-AI` returned `200 OK` (React SPA shell), while `GET https://anonymous.4open.science/api/repo/Vulture-AI/files/` returned `404 Not Found`. Because the remote tree could not be fetched headlessly, the author must verify/re-publish the `Vulture-AI` link on `anonymous.4open.science` with `fix/final-pass` (or updated `research-v2`), `daman`/`damanknows`/`damanlovedeeps@gmail.com` in the anonymize-words list, and commit history anonymized. |
