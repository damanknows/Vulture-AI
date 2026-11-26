# Response to Reviewer #2

**Paper 144:** Vulture-AI. **Decision:** Accept After Modification.

**Attribution note.** The revision record does not assign concerns to named reviewers. This letter covers the concerns on the RAG implementation, explanation quality, references, CPE matching, and the data-side questions on temporal leakage and benchmark independence (Concerns 6, 7, 12, 13, and the data-side parts of 9 and 10). Methodological concerns are in Reviewer #1's letter.

---

## Concern 6: Unclear RAG retrieval implementation
**Comment:** The paper says "retrieval-augmented generation" but does not say what is retrieved, from where, or how. Is it NVD, EPSS, KEV, or an external database? Is retrieval deterministic or learned? No retrieval metrics are reported.

**Modification.** The System Architecture section now describes retrieval exactly as implemented. Retrieval is exact CVE-identifier lookup or case-insensitive keyword substring matching over the local enriched dataset (`retrieval.py`). The assistant uses no vector database, no embedding model, and no external search. The earlier wording that implied a richer retrieval layer has been removed.

**Section.** System Architecture (Explanation); Related Work §5 (RAG).

**Experiment added.** None. Retrieval quality was not measured. A precision or recall measure for retrieval is not meaningful for exact and substring lookup, and we did not construct a relevance set for it.

**Result.** Not applicable.

**Status: addressed by correction.** The retrieval description now matches the code. The concern about "no retrieval metrics" is not addressed, and the paper does not claim retrieval quality.

---

## Concern 7: Missing explanation-quality evaluation
**Comment:** The paper claims "intuitive triaging assistance" but reports no measure of explanation quality: factuality, length, usefulness, or faithfulness to evidence. How is it measured?

**Modification.** We removed "intuitive triaging assistance" and any claim of explanation utility. The Results section states that explanation quality was not measured. The Discussion states that explanation utility and practical applicability are unknown. The Threats section describes the requirements for any future automated judge (model, prompt, version, settings, and human spot-check).

**Section.** Abstract; Results (Explanation quality); Discussion (Explanation utility); Threats (Automated explanation evaluation).

**Experiment added.** None that measures explanation quality. The rubric (factual correctness, evidence consistency, score faithfulness, clarity; 1–5 scale) is implemented as an importer that validates human or automated ratings, with a template file that contains no rows (`experiments/revision/guardrail/explanation_evaluation.csv`).

**Result.** No ratings exist, so no explanation-quality result is reported. We did not run an automated judge, and we did not fabricate scores.

**Status: not addressed.** Explanation quality remains unmeasured. The reviewer's concern is valid, and the paper now makes no claim about it. A human-rated or documented automated evaluation is future work.

---

## Concern 12: Missing literature and incorrect references
**Comment:** The bibliography is incomplete. It omits recent work on CVSS v4.0, EPSS (the reviewer cites "EPSS v2, 2024"), and RAG security from 2024–2025. Some citations are outdated. Are they accurate?

**Modification.** We checked each cited source against its primary page and added entries only for sources we could verify. The revised bibliography (`references_revised.bib`) adds CVSS v4.0, the FIRST EPSS FAQ, CISA KEV and SSVC, Liu et al. (USENIX Security 2024), Hines et al. (spotlighting, 2024), Chen et al. (StruQ, USENIX Security 2025), and Chen et al. (SecAlign, CCS 2025). Related Work §5 uses them to describe current RAG-injection defenses. We corrected the BOD 22-01 statement: it was superseded by BOD 26-04.

**Section.** Related Work (all subsections); References.

**Experiment added.** None. This is a literature change.

**Result (verification status):**
- Verified against the primary page: CVSS v4.0 and v3.1 specifications; the FIRST EPSS program and FAQ; CISA KEV, SSVC, and BOD 22-01 pages; arXiv records for Greshake, Lewis, Liu, Hines, Chen (StruQ), and Chen (SecAlign).
- Not verified, and flagged in the bibliography: the EPSS methodology venue (cited as *Digital Threats*; not confirmed), the Greshake venue and pages (AISec 2023; not confirmed), the SEI SSVC report (URLs returned 404), and Mell et al. (not fetched).
- Not found: verified primary sources for ML-based triage beyond EPSS, LLM-based triage, and context-aware enterprise prioritization. We do not cite any for these.

**Note on "EPSS v2 (2024)".** In the FIRST pages we read (the EPSS program page and FAQ), we did not find a release named "EPSS v2". The FAQ describes model updates and a version changelog. We did not search the full FIRST archive or the changelog page, so this is a search limit, not a confirmed absence. We therefore do not cite it, and we do not claim it does not exist. The reviewer should supply the reference if they have one.

**Status: partially addressed.** The verifiable set is corrected and extended. Three bibliographic items remain unconfirmed and are flagged, not silently kept. The reviewer's requested sources for ML and LLM triage were not located.

---

## Concern 13: CPE and Nmap matching not evaluated
**Comment:** The paper mentions CPE normalization and Nmap integration but gives little evaluation. How accurate is CPE matching? What is the false-negative rate? How does it handle version ambiguity such as "Apache 2.4" versus "2.4.49"?

**Modification.** The System Architecture section describes the matcher: it normalizes product and version strings, builds CPE 2.3 candidate identifiers, and records match basis and confidence. The paper states that matching accuracy has not been evaluated. The Threats section states that the false-negative rate of the scanner-to-CVE step is unknown.

**Section.** System Architecture (Input and scanning); Threats (Data-source limitations).

**Experiment added.** None. We did not construct a labelled set of scanner outputs with correct CVE matches.

**Result.** The existing unit tests for the matcher pass (4 tests in `tests/test_cve_matcher.py`). These check basic functionality and do not measure accuracy, recall, or ambiguity handling.

**Not done.** No accuracy, false-negative, or version-ambiguity evaluation was performed. This would need a labelled corpus of scan outputs and their correct CVE identifiers.

**Status: not addressed.** The limitation is disclosed. An evaluation is the required next step.

---

## Concern 9 (data side): Temporal leakage from later EPSS and KEV snapshots
**Comment:** EPSS and KEV snapshots from 2026-10-13 are used. If evaluation uses later data than the prediction would, this is look-ahead bias.

**Modification.** As described in the reply to Reviewer #1, the paper now states the temporal setting, removes early-prediction claims, and lists the temporal limitations. The Experimental Setup gives the snapshot dates.

**Section.** Experimental Setup (Temporal setting); Threats (Temporal leakage).

**Experiment added.** None. Historical data were not downloaded.

**Result.** All 461 EPSS cache entries are dated 2026-10-13. The KEV feed is version 2026.10.13. The 461 added CVEs carry publication dates in `source_timestamp` but 2026 feature values.

**Status: addressed by disclosure; historical evaluation not performed.**

---

## Concern 10 (data side): Possible lack of independence in the 500-CVE experiment
**Comment:** The 500-CVE corpus includes the 39 curated CVEs. This may amount to evaluating on training data.

**Modification.** As described in the reply to Reviewer #1, the overlap is stated and the KEV concordance is described as a policy-consistency check.

**Section.** Results (Retrospective KEV concordance); Threats (Data-source limitations).

**Experiment added.** None.

**Result.** 0 of 461 added CVEs are in the KEV feed. All 25 KEV entries are among the 39 curated records. The four records whose KEV flag disagrees with the feed (CVE-2022-1292, CVE-2019-15846, CVE-2021-3560, CVE-2022-0492) are reported in `revision/evidence/kev_consistency.json`. They are included in all reported results. Correcting them could change the headline numbers, and that decision has not been made.

**Status: addressed by disclosure. The KEV-flag discrepancy is open.**

---

## Summary for Reviewer #2

Concerns 6 and 12 are addressed: the retrieval description now matches the code, and the bibliography is corrected for the verified set. Concern 7 (explanation quality) and Concern 13 (CPE matching accuracy) are not addressed; neither was measured, and the paper now makes no claim about either. Concerns 9 and 10 are addressed by disclosure, and the KEV-flag discrepancy remains open for the authors to resolve.
