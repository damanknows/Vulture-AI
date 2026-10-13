# Limitations and Threats to Validity

## 1. Construct Circularity & Heuristic Alignment
The benchmark reference labels were assigned following CISA SSVC decision tree rubrics. In SSVC, decision outcomes are explicitly governed by exploitation state (correlated with KEV and EPSS), network exposure ($N$), and technical impact ($C$ and $A$). Because the proposed VRS formula and the SSVC decision tree share these underlying features, strong rank correlation ($\rho = 0.9488$) demonstrates **heuristic construct alignment** with established vulnerability triage principles. It does not constitute independent empirical proof of enterprise breach prediction or incident avoidance.

## 2. Environmental Context Assignment
In `data/benchmark/cves.csv`, values for Network Exposure ($N$) and Asset Criticality ($A$) represent archetypal reference deployment assumptions (e.g., perimeter gateway vs. internal server) rather than live telemetry collected from an organization's internal network topography. In production environments, inaccurate or outdated asset inventories will affect fine-grained risk scoring.

## 3. Metric Saturation and Ceiling Effects at $K=10$
Because the benchmark includes 15 Tier 1 (Act) records, any ordering of the top 10 positions that contains only Tier 1 items achieves $\text{NDCG@10} = 1.0000$ and $\text{P@10} = 1.0000$. This explains why multiple variants (Full VRS, No EPSS, and No Bucket Override) exhibit identical top-10 performance. Deeper budget evaluations ($K=15$) and Spearman correlation ($\rho$) are required to reveal discriminative differences across model ablations.

## 4. EPSS Ablation Dynamics
Removing EPSS increases Spearman rank correlation from $\rho = 0.9488$ to $\rho = 0.9575$. This occurs because EPSS models rolling 30-day exploitation probability, heavily weighting high-volume automated reconnaissance and brute-force scanning (e.g., OpenSSH user enumeration `CVE-2018-15473`, EPSS 0.986). Under SSVC triage, low-impact reconnaissance bugs are categorized as *Defer* (reference priority 36). EPSS pulls such vulnerabilities higher in ranking. Ablating EPSS allows CVSS technical impact and exposure to penalize these low-impact vulnerabilities, placing them closer to the bottom and slightly improving monotonic rank alignment with the SSVC rubric. This must not be interpreted as proving EPSS is unhelpful in operational environments.

## 5. Sample Size and Generalization
The benchmark comprises 41 curated vulnerability records. While covering web servers, firewalls, enterprise gateways, operating system kernels, libraries, and missing-data edge cases, $N=41$ represents a sample size that limits claims of broad statistical generalizability across the entire NVD corpus ($>$250,000 CVEs).

## 6. Temporal Drift
EPSS probabilities fluctuate daily based on global threat activity. Replicating experiments at a future date without using the frozen snapshot (`data/benchmark/cves.csv`) will introduce numerical variance.

## 7. RAG Evaluation and Mocked Models
The guardrail evaluations in `evaluate_rag.py` and `tests/test_evidence_validator.py` execute against deterministic MockLLM fixtures to ensure offline reproducibility without requiring paid API keys. While MockLLM execution confirms schema compliance and attribution filter enforcement, it does not evaluate empirical resistance against adaptive, novel jailbreaks on frontier commercial LLMs.
