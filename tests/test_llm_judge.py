"""Unit tests for explanation-quality LLM judge pipeline."""

import csv
import json
from pathlib import Path
from types import SimpleNamespace

from experiments.revision.explanation.llm_judge import (
    JUDGE_PROMPT_SHA256,
    quadratic_weighted_kappa,
    run_explanation_evaluation,
)


def _mock_completion(model: str, messages: list, temperature: float = 0.0, **kwargs):
    sys_msg = messages[0]["content"]
    if "strict cybersecurity evaluation judge" in sys_msg:
        score = 5 if model == "qwen-3.8-27b" else 4
        payload = {
            "factual_consistency": score,
            "evidence_grounding": score,
            "actionability": 4,
            "clarity": 5,
            "notes": "Mock judge",
        }
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(payload)))])
    user_msg = messages[-1]["content"]
    import re
    m = re.search(r"CVE-\d{4}-\d+", user_msg)
    cid = m.group(0) if m else "CVE-2021-44228"
    payload = {
        "cve_id": cid,
        "cvss_severity": "CRITICAL",
        "priority": "high",
        "explanation": f"Grounded explanation for {cid}.",
        "evidence_references": [f"benchmark_host:443_{cid}"],
        "uncertainties": ["None"],
        "recommended_remediation": "Patch immediately.",
    }
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(payload)))])


def test_quadratic_weighted_kappa_bounds():
    assert quadratic_weighted_kappa([5, 4, 3, 2, 1], [5, 4, 3, 2, 1]) == 1.0
    k = quadratic_weighted_kappa([5, 4, 4, 3, 5], [4, 4, 3, 3, 5])
    assert -1.0 <= k <= 1.0


def test_run_explanation_evaluation_offline_mock(tmp_path: Path):
    out_csv = tmp_path / "expl.csv"
    out_sum = tmp_path / "sum.json"
    out_raw = tmp_path / "raw.jsonl"
    res = run_explanation_evaluation(
        out_csv=out_csv,
        out_summary=out_sum,
        out_raw=out_raw,
        n_records=5,
        completion_fn=_mock_completion,
    )
    assert res["status"] == "COMPLETED"
    assert res["n_records"] == 5
    assert res["n_judge_rows"] == 10
    assert res["judge_prompt_sha256"] == JUDGE_PROMPT_SHA256
    rows = list(csv.DictReader(out_csv.open("r", encoding="utf-8")))
    assert len(rows) == 10
    assert rows[0]["judge_prompt_sha256"] == JUDGE_PROMPT_SHA256


def test_run_explanation_evaluation_handles_unavailable_judge(tmp_path: Path):
    import urllib.error

    def _fail_judge(**kwargs):
        raise urllib.error.HTTPError("https://api.cerebras.ai/v1/chat/completions", 402, "Payment Required", {}, None)

    out_csv = tmp_path / "expl.csv"
    out_sum = tmp_path / "sum.json"
    out_raw = tmp_path / "raw.jsonl"
    res = run_explanation_evaluation(
        out_csv=out_csv,
        out_summary=out_sum,
        out_raw=out_raw,
        n_records=5,
        completion_fn=_fail_judge,
    )
    assert res["status"] == "NOT_AVAILABLE"
    assert res["stub_validation_passed"] == 5
    rows = list(csv.DictReader(out_csv.open("r", encoding="utf-8")))
    assert rows[0]["status"] == "NOT_AVAILABLE"
