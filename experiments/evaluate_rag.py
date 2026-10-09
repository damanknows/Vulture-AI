import json
import os
import sys
import random

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# mock first
import sys
import types
litellm_mock = types.ModuleType("litellm")
litellm_mock.completion = lambda *a, **kw: MockLLM('{"priority": "high", "reason": "CVSS is high.", "evidence": ["unknown_CVE-MOCK"], "uncertainties": []}')
sys.modules["litellm"] = litellm_mock

from vulture_chatbot import chat_with_validation
from experiments.run_baselines import load_benchmark

# Mock litellm to avoid network calls during evaluation
class MockLLM:
    def __init__(self, content):
        self.choices = [self]
        self.message = self
        self.content = content

import types
import litellm
def mock_completion(*args, **kwargs):
    # Simulate a response that cites the evidence correctly
    # The source_id logic is <target>_<cve_id> which is "unknown_<cve_id>" here since target isn't set, 
    # but wait, retrieve_by_cve uses finding.get("finding").get("target", "unknown").
    return MockLLM('{"priority": "high", "reason": "CVSS is high.", "evidence": ["unknown_CVE-MOCK"], "uncertainties": []}')

litellm.completion = mock_completion

def evaluate_rag():
    findings, _ = load_benchmark("data/benchmark/cves.csv")
    sample = random.sample(findings, min(5, len(findings)))
    
    results = []
    for f in sample:
        cve_id = f["cve_matches"][0]["cve_id"]
        # run rag
        res = chat_with_validation(query=f"Why is {cve_id} a risk?", dataset=[f], cve_id=cve_id, finding=f)
        
        has_evidence = len(res.get("evidence", [])) > 0
        has_unsupported = len(res.get("uncertainties", [])) > 0 # uncertainties mapped to unsupported_claims in validator
        
        results.append({
            "cve_id": cve_id,
            "has_evidence": has_evidence,
            "has_unsupported_claims": has_unsupported,
            "manual_rubric_score": None # Placeholder
        })
        
    os.makedirs("experiments/results", exist_ok=True)
    with open("experiments/results/rag_eval.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    evaluate_rag()
