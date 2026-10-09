"""
Vulture-AI scan chatbot - Refactored for Retrieval + Validation + Generation
"""

import os
import json
import logging
import argparse
from datetime import datetime
from litellm import completion

import retrieval
import evidence_validator
import risk_engine

MODEL_NAME = os.getenv("MODEL_NAME", "ollama/llama3.2")
OLLAMA_API_BASE = os.getenv("OLLAMA_API_BASE", "http://localhost:11434")

SYSTEM_PROMPT = """You are an expert Application Security Assistant.
You must ground your answers ONLY in the provided validated evidence.
Do NOT output the VRS score. 

You must return your answer in STRICT JSON format exactly matching this schema:
{
  "priority": "high|medium|low",
  "reason": "Explain the priority based on the evidence.",
  "evidence": ["list of source_ids used"],
  "uncertainties": ["list of things you are unsure about"]
}
Do not include markdown blocks around the JSON. Output raw JSON only.
"""

def _llm_kwargs(model: str) -> dict:
    if model.startswith("ollama/"):
        return {"api_base": OLLAMA_API_BASE}
    return {}

def chat_with_validation(query: str, dataset: list[dict], cve_id: str = None, finding: dict = None, model: str = MODEL_NAME) -> dict:
    # 1. Retrieval
    if cve_id:
        evidence = retrieval.retrieve_by_cve(cve_id, dataset)
    else:
        evidence = retrieval.retrieve_by_query(query, dataset)
        
    # Filter evidence if a specific finding is targeted
    if finding:
        target_ip = finding.get("finding", {}).get("target", "")
        evidence = [e for e in evidence if target_ip in e.get("source_id", "")]
        
    if not evidence:
        return {
            "priority": "low",
            "reason": "Unable to generate a grounded explanation (No evidence retrieved).",
            "evidence": [],
            "uncertainties": ["No matching evidence found in the dataset."]
        }
        
    # Build prompt with evidence
    evidence_text = json.dumps(evidence, indent=2)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Query: {query}\n\nEvidence:\n{evidence_text}"}
    ]
    
    # 2. Generation
    try:
        response = completion(
            model=model,
            messages=messages,
            temperature=0.1,
            **_llm_kwargs(model)
        )
        raw_output = response.choices[0].message.content.strip()
        
        # Remove potential markdown formatting
        if raw_output.startswith("```json"):
            raw_output = raw_output[7:]
        if raw_output.endswith("```"):
            raw_output = raw_output[:-3]
            
        parsed = json.loads(raw_output.strip())
        
        # 3. Validation
        validation_res = evidence_validator.validate(parsed.get("reason", ""), evidence)
        if not validation_res["valid"]:
            return {
                "priority": "low",
                "reason": f"Unable to generate a grounded explanation. Validation failed: {validation_res['reason']}",
                "evidence": [],
                "uncertainties": validation_res["unsupported_claims"]
            }
            
        # 4. Re-inject VRS
        # If finding is provided, compute VRS
        if finding:
            vrs_data = risk_engine.compute_vrs(finding)
            parsed["vrs_score"] = vrs_data["vrs"]
            parsed["vrs_bucket"] = vrs_data["bucket"]
            
        return parsed
        
    except json.JSONDecodeError:
        return {
            "priority": "low",
            "reason": "Unable to generate a grounded explanation (LLM output was not valid JSON).",
            "evidence": [],
            "uncertainties": []
        }
    except Exception as e:
        logging.error(f"Generation error: {e}")
        return {
            "priority": "low",
            "reason": "Unable to generate a grounded explanation (Internal error).",
            "evidence": [],
            "uncertainties": []
        }

if __name__ == "__main__":
    pass
