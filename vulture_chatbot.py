import os
import json
import logging
from pydantic import BaseModel, ValidationError, Field
from typing import List, Optional
try:
    from litellm import completion
except ImportError:
    completion = None

import retrieval
import evidence_validator
import risk_engine

MODEL_NAME = os.getenv("MODEL_NAME", "ollama/llama3.2")
OLLAMA_API_BASE = os.getenv("OLLAMA_API_BASE", "http://localhost:11434")

class ChatbotResponse(BaseModel):
    cve_id: Optional[str] = Field(description="The primary CVE ID discussed, if any")
    cvss_severity: Optional[str] = Field(description="The severity level based on evidence")
    priority: str = Field(description="high, medium, or low")
    explanation: str = Field(description="Explanation of the vulnerability based ONLY on evidence. Distinguish facts from inferences.")
    evidence_references: List[str] = Field(description="List of source IDs used")
    uncertainties: List[str] = Field(description="List of things you are unsure about or unsupported")
    recommended_remediation: str = Field(description="Recommended steps to fix the issue")

SYSTEM_PROMPT = """You are a trustworthy Application Security Assistant.
You must ground your answers ONLY in the provided validated evidence.
Clearly distinguish observed facts (from scan banners), externally sourced facts (from NVD/EPSS), inferences, and unknowns.
DO NOT invent CVEs, CVSS values, EPSS values, scan observations, or affected versions.
DO NOT output the VRS score yourself. 

You must return your answer in STRICT JSON format matching this schema:
{
  "cve_id": "CVE-XXXX-XXXX or null",
  "cvss_severity": "CRITICAL|HIGH|MEDIUM|LOW or null",
  "priority": "high|medium|low",
  "explanation": "Explain based ONLY on evidence. State facts vs inferences clearly.",
  "evidence_references": ["list of source_ids used"],
  "uncertainties": ["list of things you are unsure about"],
  "recommended_remediation": "remediation advice"
}
Do not include markdown blocks around the JSON. Output raw JSON only.
"""

def _llm_kwargs(model: str) -> dict:
    if model.startswith("ollama/"):
        return {"api_base": OLLAMA_API_BASE}
    return {}

def chat_with_validation(query: str, dataset: list[dict], cve_id: str = None, finding: dict = None, model: str = MODEL_NAME, config_mode: str = "D") -> dict:
    """
    config_mode:
    A: LLM without retrieved evidence
    B: LLM with scan context
    C: LLM with RAG
    D: LLM with RAG plus evidence validation
    """
    evidence = []
    
    if config_mode in ["C", "D"]:
        if cve_id:
            evidence = retrieval.retrieve_by_cve(cve_id, dataset)
        else:
            evidence = retrieval.retrieve_by_query(query, dataset)
            
        if finding:
            target_ip = finding.get("finding", {}).get("target", "")
            evidence = [e for e in evidence if target_ip in e.get("source_id", "")]
            
    elif config_mode == "B":
        # Just scan context, no NVD/EPSS enrichment
        if finding:
            scan_fact = finding.get("finding", {})
            evidence = [{
                "source": "scan",
                "source_id": "scan_context",
                "cve_id": None,
                "applicability": "Direct scan observation",
                "content": json.dumps(scan_fact)
            }]
            
    # If mode A, evidence remains empty
            
    evidence_text = json.dumps(evidence, indent=2) if evidence else "No evidence provided."
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Query: {query}\n\nEvidence:\n{evidence_text}"}
    ]

    if completion is None:
        return _fallback_response("litellm dependency is missing.")
        
    try:
        response = completion(
            model=model,
            messages=messages,
            temperature=0.0,
            **_llm_kwargs(model)
        )
        raw_output = response.choices[0].message.content.strip()
        
        if raw_output.startswith("```json"):
            raw_output = raw_output[7:]
        if raw_output.endswith("```"):
            raw_output = raw_output[:-3]
            
        try:
            parsed = json.loads(raw_output.strip())
            validated = ChatbotResponse(**parsed).model_dump()
        except (json.JSONDecodeError, ValidationError) as e:
            return _fallback_response(f"LLM output violated schema: {e}")
            
        validated["validation_status"] = "unvalidated"
        
        if config_mode == "D":
            validation_res = evidence_validator.validate(validated.get("explanation", ""), evidence)
            if not validation_res["valid"]:
                validated["validation_status"] = "failed"
                validated["uncertainties"].extend(validation_res["unsupported_claims"])
                validated["explanation"] += f"\n\n[System Warning: Validation failed - {validation_res['reason']}]"
            else:
                validated["validation_status"] = "passed"
                
        # Re-inject VRS immutably
        validated["vrs_score"] = None
        if finding:
            vrs_data = risk_engine.compute_vrs(finding)
            validated["vrs_score"] = vrs_data.get("vrs")
            
        return validated
        
    except Exception as e:
        logging.error(f"Generation error: {e}")
        return _fallback_response(f"Internal error: {e}")

def _fallback_response(reason: str) -> dict:
    return {
        "cve_id": None,
        "cvss_severity": None,
        "priority": "low",
        "explanation": f"Unable to generate explanation. {reason}",
        "evidence_references": [],
        "uncertainties": ["System failure"],
        "recommended_remediation": "Unknown",
        "validation_status": "failed",
        "vrs_score": None
    }
