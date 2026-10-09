import re

PROMPT_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)you\s+are\s+now",
    r"(?i)system:",
    r"(?i)bypass",
    r"(?i)forget\s+everything"
]

def validate(claim: str, evidence: list[dict]) -> dict:
    result = {
        "valid": True,
        "unsupported_claims": [],
        "reason": ""
    }

    # 1. Detect prompt injection in evidence
    for doc in evidence:
        content = doc.get("content", "")
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, content):
                result["valid"] = False
                result["reason"] = f"Prompt injection detected in retrieved document: {doc.get('source_id')}"
                return result

    # Extract info from evidence
    valid_cves = set()
    valid_numbers = set()
    
    for doc in evidence:
        if doc.get("cve_id"):
            valid_cves.add(doc["cve_id"].lower())
            
        # Very crude numeric extraction from content (CVSS/EPSS)
        content_nums = re.findall(r'\b\d+\.\d+\b', doc.get("content", ""))
        valid_numbers.update([float(n) for n in content_nums])

    # 2. Reject any CVE ID in the claim not present in evidence
    claim_cves = re.findall(r'CVE-\d{4}-\d+', claim, re.IGNORECASE)
    for cve in claim_cves:
        if cve.lower() not in valid_cves:
            result["valid"] = False
            result["unsupported_claims"].append(cve)
            result["reason"] += f"Claim cites non-retrieved CVE: {cve}. "
            
    # 3. Check numeric values in claim
    # Extract floating point numbers that look like CVSS/EPSS
    claim_nums = re.findall(r'\b\d+\.\d+\b', claim)
    for num_str in claim_nums:
        val = float(num_str)
        # Check against evidence numbers with a small tolerance
        matched = False
        for valid_val in valid_numbers:
            if abs(val - valid_val) < 0.01:
                matched = True
                break
        
        # If we didn't find the exact number in the raw content, this is a basic check.
        # In reality, EPSS and CVSS might be formatted differently, but we follow instructions strictly.
        if not matched and valid_numbers: # Only reject if we have *some* numbers to compare against
            # Wait, this might be too strict if LLM outputs 9.80 instead of 9.8, but float comparison handles that.
            # What if the number is the VRS score? The LLM shouldn't output VRS, but we haven't stripped it yet in validation.
            result["valid"] = False
            result["unsupported_claims"].append(num_str)
            result["reason"] += f"Claim contains unsupported numeric value: {num_str}. "

    if not result["valid"]:
        result["reason"] = result["reason"].strip()

    return result
