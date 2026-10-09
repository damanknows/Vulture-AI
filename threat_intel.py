import os
import json
import time
import hashlib
import requests
from datetime import datetime, timezone
from urllib.parse import urlencode

CACHE_DIR = os.path.join("data", "cache")
CACHE_TTL = 86400  # 24 hours

os.makedirs(CACHE_DIR, exist_ok=True)

def _get_cache_path(url: str) -> str:
    h = hashlib.sha256(url.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{h}.json")

def _read_cache(url: str) -> dict:
    path = _get_cache_path(url)
    if os.path.exists(path):
        mtime = os.path.getmtime(path)
        if time.time() - mtime < CACHE_TTL:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                pass
    return None

def _write_cache(url: str, data: dict):
    path = _get_cache_path(url)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except:
        pass

def _fetch_url(url: str, headers: dict = None) -> dict:
    cached = _read_cache(url)
    if cached is not None:
        return cached
    
    # Simple sleep for rate limiting NVD. Wait 6 seconds (10 req/min for safety)
    if "nvd.nist.gov" in url:
        time.sleep(6)
        
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        _write_cache(url, data)
        return data
    except Exception as e:
        return {"error": str(e)}

def fetch_nvd(cve_id: str) -> dict:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
        
    retrieved_at = datetime.now(timezone.utc).isoformat()
    data = _fetch_url(url, headers=headers)
    
    if "error" in data:
        return {
            "source": "nvd",
            "source_record_id": cve_id,
            "retrieved_at": retrieved_at,
            "error": data["error"]
        }
        
    return {
        "source": "nvd",
        "source_record_id": cve_id,
        "retrieved_at": retrieved_at,
        "data": data
    }

def fetch_epss(cve_ids: list[str]) -> dict:
    """Returns {cve_id: epss_score}"""
    if not cve_ids:
        return {}
    
    cves_param = ",".join(cve_ids)
    url = f"https://api.first.org/data/v1/epss?cve={cves_param}"
    retrieved_at = datetime.now(timezone.utc).isoformat()
    
    data = _fetch_url(url)
    if "error" in data:
        return {
            "source": "epss",
            "source_record_id": "batch",
            "retrieved_at": retrieved_at,
            "error": data["error"]
        }
    
    results = {}
    for item in data.get("data", []):
        results[item["cve"]] = float(item["epss"])
        
    return {
        "source": "epss",
        "source_record_id": "batch",
        "retrieved_at": retrieved_at,
        "data": results
    }

def fetch_kev() -> dict:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    retrieved_at = datetime.now(timezone.utc).isoformat()
    
    data = _fetch_url(url)
    if "error" in data:
        return {
            "source": "kev",
            "source_record_id": "cisa_kev",
            "retrieved_at": retrieved_at,
            "error": data["error"]
        }
        
    cve_set = set(item["cveID"] for item in data.get("vulnerabilities", []))
    return {
        "source": "kev",
        "source_record_id": "cisa_kev",
        "retrieved_at": retrieved_at,
        "data": {"cves": list(cve_set)}
    }

def search_nvd(keyword: str) -> dict:
    """Helper to search NVD via keywordSearch"""
    params = {"keywordSearch": keyword}
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{urlencode(params)}"
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
        
    retrieved_at = datetime.now(timezone.utc).isoformat()
    data = _fetch_url(url, headers=headers)
    
    if "error" in data:
        return {
            "source": "nvd",
            "source_record_id": f"search:{keyword}",
            "retrieved_at": retrieved_at,
            "error": data["error"]
        }
        
    return {
        "source": "nvd",
        "source_record_id": f"search:{keyword}",
        "retrieved_at": retrieved_at,
        "data": data
    }
