import os
import time
import datetime
import hashlib
import traceback
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from vulture_chatbot import chat_with_validation, MODEL_NAME
from scanner import scan_target
from cve_matcher import match_findings_to_cves
from cve_matcher import match_findings_to_cves

# ASCII Art
VULTURE_ART = r"""
 __      __  _    _  _       _______  _    _  _____   ______ 
 \ \    / / | |  | || |     |__   __|| |  | ||  __ \ |  ____|
  \ \  / /  | |  | || |        | |   | |  | || |__) || |__   
   \ \/  /   | |  | || |        | |   | |  | ||  _  / |  __|  
    \  /    | |__| || |____    | |   | |__| || | \ \ | |____ 
     \/      \____/ |______|   |_|    \____/ |_|  \_\|______|
"""

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SCAN_DATA = []
ENRICHED_FINDINGS = []

app = Flask(__name__, static_folder="static")

class Config:
    PORT = int(os.environ.get("PORT", 5000))
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
    DEMO_MODE = os.environ.get("VULTURE_DEMO_MODE", "0") == "1"

app.config.from_object(Config)


cors_origins = os.environ.get("VULTURE_CORS_ORIGINS", "").split(",")
cors_origins = [o.strip() for o in cors_origins if o.strip()]
if not cors_origins:
    cors_origins = ["http://localhost:3000", "http://localhost:5000"]
CORS(app, origins=cors_origins)

# Request size limit (1MB)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024


# In-memory scan store for React UI
scans_db = []
scan_counter = 1

SERVICE_CATALOG = [
    {"port": 80, "protocol": "tcp", "name": "http", "product": "Apache httpd", "version": "2.4.49", "cve": "CVE-2021-41773", "desc": "Path Traversal & RCE in Apache HTTP Server 2.4.49", "score": 9.8, "severity": "CRITICAL"},
    {"port": 443, "protocol": "tcp", "name": "https", "product": "nginx", "version": "1.18.0", "cve": "CVE-2021-23017", "desc": "1-byte memory overwrite in resolver via crafted DNS response", "score": 7.7, "severity": "HIGH"},
    {"port": 22, "protocol": "tcp", "name": "ssh", "product": "OpenSSH", "version": "7.4", "cve": "CVE-2018-15473", "desc": "User enumeration vulnerability in OpenSSH timing side-channel", "score": 5.3, "severity": "MEDIUM"},
    {"port": 3306, "protocol": "tcp", "name": "mysql", "product": "MySQL Server", "version": "8.0.27", "cve": "CVE-2022-1292", "desc": "OpenSSL c_rehash script command injection bundled with MySQL", "score": 9.8, "severity": "CRITICAL"},
    {"port": 5432, "protocol": "tcp", "name": "postgresql", "product": "PostgreSQL", "version": "14.2", "cve": "CVE-2022-1552", "desc": "Privilege escalation via pg_signal_backend role misuse", "score": 8.8, "severity": "HIGH"},
    {"port": 6379, "protocol": "tcp", "name": "redis", "product": "Redis Cache", "version": "6.0.9", "cve": "CVE-2021-32625", "desc": "Integer overflow in STRALGO LCS leading to memory corruption", "score": 6.5, "severity": "MEDIUM"},
    {"port": 21, "protocol": "tcp", "name": "ftp", "product": "ProFTPD", "version": "1.3.5", "cve": "CVE-2015-3306", "desc": "Mod_copy unauthenticated arbitrary file copy RCE chain", "score": 10.0, "severity": "CRITICAL"},
    {"port": 8080, "protocol": "tcp", "name": "http-alt", "product": "Apache Tomcat", "version": "9.0.50", "cve": "CVE-2022-22965", "desc": "Spring4Shell RCE via data binding in Spring MVC on Tomcat", "score": 9.8, "severity": "CRITICAL"},
    {"port": 25, "protocol": "tcp", "name": "smtp", "product": "Exim Mail Server", "version": "4.94.2", "cve": "CVE-2019-15846", "desc": "RCE via sender address buffer overflow in Exim", "score": 9.8, "severity": "CRITICAL"},
    {"port": 9200, "protocol": "tcp", "name": "elasticsearch", "product": "Elasticsearch", "version": "7.16.3", "cve": "CVE-2022-23710", "desc": "Heap OOB read leading to information disclosure", "score": 7.5, "severity": "HIGH"}
]


def run_demo_scan(target):
    global scan_counter
    import datetime, hashlib
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    scan_id = scan_counter
    scan_counter += 1
    
    hash_val = int(hashlib.md5(target.encode('utf-8')).hexdigest(), 16)
    num_svcs = 2 + (hash_val % 4)
    raw_indices = [(hash_val + i * 3) % len(SERVICE_CATALOG) for i in range(num_svcs)]
    unique_indices = list(dict.fromkeys(raw_indices))
    
    selected_services = [SERVICE_CATALOG[idx] for idx in unique_indices]
    
    ports = []
    scan_vulnerability_list = []
    for i, s in enumerate(selected_services):
        port_id = (scan_id * 100) + i + 1
        vuln_id = (scan_id * 1000) + i + 1
        ports.append({
            "id": port_id, "number": s["port"], "protocol": s["protocol"], "state": "open",
            "service_name": s["name"], "service_product": s["product"], "service_version": s["version"], "service_extra": ""
        })
        scan_vulnerability_list.append({
            "id": vuln_id, "port_id": port_id, "cve_id": s["cve"], "description": s["desc"],
            "cvss_v3_score": s["score"], "severity": s["severity"], "published": now, "matched_cpe": ""
        })
        
    entry = {
        "id": scan_id, "target": target, "state": "completed",
        "created_at": now, "started_at": now, "finished_at": now,
        "host_count": 1, "vulnerability_count": len(scan_vulnerability_list),
        "hosts": [{"id": scan_id * 10, "ip": target, "hostname": target, "state": "up", "ports": ports}],
        "_vulnerabilities": scan_vulnerability_list
    }
    scans_db.insert(0, entry)
    return entry

def run_real_scan(target):
    global scan_counter
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    scan_id = scan_counter
    scan_counter += 1
    
    scan_res = scan_target(target)
    

    ports = []
    scan_vulnerability_list = []
    v_count = 0
    if scan_res.get("scan_status") == "completed":
        findings = scan_res.get("findings", [])
        
        # Connect enrichment pipeline
        enriched = match_findings_to_cves(findings)
        
        global ENRICHED_FINDINGS
        ENRICHED_FINDINGS.extend(enriched)
        
        for i, f in enumerate(enriched):
            raw = f["finding"]
            port_id = (scan_id * 100) + i + 1
            vuln_id = (scan_id * 1000) + i + 1
            
            ports.append({
                "id": port_id,
                "number": int(raw.get("port", 0)),
                "protocol": raw.get("protocol", ""),
                "state": "open",
                "service_name": raw.get("service", ""),
                "service_product": raw.get("product", ""),
                "service_version": raw.get("version", ""),
                "service_extra": f"Confidence: {raw.get('detection_confidence', 'unknown')}"
            })
            
            for cve in f.get("cve_matches", []):
                v_count += 1
                scan_vulnerability_list.append({
                    "id": vuln_id + v_count,
                    "port_id": port_id,
                    "cve_id": cve.get("cve_id"),
                    "description": cve.get("affected_product", ""),
                    "cvss_v3_score": cve.get("cvss_score", 0.0),
                    "severity": cve.get("cvss_severity", "UNKNOWN"),
                    "published": cve.get("epss_date", now),
                    "matched_cpe": ""
                })
                
    entry = {
        "id": scan_id,
        "target": target,
        "state": scan_res.get("scan_status", "failed"),
        "created_at": now,
        "started_at": now,
        "finished_at": now,
        "host_count": 1,
        "vulnerability_count": v_count,
        "hosts": [{"id": scan_id * 10, "ip": target, "hostname": target, "state": "up", "ports": ports}],
        "_vulnerabilities": scan_vulnerability_list
    }

    scans_db.insert(0, entry)
    return entry

@app.route('/api/scans', methods=['GET', 'POST'])
def api_scans():
    if request.method == 'POST':
        data = request.json or {}
        target = data.get("target", "127.0.0.1")
        if app.config.get("DEMO_MODE"):
            entry = run_demo_scan(target)
        else:
            entry = run_real_scan(target)
        summary = {k: v for k, v in entry.items() if not k.startswith("_") and k != "hosts"}
        return jsonify(summary), 201
    else:
        summaries = [{k: v for k, v in entry.items() if not k.startswith("_") and k != "hosts"} for entry in scans_db]
        return jsonify(summaries)


@app.route('/api/scans/<int:scan_id>', methods=['GET'])
def api_scan_detail(scan_id):
    for entry in scans_db:
        if entry["id"] == scan_id:
            res = {k: v for k, v in entry.items() if not k.startswith("_")}
            return jsonify(res)
    return jsonify({"detail": "scan not found"}), 404

@app.route('/api/hosts/vulnerabilities', methods=['GET'])
def api_hosts_vulnerabilities():
    scan_id_arg = request.args.get('scan_id')
    if scan_id_arg:
        try:
            scan_id = int(scan_id_arg)
            for entry in scans_db:
                if entry["id"] == scan_id:
                    return jsonify(entry.get("_vulnerabilities", []))
        except ValueError:
            pass
    all_vulns = []
    for entry in scans_db:
        all_vulns.extend(entry.get("_vulnerabilities", []))
    return jsonify(all_vulns)

# ─── Chatbot API endpoints ────────────────────────────────────────────────────

@app.route('/api/scan', methods=['GET'])
def get_scan():
    return jsonify(SCAN_DATA)



@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    try:
        result = chat_with_validation(query="Analyze the overall scan results.", dataset=ENRICHED_FINDINGS, model=MODEL_NAME)
        reply = f"Priority: {result.get('priority', 'unknown')}\nReason: {result.get('explanation', '')}"
        return jsonify({"reply": reply})
    except Exception as e:
        logger.error("Error in /api/analyze: %s", e)
        # Omitted traceback to prevent sensitive data leakage
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/api/chat', methods=['POST'])
def api_chat():
    try:
        data = request.json or {}
        question = data.get("question", "")
        result = chat_with_validation(query=question, dataset=ENRICHED_FINDINGS, model=MODEL_NAME)
        reply = f"Priority: {result.get('priority', 'unknown')}\nReason: {result.get('explanation', '')}"
        return jsonify({"reply": reply})
    except Exception as e:
        logger.error("Error in /api/chat: %s", e)
        # Omitted traceback to prevent sensitive data leakage
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/api/model', methods=['GET'])
def get_model():
    return jsonify({"model": MODEL_NAME})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

# ─── SPA fallback: any unknown route serves index.html (for React Router) ─────


@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')

def catch_all(path):
    file_path = os.path.join(app.static_folder, path)
    if os.path.isfile(file_path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    print(VULTURE_ART)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
