import os
import time
import datetime
import hashlib
import traceback
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from vulture_chatbot import analyze, chat, load_scan, ensure_sample_scan_data, MODEL_NAME, SCAN_FILE

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

# Ensure sample data exists and load it once at startup
ensure_sample_scan_data(SCAN_FILE)
SCAN_DATA = load_scan(SCAN_FILE)

app = Flask(__name__, static_folder="static")
CORS(app)

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

def create_scan_entry(target):
    global scan_counter
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    scan_id = scan_counter
    scan_counter += 1
    
    # Generate target-specific findings deterministically using IP hash
    hash_val = int(hashlib.md5(target.encode('utf-8')).hexdigest(), 16)
    
    # Pick 2 to 5 services uniquely for this IP target
    num_svcs = 2 + (hash_val % 4)
    raw_indices = [(hash_val + i * 3) % len(SERVICE_CATALOG) for i in range(num_svcs)]
    unique_indices = list(dict.fromkeys(raw_indices))
    
    selected_services = [SERVICE_CATALOG[idx] for idx in unique_indices]
    v_count = len(selected_services)
    
    ports = []
    scan_vulnerability_list = []
    
    for i, s in enumerate(selected_services):
        port_id = (scan_id * 100) + i + 1
        vuln_id = (scan_id * 1000) + i + 1
        
        ports.append({
            "id": port_id,
            "number": s["port"],
            "protocol": s["protocol"],
            "state": "open",
            "service_name": s["name"],
            "service_product": s["product"],
            "service_version": s["version"],
            "service_extra": ""
        })
        
        scan_vulnerability_list.append({
            "id": vuln_id,
            "port_id": port_id,
            "cve_id": s["cve"],
            "description": s["desc"],
            "cvss_v3_score": s["score"],
            "severity": s["severity"],
            "published": now,
            "matched_cpe": f"cpe:2.3:a:{s['name']}:{s['product'].lower().replace(' ', '_')}:{s['version']}"
        })
        
    hostname = "localhost" if target in ["127.0.0.1", "localhost"] else f"host-{hash_val % 1000}.local"
    
    entry = {
        "id": scan_id,
        "target": target,
        "state": "completed",
        "created_at": now,
        "started_at": now,
        "finished_at": now,
        "host_count": 1,
        "vulnerability_count": v_count,
        "hosts": [
            {
                "id": scan_id * 10,
                "ip": target,
                "hostname": hostname,
                "state": "up",
                "ports": ports
            }
        ],
        "_vulnerabilities": scan_vulnerability_list
    }
    scans_db.insert(0, entry)
    return entry

# Create initial seed scans for demonstration
create_scan_entry("172.25.208.1")
create_scan_entry("127.0.0.1")
create_scan_entry("172.25.236.144")

# ─── Serve the React SPA (exact frontend from vulture-ai-o63e.onrender.com) ───

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/vulture-logo.jpg')
def logo():
    return send_from_directory(app.static_folder, 'vulture-logo.jpg')

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    return send_from_directory(os.path.join(app.static_folder, 'assets'), filename)

# ─── Scans API for React Frontend ─────────────────────────────────────────────

@app.route('/api/scans', methods=['GET', 'POST'])
def api_scans():
    if request.method == 'POST':
        data = request.json or {}
        target = data.get("target", "127.0.0.1")
        entry = create_scan_entry(target)
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
        reply = analyze(SCAN_DATA, MODEL_NAME)
        return jsonify({"reply": reply})
    except Exception as e:
        logger.error("Error in /api/analyze: %s", e)
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def api_chat():
    try:
        data = request.json or {}
        question = data.get("question", "")
        history = data.get("history", [])
        
        reply = chat(SCAN_DATA, history, question, MODEL_NAME)
        return jsonify({"reply": reply})
    except Exception as e:
        logger.error("Error in /api/chat: %s", e)
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/model', methods=['GET'])
def get_model():
    return jsonify({"model": MODEL_NAME})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

# ─── SPA fallback: any unknown route serves index.html (for React Router) ─────

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
