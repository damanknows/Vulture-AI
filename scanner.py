import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

def is_target_allowed(target: str) -> bool:
    allowed_targets = os.environ.get("VULTURE_ALLOWED_TARGETS", "127.0.0.1,localhost").split(",")
    allowed_targets = [t.strip() for t in allowed_targets if t.strip()]
    return target in allowed_targets

def scan_target(target: str, ports: str = "1-1000", timeout: int = 300) -> dict:
    """
    Run an Nmap scan against an authorized target and return structured results.
    Returns: {"target": str, "scan_status": "completed"|"failed"|"timeout",
              "findings": [ {target, port, protocol, service, product,
                             version, evidence_source, scan_timestamp} ],
              "error": str|None, "raw_xml_path": str}
    """
    scan_timestamp = datetime.now(timezone.utc).isoformat()
    result = {
        "target": target,
        "scan_status": "failed",
        "findings": [],
        "error": None,
        "raw_xml_path": ""
    }

    if not is_target_allowed(target):
        result["error"] = f"Target {target} is not in the allowlist."
        return result

    raw_dir = os.path.join("data", "raw", "nmap")
    os.makedirs(raw_dir, exist_ok=True)
    
    # Sanitize timestamp for filename
    safe_ts = scan_timestamp.replace(":", "").replace("+", "Z")
    raw_xml_path = os.path.join(raw_dir, f"{target}_{safe_ts}.xml")
    result["raw_xml_path"] = raw_xml_path

    # Construct Nmap command
    # -sV: Version detection
    # -T4: Timing template (aggressive)
    # --host-timeout: Give up on target after this long
    # -oX -: Output XML to stdout
    cmd = [
        "nmap",
        "-sV",
        "-T4",
        f"--host-timeout={timeout}s",
        "-p", ports,
        "-oX", "-",
        target
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0 and not proc.stdout:
            result["error"] = f"Nmap failed: {proc.stderr}"
            return result
            
        xml_output = proc.stdout
    except subprocess.TimeoutExpired:
        result["scan_status"] = "timeout"
        result["error"] = f"Scan exceeded timeout of {timeout} seconds."
        return result
    except Exception as e:
        result["error"] = f"Error executing Nmap: {e}"
        return result

    try:
        with open(raw_xml_path, "w", encoding="utf-8") as f:
            f.write(xml_output)
    except IOError as e:
        result["error"] = f"Failed to save raw XML: {e}"
        return result

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        result["error"] = f"Failed to parse Nmap XML output: {e}"
        return result

    for host in root.findall('host'):
        address = host.find('address')
        if address is None or address.get('addr') != target:
            # If addr doesn't exactly match target, we might skip, but let's just use target
            host_target = target
            if address is not None:
                host_target = address.get('addr') or target
        else:
            host_target = target

        ports_el = host.find('ports')
        if ports_el is not None:
            for port in ports_el.findall('port'):
                state_el = port.find('state')
                if state_el is None or state_el.get('state') != 'open':
                    continue
                
                portid = port.get('portid')
                protocol = port.get('protocol')
                
                service_el = port.find('service')
                service = None
                product = None
                version = None
                
                if service_el is not None:
                    service = service_el.get('name')
                    product = service_el.get('product')
                    version = service_el.get('version')
                
                result["findings"].append({
                    "target": host_target,
                    "port": portid,
                    "protocol": protocol,
                    "service": service,
                    "product": product,
                    "version": version,
                    "evidence_source": "nmap",
                    "scan_timestamp": scan_timestamp
                })

    result["scan_status"] = "completed"
    return result
