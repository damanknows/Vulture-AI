import os
import subprocess
import pytest
from scanner import is_target_allowed, scan_target

@pytest.fixture
def mock_nmap_xml():
    return """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" version="8.2p1" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="conn-refused" reason_ttl="0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

def test_is_target_allowed(monkeypatch):
    monkeypatch.setenv("VULTURE_ALLOWED_TARGETS", "127.0.0.1, 10.0.0.5")
    assert is_target_allowed("127.0.0.1") is True
    assert is_target_allowed("10.0.0.5") is True
    assert is_target_allowed("192.168.1.1") is False

def test_scan_target_allowlist_rejection():
    # Should reject unless in default allowlist
    result = scan_target("8.8.8.8")
    assert result["scan_status"] == "failed"
    assert "not in the allowlist" in result["error"]

def test_scan_target_success(monkeypatch, mock_nmap_xml, tmp_path):
    # Mock subprocess.run
    class MockProcess:
        returncode = 0
        stdout = mock_nmap_xml
        stderr = ""
        
    def mock_run(*args, **kwargs):
        return MockProcess()
        
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    # Need to mock raw directory to not write into data/raw in tests, or we can just let it write.
    # To be clean, let's mock the os.makedirs and open, or just let it write to data/raw/nmap for tests.
    
    result = scan_target("127.0.0.1", "22,80")
    
    assert result["scan_status"] == "completed"
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["port"] == "22"
    assert finding["protocol"] == "tcp"
    assert finding["service"] == "ssh"
    assert finding["product"] == "OpenSSH"
    assert finding["version"] == "8.2p1"
    assert finding["evidence_source"] == "nmap"

def test_scan_target_timeout(monkeypatch):
    def mock_run_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 0))
        
    monkeypatch.setattr(subprocess, "run", mock_run_timeout)
    
    result = scan_target("127.0.0.1")
    assert result["scan_status"] == "timeout"
    assert "exceeded timeout" in result["error"]

@pytest.mark.integration
@pytest.mark.skip(reason="integration")
def test_real_scan_target():
    # This will run a real nmap scan if executed
    result = scan_target("127.0.0.1", "22")
    assert result["scan_status"] == "completed"
    assert isinstance(result["findings"], list)
