"""Standalone smoke test runner using stdlib unittest.

This file is the fallback when pytest isn't installable (e.g. CI without
network access). It exercises the parser, the matcher, and the target
validation — the same things pytest covers — using only stdlib.
"""
from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import unittest
import warnings
from pathlib import Path
from unittest.mock import MagicMock

# Python 3.12+ turned DeprecationWarning into errors by default in some
# configurations. We don't want cosmetic datetime.utcnow warnings to mask
# actual test failures.
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Make project root importable.
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Force a workspace-local CWD so the Settings class doesn't read the user's
# real .env. Use the sandbox-writable workspace rather than %TEMP%.
_ws_tmp = Path(ROOT) / ".unittest-tmp"
_ws_tmp.mkdir(exist_ok=True)
os.chdir(_ws_tmp)


class TargetValidationTests(unittest.TestCase):
    def test_loopback(self):
        from backend.config import is_target_allowed
        self.assertTrue(is_target_allowed("127.0.0.1"))

    def test_rfc1918(self):
        from backend.config import is_target_allowed
        self.assertTrue(is_target_allowed("10.0.0.5"))
        self.assertTrue(is_target_allowed("192.168.1.1"))
        self.assertTrue(is_target_allowed("172.16.0.1"))

    def test_public_rejected(self):
        from backend.config import is_target_allowed
        self.assertFalse(is_target_allowed("8.8.8.8"))

    def test_shell_metachars_rejected(self):
        from backend.config import is_target_allowed
        with self.assertRaises(ValueError):
            is_target_allowed("; rm -rf /")
        with self.assertRaises(ValueError):
            is_target_allowed("not-an-ip")

    def test_cidr_format(self):
        from backend.config import is_target_allowed
        self.assertTrue(is_target_allowed("127.0.0.1/32"))


class NmapParserTests(unittest.TestCase):
    SAMPLE = textwrap.dedent(
        """\
        <?xml version="1.0"?>
        <nmaprun args="nmap -sV 127.0.0.1">
          <host>
            <status state="up"/>
            <address addr="127.0.0.1" addrtype="ipv4"/>
            <hostnames><hostname name="localhost"/></hostnames>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu-4ubuntu0.5"/>
              </port>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache httpd" version="2.4.41"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
    )

    def test_parses_two_ports(self):
        from scanner.scanner import parse_nmap_xml
        r = parse_nmap_xml(self.SAMPLE, target="127.0.0.1")
        self.assertEqual(len(r.hosts), 1)
        h = r.hosts[0]
        self.assertEqual(h.ip, "127.0.0.1")
        self.assertEqual(h.hostname, "localhost")
        self.assertEqual(len(h.ports), 2)
        self.assertEqual(h.ports[0].number, 22)
        self.assertEqual(h.ports[0].service.product, "OpenSSH")
        self.assertEqual(h.ports[1].service.product, "Apache httpd")

    def test_empty_xml(self):
        from scanner.scanner import parse_nmap_xml
        r = parse_nmap_xml("", target="127.0.0.1")
        self.assertEqual(r.hosts, [])


class CveMatcherTests(unittest.TestCase):
    def test_normalize_messy_version(self):
        from scanner.cve_matcher import normalize_service_string
        norm = normalize_service_string(
            product="OpenSSH", version="8.2p1", extra="Ubuntu-4ubuntu0.5"
        )
        self.assertIsNotNone(norm)
        vendor, product, version = norm
        self.assertEqual(vendor, "OpenSSH")
        self.assertIn("openssh", product)
        self.assertTrue(version.startswith("8.2"))

    def test_normalize_distro_suffix(self):
        from scanner.cve_matcher import normalize_service_string
        norm = normalize_service_string(
            product="MySQL", version="5.7.33-0ubuntu0.16.04.1", extra=None
        )
        self.assertEqual(norm[2], "5.7.33")

    def test_normalize_returns_none_without_inputs(self):
        from scanner.cve_matcher import normalize_service_string
        self.assertIsNone(normalize_service_string(product=None, version="1.2"))
        self.assertIsNone(normalize_service_string(product="nginx", version=None))

    def test_build_cpe_uris_escaping(self):
        from scanner.cve_matcher import build_cpe_uris
        uris = build_cpe_uris("Apache", "Apache httpd", "2.4.41")
        self.assertTrue(any("apache" in u for u in uris))
        for u in uris:
            self.assertTrue(u.startswith("cpe:2.3:a:"))
        # Spaces must be escaped.
        joined = " ".join(uris)
        self.assertIn("\\ ", joined)

    def test_match_cves_with_mocked_nvd(self):
        from backend.db.session import init_db, session_scope
        from scanner import cve_matcher
        from scanner.models import PortResult, ScanResult, ServiceInfo, HostResult

        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-12345",
                        "descriptions": [{"lang": "en", "value": "Bad"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                            ]
                        },
                        "published": "2021-03-04T05:15:00.000",
                    }
                }
            ]
        }
        session.get.return_value = resp

        init_db()
        scan = ScanResult(target="127.0.0.1")
        scan.hosts.append(HostResult(ip="127.0.0.1"))
        scan.hosts[0].ports.append(
            PortResult(number=22, service=ServiceInfo(product="OpenSSH", version="8.2p1", extra="Ubuntu-4ubuntu0.5"))
        )

        with session_scope() as db:
            results = cve_matcher.match_cves_for_scan(scan, db, http_session=session)
        cves = results[0]
        self.assertTrue(any(c.cve_id == "CVE-2021-12345" for c in cves))
        self.assertTrue(any(c.cvss.severity == "CRITICAL" for c in cves))

    def test_match_cves_handles_unreachable_nvd(self):
        from backend.db.session import init_db, session_scope
        from scanner import cve_matcher
        from scanner.models import PortResult, ServiceInfo

        bad = MagicMock()
        bad.get.side_effect = RuntimeError("network down")
        init_db()
        port = PortResult(number=80, service=ServiceInfo(product="nginx", version="1.18.0"))
        with session_scope() as db:
            self.assertEqual(cve_matcher.match_cves_for_port(port, db, http_session=bad), [])

    def test_match_cves_handles_rate_limit(self):
        from backend.db.session import init_db, session_scope
        from scanner import cve_matcher
        from scanner.models import PortResult, ServiceInfo

        rl = MagicMock()
        rl_resp = MagicMock()
        rl_resp.status_code = 429
        rl.get.return_value = rl_resp
        init_db()
        port = PortResult(number=443, service=ServiceInfo(product="nginx", version="1.18.0"))
        with session_scope() as db:
            self.assertEqual(cve_matcher.match_cves_for_port(port, db, http_session=rl), [])


class ScanStateMachineTests(unittest.TestCase):
    def test_transition_paths(self):
        from backend.db.models import Scan, ScanState
        s = Scan(target="127.0.0.1")
        self.assertEqual(s.state, ScanState.QUEUED)
        self.assertTrue(s.transition_to(ScanState.RUNNING))
        self.assertTrue(s.transition_to(ScanState.COMPLETED))
        # Terminal states cannot transition further.
        self.assertFalse(s.transition_to(ScanState.RUNNING))
        self.assertFalse(s.transition_to(ScanState.FAILED))

    def test_cannot_skip_states(self):
        from backend.db.models import Scan, ScanState
        s = Scan(target="127.0.0.1")
        # Cannot jump queued -> completed.
        self.assertFalse(s.transition_to(ScanState.COMPLETED))
        # Cannot jump queued -> failed mid-flight? Actually FAILED is allowed
        # from QUEUED — the runner may bail before starting. Verify that.
        self.assertTrue(s.transition_to(ScanState.FAILED))


class ApiSmokeTests(unittest.TestCase):
    def test_app_registers_routes(self):
        from backend.main import create_app
        app = create_app()
        paths = sorted({r.path for r in app.routes if hasattr(r, "path")})
        self.assertIn("/health", paths)
        self.assertIn("/scans", paths)
        self.assertIn("/scans/{scan_id}", paths)
        self.assertIn("/hosts", paths)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        # Discard the cached engine so the in-memory SQLite connection
        # closes cleanly and avoids ResourceWarning noise.
        try:
            from backend.db import session as _s
            if _s._engine is not None:
                _s._engine.dispose()
                _s._engine = None
                _s._SessionLocal = None
        except Exception:
            pass
