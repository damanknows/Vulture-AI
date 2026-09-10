"""Unit tests for the Nmap XML parser (no network, no subprocess)."""
from __future__ import annotations

import textwrap

from scanner.scanner import parse_nmap_xml


SAMPLE_XML = textwrap.dedent(
    """\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap -sV -p 22,80 127.0.0.1" start="1700000000" version="7.94">
      <host>
        <status state="up"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <hostnames><hostname name="localhost" type="user"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu-4ubuntu0.5"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.41"/>
          </port>
          <port protocol="tcp" portid="9999">
            <state state="closed" reason="reset"/>
            <service name="unknown"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
)


def test_parses_single_host_with_three_ports():
    result = parse_nmap_xml(SAMPLE_XML, target="127.0.0.1")
    assert result.target == "127.0.0.1"
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "127.0.0.1"
    assert host.hostname == "localhost"
    assert host.state == "up"
    assert len(host.ports) == 3

    ssh = host.ports[0]
    assert ssh.number == 22
    assert ssh.state == "open"
    assert ssh.service.name == "ssh"
    assert ssh.service.product == "OpenSSH"
    assert ssh.service.version == "8.2p1"
    assert ssh.service.extra == "Ubuntu-4ubuntu0.5"

    http = host.ports[1]
    assert http.service.product == "Apache httpd"
    assert http.service.version == "2.4.41"

    closed = host.ports[2]
    assert closed.state == "closed"


def test_empty_xml_returns_empty_result():
    result = parse_nmap_xml("", target="127.0.0.1")
    assert result.hosts == []


def test_xml_without_target_argument_still_parses():
    xml = textwrap.dedent(
        """\
        <?xml version="1.0"?>
        <nmaprun><host>
          <status state="up"/>
          <address addr="10.0.0.5" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="nginx" version="1.18.0"/>
          </port></ports>
        </host></nmaprun>
        """
    )
    result = parse_nmap_xml(xml, target="10.0.0.5")
    assert result.target == "10.0.0.5"
    assert result.hosts[0].ip == "10.0.0.5"
    assert result.hosts[0].ports[0].service.product == "nginx"
