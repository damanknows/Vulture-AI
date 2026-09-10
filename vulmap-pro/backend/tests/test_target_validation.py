"""Tests for the target allowlist / command-injection guardrail."""
from __future__ import annotations

import pytest

from backend.config import is_target_allowed


def test_loopback_is_allowed():
    assert is_target_allowed("127.0.0.1") is True


def test_rfc1918_are_allowed():
    assert is_target_allowed("10.0.0.5") is True
    assert is_target_allowed("192.168.1.1") is True
    assert is_target_allowed("172.16.0.1") is True


def test_public_ip_is_rejected_by_default():
    assert is_target_allowed("8.8.8.8") is False


def test_arbitrary_string_is_rejected():
    with pytest.raises(ValueError):
        is_target_allowed("; rm -rf /")


def test_invalid_ip_raises_valueerror():
    with pytest.raises(ValueError):
        is_target_allowed("not-an-ip")


def test_cidr_format_is_accepted_inside_allowlist():
    assert is_target_allowed("127.0.0.1/32") is True
