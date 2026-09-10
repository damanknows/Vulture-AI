"""Test fixtures: in-memory SQLite + temp isolated cwd.

We patch the project root so the .env-based settings point at a fresh
SQLite DB during tests, regardless of where pytest is invoked from.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def _isolate_cwd(tmp_path_factory):
    """Put the package on sys.path and use a temp CWD so .env writes are safe."""
    root = Path(__file__).resolve().parents[2]  # .../vulmap-pro
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    tmp = tmp_path_factory.mktemp("vulmap-tests")
    os.chdir(tmp)
    yield tmp


@pytest.fixture
def db_url(tmp_path):
    """Per-test SQLite URL."""
    return f"sqlite:///{tmp_path / 'test.db'}"
