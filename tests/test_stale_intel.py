import pytest
from threat_intel import _read_cache, _write_cache
import os
import time

def test_stale_intel(tmp_path, monkeypatch):
    # Override cache dir for test
    monkeypatch.setattr("threat_intel.CACHE_DIR", str(tmp_path))
    
    url = "http://example.com/api"
    data = {"test": "data"}
    
    # Write cache
    _write_cache(url, data)
    
    # Read cache (should be fresh)
    assert _read_cache(url) == data
    
    # Manipulate mtime to make it stale (older than TTL)
    cache_path = os.path.join(str(tmp_path), os.listdir(str(tmp_path))[0])
    stale_time = time.time() - 90000  # 25 hours ago
    os.utime(cache_path, (stale_time, stale_time))
    
    # Read cache (should be None since it's stale)
    assert _read_cache(url) is None
