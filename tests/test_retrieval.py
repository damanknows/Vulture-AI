import pytest
from retrieval import retrieve_by_cve, retrieve_by_query

@pytest.fixture
def mock_dataset():
    return [
        {
            "finding": {"target": "10.0.0.1", "product": "apache http_server", "version": "2.4.49"},
            "cve_matches": [
                {
                    "cve_id": "CVE-2021-41773",
                    "intel": {
                        "retrieved_at": "2026-10-09",
                        "data": {"metrics": "cvss 9.8"}
                    }
                }
            ]
        }
    ]

def test_exact_cve_lookup(mock_dataset):
    res = retrieve_by_cve("CVE-2021-41773", mock_dataset)
    assert len(res) == 1
    assert res[0]["cve_id"] == "CVE-2021-41773"
    assert res[0]["source_id"] == "10.0.0.1:unknown_CVE-2021-41773"

def test_query_lookup(mock_dataset):
    res = retrieve_by_query("apache", mock_dataset)
    assert len(res) == 1
    assert res[0]["cve_id"] == "CVE-2021-41773"
