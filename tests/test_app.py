import pytest
from app import app, scans_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}

def test_get_scans(client):
    response = client.get("/api/scans")
    assert response.status_code == 200
    assert isinstance(response.get_json(), list)

def test_app_imports():
    try:
        import app
        from vulture_chatbot import chat_with_validation
        from scanner import scan_target
    except ImportError as e:
        pytest.fail(f"ImportError occurred: {e}")
