"""Test setup. The secret below is a throwaway TEST value, never used outside tests."""
import os

os.environ.setdefault("APP_SECRET_KEY", "test-only-secret-key-not-for-real-use-0123456789")
os.environ.setdefault("APP_ENV", "test")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.main import create_app  # noqa: E402

STRONG_PASSWORD = "Correct-Horse-Battery-9"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A fresh app + fresh empty database for every test (tests never share state)."""
    monkeypatch.setenv("APP_DB_PATH", str(tmp_path / "test.db"))
    get_settings.cache_clear()
    with TestClient(create_app(), raise_server_exceptions=False) as c:
        yield c
    get_settings.cache_clear()


@pytest.fixture()
def registered(client):
    body = {"username": "alice", "email": "alice@example.com", "password": STRONG_PASSWORD}
    assert client.post("/register", json=body).status_code == 201
    return body


@pytest.fixture()
def token(client, registered):
    r = client.post("/login", json={"username": "alice", "password": STRONG_PASSWORD})
    return r.json()["access_token"]
