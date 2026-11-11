"""Functional + security tests. Each docstring says what weakness the test guards against."""
import io
import logging
import sqlite3
import time

import jwt
import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.main import create_app
from tests.conftest import STRONG_PASSWORD


# ---------- health ----------
def test_health_ok(client):
    """Liveness probe works (used by Docker HEALTHCHECK and staging verification)."""
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


# ---------- registration ----------
def test_register_success(client):
    r = client.post("/register", json={"username": "bob", "email": "bob@example.com", "password": STRONG_PASSWORD})
    assert r.status_code == 201
    assert "password" not in r.text.lower()  # never echo credentials back


def test_register_duplicate_conflict(client, registered):
    """Duplicates are rejected with 409, not a 500 crash."""
    assert client.post("/register", json=registered).status_code == 409


@pytest.mark.parametrize(
    "patch",
    [
        {"password": "short1A"},  # too short
        {"password": "alllowercase1234"},  # no upper case
        {"email": "not-an-email"},
        {"username": "a"},  # too short
        {"username": "bob'; DROP TABLE users;--"},  # SQLi-shaped, fails character allow-list
        {"username": "<script>alert(1)</script>"},  # XSS-shaped
        {"username": "x" * 500},  # oversized input
    ],
)
def test_register_rejects_invalid_input(client, patch):
    """Allow-list validation blocks malformed/hostile input before any logic runs."""
    body = {"username": "carol", "email": "carol@example.com", "password": STRONG_PASSWORD, **patch}
    assert client.post("/register", json=body).status_code == 422


def test_register_rejects_unexpected_fields(client):
    """Mass-assignment defence: attacker can't smuggle fields like is_admin."""
    body = {"username": "dave", "email": "d@example.com", "password": STRONG_PASSWORD, "is_admin": True}
    assert client.post("/register", json=body).status_code == 422


def test_validation_error_does_not_echo_password(client):
    """Error responses must not reflect the submitted secret value."""
    r = client.post("/register", json={"username": "eve", "email": "e@example.com", "password": "Sh0rt"})
    assert r.status_code == 422 and "Sh0rt" not in r.text


# ---------- password handling ----------
def test_password_is_stored_hashed(client, registered, tmp_path):
    """Passwords must never be stored in plaintext; Argon2id hash expected."""
    conn = sqlite3.connect(get_settings().db_path)
    stored = conn.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()[0]
    conn.close()
    assert stored != STRONG_PASSWORD and stored.startswith("$argon2id$")


def test_same_password_yields_different_hashes(client):
    """Per-user random salts: identical passwords must not produce identical hashes."""
    from app.security import hash_password

    assert hash_password(STRONG_PASSWORD) != hash_password(STRONG_PASSWORD)


# ---------- login ----------
def test_login_success_returns_bearer_token(client, registered):
    r = client.post("/login", json={"username": "alice", "password": STRONG_PASSWORD})
    assert r.status_code == 200 and r.json()["token_type"] == "bearer" and r.json()["access_token"]


def test_login_wrong_password_and_unknown_user_are_indistinguishable(client, registered):
    """Prevents username enumeration: identical status AND message in both cases."""
    wrong = client.post("/login", json={"username": "alice", "password": "Wrong-Password-1"})
    ghost = client.post("/login", json={"username": "nobody", "password": "Wrong-Password-1"})
    assert wrong.status_code == ghost.status_code == 401
    assert wrong.json() == ghost.json()


def test_login_sql_injection_attempt_fails(client, registered):
    """Parameterized queries: classic ' OR '1'='1 must not authenticate."""
    r = client.post("/login", json={"username": "alice' OR '1'='1", "password": "x' OR '1'='1"})
    assert r.status_code == 401


# ---------- authentication / authorization ----------
def test_profile_requires_token(client):
    r = client.get("/profile")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"


def test_profile_with_valid_token(client, token):
    r = client.get("/profile", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json() == {"username": "alice", "email": "alice@example.com"}
    assert "password" not in r.text.lower()


def test_profile_rejects_garbage_token(client):
    assert client.get("/profile", headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401


def test_profile_rejects_tampered_token(client, token):
    """Signature must be verified: flipping bytes invalidates the token."""
    head, payload, sig = token.split(".")
    bad = f"{head}.{payload}.{sig[:-3]}AAA"
    assert client.get("/profile", headers={"Authorization": f"Bearer {bad}"}).status_code == 401


def test_profile_rejects_token_signed_with_wrong_key(client, registered):
    forged = jwt.encode(
        {"sub": "alice", "iss": "secure-cicd-demo", "iat": int(time.time()), "exp": int(time.time()) + 600},
        "attacker-key-attacker-key-attacker-key-00",
        algorithm="HS256",
    )
    assert client.get("/profile", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_profile_rejects_alg_none_token(client, registered):
    """Classic JWT attack: unsigned token with alg=none must be refused (algorithm pinned)."""
    forged = jwt.encode({"sub": "alice", "iss": "secure-cicd-demo", "exp": int(time.time()) + 600}, None, algorithm="none")
    assert client.get("/profile", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_profile_rejects_expired_token(client, registered):
    s = get_settings()
    expired = jwt.encode(
        {"sub": "alice", "iss": s.token_issuer, "iat": 1, "exp": 2}, s.secret_key, algorithm="HS256"
    )
    assert client.get("/profile", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_token_for_deleted_user_is_rejected(client, token):
    conn = sqlite3.connect(get_settings().db_path)
    conn.execute("DELETE FROM users WHERE username='alice'")
    conn.commit()
    conn.close()
    assert client.get("/profile", headers={"Authorization": f"Bearer {token}"}).status_code == 401


# ---------- security headers ----------
@pytest.mark.parametrize(
    "header,expected",
    [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
    ],
)
def test_security_headers_present(client, header, expected):
    assert client.get("/health").headers[header] == expected


def test_security_headers_also_on_errors(client):
    r = client.get("/profile")
    assert r.status_code == 401 and r.headers["x-content-type-options"] == "nosniff"


def test_no_wildcard_cors_header(client):
    r = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


# ---------- error handling / config ----------
def test_unknown_route_is_clean_404(client):
    r = client.get("/nope")
    assert r.status_code == 404 and "Traceback" not in r.text


def test_wrong_method_is_405(client):
    assert client.get("/login").status_code == 405


def test_unhandled_exception_returns_generic_500(client):
    """No stack traces, file paths, or exception text leak to the client."""
    app = client.app

    @app.get("/boom")
    def boom():
        raise RuntimeError("secret internal detail /srv/app/db.py")

    r = client.get("/boom")
    assert r.status_code == 500 and r.json() == {"detail": "Internal server error"}
    assert "secret internal" not in r.text


def test_production_hides_docs(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("APP_DB_PATH", str(tmp_path / "p.db"))
    get_settings.cache_clear()
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404
    get_settings.cache_clear()


def test_wildcard_cors_config_is_rejected():
    with pytest.raises(ValidationError):
        Settings(secret_key="x" * 32, cors_origins=["*"])


def test_app_refuses_to_start_without_secret(monkeypatch):
    monkeypatch.delenv("APP_SECRET_KEY")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


# ---------- logging ----------
def test_logs_do_not_contain_secrets(client):
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    logger = logging.getLogger("app")
    logger.addHandler(handler)
    try:
        client.post("/register", json={"username": "frank", "email": "f@example.com", "password": STRONG_PASSWORD})
        tok = client.post("/login", json={"username": "frank", "password": STRONG_PASSWORD}).json()["access_token"]
        client.get("/profile", headers={"Authorization": f"Bearer {tok}"})
    finally:
        logger.removeHandler(handler)
    out = buf.getvalue()
    assert out  # something was logged
    assert STRONG_PASSWORD not in out and tok not in out and "argon2" not in out
