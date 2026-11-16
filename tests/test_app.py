import base64
import io
import os
import secrets
from pathlib import Path

import pytest

# Set valid demo secrets before importing the Flask application.
os.environ.setdefault("FLASK_SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault(
    "MASTER_KEY",
    base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
)

import app as secureshare


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(secureshare, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(secureshare, "STORAGE", tmp_path / "encrypted")
    secureshare.STORAGE.mkdir(parents=True)
    secureshare.init_db()
    secureshare._AUTH_ATTEMPTS.clear()
    secureshare.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with secureshare.app.test_client() as test_client:
        yield test_client


def csrf(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess["_csrf"]


def register_and_login(client):
    token = csrf(client)
    response = client.post("/register", data={
        "_csrf": token,
        "username": "testuser",
        "email": "test@example.com",
        "password": "a-long-test-password",
    }, follow_redirects=True)
    assert response.status_code == 200

    token = csrf(client)
    response = client.post("/login", data={
        "_csrf": token,
        "identity": "testuser",
        "password": "a-long-test-password",
    }, follow_redirects=True)
    assert response.status_code == 200


def test_post_without_csrf_is_rejected(client):
    response = client.post("/login", data={"identity": "nobody", "password": "bad"})
    assert response.status_code == 400


def test_private_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_upload_is_encrypted_and_owner_can_download(client):
    register_and_login(client)
    original = b"SecureShare automated test payload"
    token = csrf(client)
    response = client.post("/upload", data={
        "_csrf": token,
        "file": (io.BytesIO(original), "sample.txt"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200

    with secureshare.app.app_context():
        row = secureshare.db().execute("SELECT * FROM files").fetchone()
        assert row is not None
        ciphertext = (secureshare.STORAGE / row["storage_name"]).read_bytes()
        assert ciphertext != original
        assert secureshare.decrypt_file(row) == original
        file_id = row["id"]

    response = client.get(f"/file/{file_id}/download")
    assert response.status_code == 200
    assert response.data == original


def test_login_attempts_are_throttled(client):
    token = csrf(client)
    for _ in range(secureshare._AUTH_LIMIT):
        response = client.post("/login", data={
            "_csrf": token,
            "identity": "nobody",
            "password": "incorrect",
        })
        assert response.status_code == 200
    response = client.post("/login", data={
        "_csrf": token,
        "identity": "nobody",
        "password": "incorrect",
    })
    assert response.status_code == 429
