import secrets

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def client(tmp_path):
    settings = Settings(secrets.token_urlsafe(48), Fernet.generate_key().decode(),
                        f"sqlite:///{tmp_path / 'test.db'}")
    with TestClient(create_app(settings)) as client:
        yield client


@pytest.fixture
def token(client):
    def login(username="doctor_aidar"):
        response = client.post("/auth/login", json={"username": username, "password": "demo123"})
        assert response.status_code == 200
        return response.json()["access_token"]
    return login


@pytest.fixture
def headers(token):
    return lambda username="doctor_aidar": {"Authorization": f"Bearer {token(username)}"}
