from datetime import datetime, timedelta, timezone

import jwt
import pytest
from sqlalchemy import select

from app.audit import record_event
from app.gateway import RateLimiter
from app.models import AuditEvent, Patient, User
from app.patients import MASK


def events(client):
    with client.app.state.db.Session() as session:
        return session.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()


def test_no_token(client):
    response = client.get("/api/patients")
    assert response.status_code == 401
    assert events(client)[-1].result == "deny"
    assert response.headers["X-Audit-ID"]


def test_doctor_foreign_card(client, headers):
    assert client.get("/api/patients/3", headers=headers()).status_code == 403
    assert events(client)[-1].reason


def test_doctor_own_card_and_filtered_list(client, headers):
    h = headers()
    response = client.get("/api/patients/1", headers=h)
    assert response.status_code == 200
    assert response.json()["diagnosis"] == "Сезонная аллергия"
    assert [p["id"] for p in client.get("/api/patients", headers=h).json()] == [1, 2, 5]


def test_nurse_masked_without_decryption(client, headers, monkeypatch):
    def forbidden_decrypt(_):
        raise AssertionError("Nurses must never decrypt medical data")
    monkeypatch.setattr(client.app.state.cipher, "decrypt", forbidden_decrypt)
    h = headers("nurse_aigul")
    response = client.get("/api/patients/1", headers=h)
    assert response.status_code == 200
    assert response.json()["diagnosis"] == MASK
    assert response.json()["notes"] == MASK
    assert len(client.get("/api/patients", headers=h).json()) == 5


def test_patient_only_own(client, headers):
    h = headers("patient_dana")
    assert client.get("/api/patients/1", headers=h).status_code == 200
    assert client.get("/api/patients/2", headers=h).status_code == 403
    assert [p["id"] for p in client.get("/api/patients", headers=h).json()] == [1]


def test_expired_token(client, token):
    secret = client.app.state.settings.jwt_secret
    claims = jwt.decode(token(), secret, algorithms=["HS256"])
    claims["exp"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    expired = jwt.encode(claims, secret, algorithm="HS256")
    response = client.get("/api/me", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401
    assert "истёк" in response.json()["detail"]


def test_tampered_token_does_not_impersonate_in_audit(client, token):
    original = token()
    head, payload, signature = original.split(".")
    modified = f"{head}.{payload}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"
    assert client.get("/api/me", headers={"Authorization": f"Bearer {modified}"}).status_code == 401
    assert events(client)[-1].username == "anonymous"


def test_admin_audit_no_medical_data(client, headers):
    h = headers("admin")
    assert client.get("/api/patients", headers=h).status_code == 403
    assert client.get("/api/patients/1", headers=h).status_code == 403
    response = client.get("/api/audit", headers=h)
    assert response.status_code == 200
    assert "Сезонная аллергия" not in response.text
    assert "demo123" not in response.text


def test_three_denies_suspicious(client, headers):
    h = headers()
    for _ in range(3):
        assert client.get("/api/patients/3", headers=h).status_code == 403
    assert events(client)[-1].suspicious
    assert "3 и более" in events(client)[-1].anomaly_reasons


def test_allow_resets_deny_streak(client, headers):
    h = headers()
    for _ in range(2):
        client.get("/api/patients/3", headers=h)
    client.get("/api/me", headers=h)
    client.get("/api/patients/3", headers=h)
    assert "3 и более" not in events(client)[-1].anomaly_reasons


def test_rate_limit_logs_and_recovers(client, headers):
    now = [100.0]
    client.app.state.limiter = RateLimiter(lambda: now[0])
    h = headers()
    for _ in range(10):
        assert client.get("/api/me", headers=h).status_code == 200
    response = client.get("/api/me", headers=h)
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "10"
    assert events(client)[-1].suspicious
    assert "лимит" in events(client)[-1].anomaly_reasons
    now[0] += 10
    assert client.get("/api/me", headers=h).status_code == 200


def test_encrypted_fields_and_password_hash(client):
    with client.app.state.db.Session() as session:
        p = session.get(Patient, 1)
        assert p.diagnosis.startswith("gAAAA")
        assert "Сезонная аллергия" not in p.diagnosis
        assert "Учебная" not in p.notes
        assert client.app.state.cipher.decrypt(p.diagnosis) == "Сезонная аллергия"
        assert session.get(User, 1).password_hash.startswith("$pbkdf2-sha256$")


@pytest.mark.parametrize("username", ["doctor_aidar", "doctor_sara", "nurse_aigul", "patient_dana"])
def test_non_admin_cannot_audit_or_reset(client, headers, username):
    h = headers(username)
    assert client.get("/api/audit", headers=h).status_code == 403
    assert client.post("/api/demo/reset", headers=h).status_code == 403


def test_night_simulation(client, headers):
    h = {**headers(), "X-Demo-Night": "1"}
    response = client.get("/api/me", headers=h)
    assert response.status_code == 200
    assert response.headers["X-Audit-Suspicious"] == "true"
    event = events(client)[-1]
    assert event.simulated_night and "Ночной" in event.anomaly_reasons


@pytest.mark.parametrize("utc_hour,night", [(19, True), (23, True), (0, False), (18, False)])
def test_real_night_timezone(client, utc_hour, night):
    with client.app.state.db.Session() as session:
        event = record_event(session, username="doctor_aidar", role="doctor", action="me.read",
                             resource="GET /api/me", result="allow", status_code=200, reason="test",
                             request_id=f"time-{utc_hour}", now=datetime(2026, 10, 28, utc_hour, tzinfo=timezone.utc))
        assert event.suspicious is night


def test_reset_reseeds_revokes_tokens_and_logs(client, headers):
    doctor = headers()
    admin = headers("admin")
    client.get("/api/me", headers=doctor)
    response = client.post("/api/demo/reset", headers=admin)
    assert response.status_code == 200
    assert len(events(client)) == 1
    assert events(client)[0].action == "demo.reset"
    assert client.get("/api/me", headers=doctor).status_code == 401
    assert client.get("/api/audit", headers=admin).status_code == 401
    assert client.get("/api/patients", headers=headers()).status_code == 200


def test_role_claim_verified_against_database(client, token):
    secret = client.app.state.settings.jwt_secret
    claims = jwt.decode(token(), secret, algorithms=["HS256"])
    claims["role"] = "admin"
    forged = jwt.encode(claims, secret, algorithm="HS256")
    assert client.get("/api/audit", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


@pytest.mark.parametrize("path", ["/api", "/api/unknown", "/api/patients/1/", "/api/patients/-1", "/api/patients/999999999999999"])
def test_unknown_paths_fail_closed(client, headers, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers=headers()).status_code == 403


def test_wrong_method_denied(client, headers):
    assert client.post("/api/patients/1", headers=headers()).status_code == 403


def test_bad_login(client):
    for username in ("doctor_aidar", "unknown"):
        assert client.post("/auth/login", json={"username": username, "password": "wrong"}).status_code == 401


def test_limits_per_user_not_per_token(client, headers):
    for _ in range(10):
        client.get("/api/me", headers=headers())
    assert client.get("/api/me", headers=headers()).status_code == 429
    assert client.get("/api/me", headers=headers("doctor_sara")).status_code == 200


def test_security_headers(client):
    response = client.get("/health")
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


@pytest.mark.parametrize("username", ["doctor_aidar", "patient_dana"])
def test_missing_and_foreign_cards_indistinguishable(client, headers, username):
    h = headers(username)
    foreign = client.get("/api/patients/3", headers=h)
    missing = client.get("/api/patients/999", headers=h)
    assert foreign.status_code == missing.status_code == 403
    assert foreign.json()["detail"] == missing.json()["detail"]


@pytest.mark.parametrize("host", ["x/", "x/api/me?", "x#", "localhost"])
def test_host_cannot_skip_auth_or_reset(client, headers, host):
    doctor = headers()
    assert client.get("/api/audit", headers={"Host": host}).status_code == 401
    assert client.post("/api/demo/reset", headers={"Host": host}).status_code == 401
    # A denied reset must not invalidate existing tokens or remove prior audit rows.
    assert len(events(client)) == 2
    assert client.get("/api/patients/1", headers=doctor).status_code == 200


@pytest.mark.parametrize("username", ["doctor_aidar", "patient_dana", "admin"])
def test_host_cannot_relabel_foreign_card(client, headers, username):
    h = {**headers(username), "Host": "x/api/me?"}
    response = client.get("/api/patients/3", headers=h)
    assert response.status_code == 403
    assert "diagnosis" not in response.json()
    assert events(client)[-1].resource == "GET /api/patients/3"
    assert events(client)[-1].action == "patient.read"


@pytest.mark.parametrize("path", ["/api/patients%2f3", "/api/patients/3%3f", "/api/patients/3%23", "/api/patients/03"])
def test_encoded_paths_cannot_bypass_ownership(client, headers, path):
    assert client.get(path, headers=headers()).status_code == 403


def test_handler_validation_denials_are_suspicious(client, headers):
    h = headers("admin")
    for _ in range(3):
        assert client.get("/api/audit?limit=0", headers=h).status_code == 422
    event = events(client)[-1]
    assert event.status_code == 422 and event.result == "deny"
    assert event.suspicious and "3 и более" in event.anomaly_reasons


def test_handler_exception_is_audited(client, headers, monkeypatch):
    def broken(_):
        raise RuntimeError("private implementation details")
    monkeypatch.setattr(client.app.state.cipher, "decrypt", broken)
    response = client.get("/api/patients/1", headers=headers())
    assert response.status_code == 500
    assert "private implementation" not in response.text
    assert events(client)[-1].result == "deny"
    assert events(client)[-1].status_code == 500


def test_reset_rollback_if_replacement_audit_fails(client, headers, monkeypatch):
    from app import main
    doctor, admin = headers(), headers("admin")
    def broken(*args, **kwargs):
        raise RuntimeError("simulated audit write failure")
    monkeypatch.setattr(main.audit, "record_event", broken)
    assert client.post("/api/demo/reset", headers=admin).status_code == 500
    assert events(client)[-1].result == "deny"
    assert client.get("/api/patients/1", headers=doctor).status_code == 200


def test_sensitive_handlers_fail_closed_without_gateway(client):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app import patients, audit
    unwrapped = FastAPI()
    unwrapped.include_router(patients.router)
    unwrapped.include_router(audit.router)
    with TestClient(unwrapped) as isolated:
        for path in ("/api/patients", "/api/patients/1", "/api/audit"):
            assert isolated.get(path).status_code == 401
