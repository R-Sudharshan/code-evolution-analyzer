import json
from unittest.mock import patch

import pytest


@pytest.fixture()
def appctx(tmp_path):
    from backend.tests import conftest

    app = conftest.make_app(tmp_path)
    c = app.test_client()
    c.post("/api/auth/login", json={"password": "testpass123"})
    r = c.post(
        "/api/auth/login", json={"password": "testpass123"}
    )
    token = r.get_json()["token"]
    c.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return c


def test_require_auth(client, appctx):
    # forged token is refused on writes
    r = client.post(
        "/api/targets",
        json={"name": "X", "url": "http://example.com/", "authorized": True},
        environ_base={"HTTP_AUTHORIZATION": "Bearer definitely-invalid"},
    )
    assert r.status_code == 401


def test_target_registration_scope_enforcement(appctx):
    r = appctx.post(
        "/api/targets",
    json={"name": "No Ack", "url": "http://example.com/", "authorized": False},
    )
    assert r.status_code == 400
    # point-level drift: explicitly restricted ports must make other ports impossible
    r = appctx.post(
        "/api/targets",
        json={"name": "PortDrift", "url": "http://example.org:8080/", "scope": {"ports": [80]}, "authorized": True},
    )
    assert r.status_code == 400
    r = appctx.post(
        "/api/targets",
        json={"name": "Ok", "url": "http://example.com/", "scope": {"domains": ["example.com"], "ports": [80]}, "authorized": True},
    )
    assert r.status_code == 201


def test_private_target_requires_explicit_ip(appctx):
    r = appctx.post(
        "/api/targets",
        json={"name": "Local", "url": "http://127.0.0.1/", "scope": {"ips": ["127.0.0.2"], "ports": [80]}, "authorized": True},
    )
    assert r.status_code == 400  # 127.0.0.1 not covered
    r = appctx.post(
        "/api/targets",
        json={"name": "Local", "url": "http://127.0.0.1:3000/", "scope": {"ips": ["127.0.0.1"], "ports": [3000]}, "authorized": True},
    )
    assert r.status_code == 201


def test_cancel_endpoint(appctx):
    r = appctx.post("/api/targets", json={"name": "C", "url": "http://example.com/", "scope": {"domains": ["example.com"], "ports": [80]}, "authorized": True})
    tid = r.get_json()["id"]
    with patch("backend.agent.engine.ensure_engine", return_value=None):
        r2 = appctx.post("/api/assessments", json={"target_id": tid, "max_steps": 3})
        aid = r2.get_json()["id"]
        r3 = appctx.post(f"/api/assessments/{aid}/cancel")
        assert r3.status_code == 200
        r4 = appctx.post(f"/api/assessments/{aid}/cancel")
        assert r4.status_code == 409  # already terminal


def test_report_generation(appctx):
    r = appctx.post("/api/targets", json={"name": "R", "url": "http://example.com/", "scope": {"domains": ["example.com"], "ports": [80]}, "authorized": True})
    tid = r.get_json()["id"]
    with patch("backend.agent.engine.ensure_engine", return_value=None):
        aid = appctx.post("/api/assessments", json={"target_id": tid}).get_json()["id"]
    rr = appctx.post(f"/api/assessments/{aid}/report", json={"format": "html"})
    assert rr.status_code == 200
    assert "AI-Assisted Web Application Penetration Test" in rr.data.decode()
    rj = appctx.post(f"/api/assessments/{aid}/report", json={"format": "json"})
    assert rj.get_json()["stats"]["findings_total"] >= 0
