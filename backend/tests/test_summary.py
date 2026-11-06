from backend.tests import conftest


def test_summary_requires_auth(tmp_path):
    app = conftest.make_app(tmp_path)
    c = app.test_client()
    r = c.get("/api/summary")
    assert r.status_code == 401


def test_summary_shape_and_tools(tmp_path):
    app = conftest.make_app(tmp_path)
    c = app.test_client()
    c.post("/api/auth/login", json={"password": "testpass123"})
    r = c.post("/api/auth/login", json={"password": "testpass123"})
    token = r.get_json()["token"]
    c.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    r = c.get("/api/summary")
    assert r.status_code == 200
    data = r.get_json()
    for key in ("stats", "recent_activity", "pending_proposals", "recent_assessments", "recent_findings", "discovered_technologies"):
        assert key in data
    assert isinstance(data["stats"]["assessments_total"], int)
    assert isinstance(data["stats"]["severity_distribution"], dict)

    r = c.get("/api/findings")
    assert r.status_code == 200
    assert r.get_json() == []

    r = c.get("/api/tools")
    assert r.status_code == 200
    ids = [t["id"] for t in r.get_json()]
    assert {"httpx", "whatweb", "nuclei", "zap"} == set(ids)
