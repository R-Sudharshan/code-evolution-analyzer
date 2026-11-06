import os
import tempfile
from pathlib import Path

_backend_dir = str(Path(__file__).resolve().parent.parent)
if _backend_dir not in os.environ.get("PYTHONPATH", ""):
    os.environ["PYTHONPATH"] = _backend_dir

_TMP = Path(tempfile.mkdtemp(prefix="pentai-tests-"))
os.environ["PENTAI_ADMIN_PASSWORD"] = os.environ.get("PENTAI_ADMIN_PASSWORD") or "testpass123"
os.environ["PENTAI_DATA_DIR"] = os.environ.get("PENTAI_DATA_DIR") or str(_TMP)

import pytest


_APP_COUNT = 0


def make_app(tmp_data=None):
    import importlib

    os.environ["PENTAI_DATA_DIR"] = str(tmp_data) if tmp_data else str(_TMP)
    import backend.storage.repos as repos
    importlib.reload(repos)
    import backend.config as config
    importlib.reload(config)
    import backend.app as be_app

    importlib.reload(be_app)
    app = be_app.create_app()
    return app


@pytest.fixture(scope="function")
def client():
    global _APP_COUNT
    _APP_COUNT += 1
    import pathlib
    tmp = pathlib.Path(tempfile.mkdtemp(prefix=f"pentai-app-{_APP_COUNT:02d}-"))
    app = make_app(tmp_data=tmp)
    app.config["TESTING"] = True
    c = app.test_client()
    r = c.post("/api/auth/login", json={"password": os.environ["PENTAI_ADMIN_PASSWORD"]})
    token = r.get_json()["token"]
    c.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    c._token = token
    yield c


@pytest.fixture()
def auth_headers():
    return {}


def register_target(c, url="http://example.com/", ips=None, name="Example", domains=None):
    scope = {}
    if ips:
        scope["ips"] = ips
    if domains:
        scope["domains"] = domains
    r = c.post(
        "/api/targets",
        json={"name": name, "url": url, "scope": scope, "authorized": True},
    )
    assert r.status_code in (201, 400), r.get_json()
    return r
