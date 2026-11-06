import pytest

from backend.execution.scope import ScopeError, ScopeValidator
from backend.storage import repos


def _mk_target(rid, url, scope):
    rec = {
        "id": rid,
        "name": "t",
        "url": url,
        "scope": scope,
        "notes": "",
        "authorized": True,
        "created_at": "now",
    }
    repos.targets().put(rid, rec)
    return rec


def test_domain_allowed_resolves_in_scope():
    _mk_target(
        "t1",
        "http://example.com/",
        {"domains": ["example.com"], "ips": [], "cidrs": [], "ports": [80]},
    )
    v = ScopeValidator("t1")
    ips = v.check_url("http://example.com/index.js")
    assert ips


def test_out_of_scope_domain_rejected():
    _mk_target("t2", "http://example.com/", {"domains": [], "ips": [], "cidrs": [], "ports": []})
    v = ScopeValidator("t2")
    with pytest.raises(ScopeError):
        v.check_url("http://evil-foreing-host.invalid/")


def test_private_ip_requires_explicit_authorization():
    _mk_target(
        "t3",
        "http://10.0.0.5/",
        {"domains": [], "ips": ["10.0.0.8"], "cidrs": [], "ports": [80]},
    )
    v = ScopeValidator("t3")
    with pytest.raises(ScopeError):
        v.check_url("http://10.0.0.7/")  # different private ip
    ips = v.check_url("http://10.0.0.8/")
    assert "10.0.0.8" in ips


def test_cloud_metadata_always_blocked():
    _mk_target(
        "t4",
        "http://10.0.0.8/",
        {"domains": [], "ips": ["169.254.169.254", "10.0.0.8"], "cidrs": [], "ports": [80]},
    )
    v = ScopeValidator("t4")
    with pytest.raises(ScopeError):
        v.check_url("http://169.254.169.254/latest/meta-data/")
        # still blocked even though it was explicitly listed


def test_port_enforcement():
    _mk_target("t5", "http://example.com:80/", {"domains": ["example.com"], "ips": [], "cidrs": [], "ports": [80]})
    v = ScopeValidator("t5")
    with pytest.raises(ScopeError):
        v.check_url("http://example.com:8080/")


def test_strict_revalidation_all_ips():
    _mk_target("t6", "http://example.com/", {"domains": ["example.com"], "ips": [], "cidrs": [], "ports": [80]})
    v = ScopeValidator("t6")
    try:
        v.check_destination_strict("example.com", 80)
    except ScopeError:
        pass


def test_bad_scope_rejected_target_registration(client):
    # base host is implicitly authorized; explicit port narrowing must still bite
    r = client.post(
        "/api/targets",
        json={
            "name": "NoAuth",
            "url": "http://example.org:8443/",
            "scope": {"domains": ["example.org"], "ports": [80]},
            "authorized": True,
        },
    )
    assert r.status_code == 400
    assert "port" in r.get_json()["error"].lower()
