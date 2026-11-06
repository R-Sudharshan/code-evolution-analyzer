"""End-to-end assessment against OWASP Juice Shop in an isolated Docker network.

LLM is mocked at the planner boundary (the reasoning engine's contract); tool
execution, scope validation, approval, parsing, findings, and reports are REAL.
"""

import json
import subprocess
import time
import uuid

import pytest

from backend.tests.conftest import make_app

JUICE_IMAGE = "bkimminich/juice-shop:latest"
NET = "pentai-e2e"


def _docker(*args, check=True, capture=True):
    return subprocess.run(["docker", *args], capture_output=capture, text=True, check=check)


def _docker_ok() -> bool:
    try:
        return _docker("version", "--format", "ok", check=False).stdout.strip() == "ok"
    except Exception:
        return False


def _image_present(image):
    try:
        out = _docker("images", image.split(":")[0], "--format", "{{.Repository}}:{{.Tag}}", check=False).stdout
    except Exception:
        return False
    return image.split(":")[0] in out


docker_needed = pytest.mark.skipif(not _docker_ok(), reason="docker not available")
juice_needed = pytest.mark.skipif(not _image_present(JUICE_IMAGE), reason="juice-shop image missing")


class FakePlanner:
    """Scripted proposals: probe -> template scan -> finish."""

    def __init__(self):
        self.called = 0

    def propose(self, assessment, target, rejected_step_note=None):
        self.called += 1
        from backend.schemas.agent import PlannedResponse

        if self.called == 1:
            return PlannedResponse(
                assessment_complete=False,
                summary="start with probe",
                action={"tool": "httpx", "operation": "probe", "target": target["url"], "args": []},
                objective="probe target",
                reason="recon",
                expected_output="liveness + tech",
                risk="informational",
                impact="GET requests only",
            )
        if self.called == 2:
            return PlannedResponse(
                assessment_complete=False,
                summary="scan configurations",
                action={"tool": "nuclei", "operation": "template_scan", "target": target["url"], "args": []},
                objective="detect misconfig/exposures",
                reason="probe confirmed live target",
                expected_output="nuclei jsonl findings",
                risk="active",
                impact="light requests",
            )
        return PlannedResponse(
            assessment_complete=True,
            summary="done",
            action={"tool": "none", "operation": "none", "target": target["url"], "args": []},
            objective="-",
            reason="-",
            expected_output="",
            risk="informational",
            impact="",
        )


@docker_needed
@juice_needed
class TestJuiceShopE2E:
    @pytest.fixture(scope="class")
    def target_row(self, class_tmpdir_cache):
        subprocess.run(["docker", "network", "create", NET], capture_output=True, check=False)
        name = f"pentai-jss-{uuid.uuid4().hex[:6]}"
        proc = _docker("run", "-d", "--rm", "--network", NET, "--name", name, JUICE_IMAGE, check=False)
        if proc.returncode != 0:
            raise AssertionError(f"cannot start juice shop: {proc.stderr}")
        # NOTE: juice shop listens on :3000; give it time
        ip = ""
        for _ in range(40):
            if _docker("inspect", name, "--format", "{{.State.Running}}", check=False).stdout.strip() == "true":
                out = _docker("inspect", name, "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}").stdout.strip()
                import urllib.request

                if out:
                    ip = out
                    try:
                        urllib.request.urlopen(f"http://{ip}:3000", timeout=2.5)
                        break
                    except Exception:
                        ip = out
            time.sleep(1.5)
        assert ip, "juice shop did not come up in time"
        yield {"ip": ip, "url": f"http://{ip}:3000/", "name": name, "ports": [3000], "ips": [ip]}
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        subprocess.run(["docker", "network", "rm", NET], capture_output=True)

    def test_full_flow(self, target_row):
        app = make_app()
        c = app.test_client()
        c.environ_base["HTTP_AUTHORIZATION"] = "Bearer " + c.post(
            "/api/auth/login", json={"password": "testpass123"}
        ).get_json()["token"]

        # 1) register target with scoped ramge covering the lab ip
        scope = {"domains": [], "ips": target_row["ips"], "cidrs": [], "ports": target_row["ports"]}
        r = c.post("/api/targets", json={"name": "JuiceLab", "url": target_row["url"], "scope": scope, "authorized": True})
        assert r.status_code == 201, r.data
        tid = r.get_json()["id"]

        # 2) run two-step assessment with a scripted planner
        from unittest.mock import patch

        fake = FakePlanner()

        # reset engine caches  # assessment machinery
        import backend.agent.engine as eng_mod

        eng_mod._ENGINES.clear()
        with patch.object(eng_mod, "Planner", lambda: fake):
            r = c.post("/api/assessments", json={"target_id": tid, "max_steps": 6})
            assert r.status_code == 201
            aid = r.get_json()["id"]

            def wait_status(st, timeout=120):
                end = time.time() + timeout
                while time.time() < end:
                    cur = c.get(f"/api/assessments/{aid}").get_json()
                    if cur["status"] == st:
                        return cur
                    time.sleep(0.8)
                raise AssertionError(f"status never reached {st}; last: {cur}")

            cur = wait_status("awaiting_approval")
            proposals = cur["pending_proposals"]
            assert len(proposals) == 1 and proposals[0]["tool"] == "httpx"
            extractor = c.get(f"/api/assessments/{aid}/actions/{proposals[0]['id']}/decision", json={})
            assert extractor.status_code == 405

            # approve via correct method
            r = c.post(f"/api/assessments/{aid}/actions/{proposals[0]['id']}/decision", json={"decision": "approve", "note": "ok"})
            assert r.status_code == 200
            cur = wait_status("awaiting_approval", timeout=180)
            proposals = cur["pending_proposals"]
            assert len(proposals) == 1 and proposals[0]["tool"] == "nuclei"

            # tamper with the stored spec -> backend must refuse (approval immutability)
            tamper = dict(proposals[0])
            import backend.storage.repos as repos_mod

            rec = repos_mod.actions().get(tamper["id"])
            repos_mod.actions().put(tamper["id"], {**rec, "target": "http://127.0.0.1:22/"})
            r = c.post(f"/api/assessments/{aid}/actions/{tamper['id']}/decision", json={"decision": "approve", "note": ""})
            assert r.status_code == 409, r.data
            # restore and approve
            repos_mod.actions().put(tamper["id"], rec)
            r = c.post(f"/api/assessments/{aid}/actions/{tamper['id']}/decision", json={"decision": "approve", "note": "go"})
            assert r.status_code == 200
            cur = wait_status("completed", timeout=300)
            assert fake.called >= 3

        findings = c.get(f"/api/assessments/{aid}/findings").get_json()
        assert isinstance(findings, list)
        for f in findings:
            assert f["source_tool"] == "nuclei"
            assert f["cvss"] and f["cvss"]["vector"].startswith("CVSS:4.0/")
            assert f["status"] in ("POTENTIAL", "VERIFIED", "FALSE_POSITIVE")

        rep = c.post(f"/api/assessments/{aid}/report", json={"format": "json"}).get_json()
        assert rep["stats"]["findings_total"] == len(findings)
        html = c.post(f"/api/assessments/{aid}/report", json={"format": "html"}).data.decode()
        assert "Findings" in html and "CVSS" in html

        # reject path: simulate a fresh rejection of a proposed step
        # (create a second quick assessment, reject at step 1)
        r = c.post("/api/assessments", json={"target_id": tid, "max_steps": 4})
        aid2 = r.get_json()["id"]

        def wait_status2(st, timeout=120):
            end = time.time() + timeout
            while time.time() < end:
                cur = c.get(f"/api/assessments/{aid2}").get_json()
                if cur["status"] == st:
                    return cur
                time.sleep(0.8)
            raise AssertionError("never reached " + st)

        cur = wait_status2("awaiting_approval")
        p = cur["pending_proposals"][0]
        r = c.post(f"/api/assessments/{aid2}/actions/{p['id']}/decision", json={"decision": "reject", "note": "not today"})
        assert r.status_code == 200
        cur = wait_status2("awaiting_approval", timeout=180)
        # after rejection planner.propose called again with new context
        assert fake.called >= 4
        c.post(f"/api/assessments/{aid2}/cancel")


@pytest.fixture(scope="class")
def class_tmpdir_cache():
    yield
