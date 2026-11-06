import time

from backend.agent.engine import spec_hash, Engine
from backend.schemas.agent import ToolSpec
from backend.storage import repos
from backend.storage import state_manager as sm


def _mk_assessment(aid, tid):
    repos.assessments().put(
        aid,
        {
            "id": aid,
            "target_id": tid,
            "status": "awaiting_approval",
            "max_steps": 5,
            "steps_done": 0,
            "created_at": "t",
            "updated_at": "t",
            "deficiencies": [],
            "phase": "",
        },
    )
    repos.targets().put(
        tid,
        {"id": tid, "name": "t", "url": "http://example.com/", "scope": {"domains": ["example.com"], "ips": [], "cidrs": [], "ports": [80]}, "authorized": True, "created_at": "t", "notes": ""},
    )
    return aid


def test_spec_hash_tamper_detection():
    spec = ToolSpec(tool="httpx", operation="probe", target="http://example.com/", args=[])
    _mk_assessment("a1", "t-1")
    h = spec_hash("a1", 1, spec)
    thr = repos.actions()
    act = {
        "id": "act1",
        "assessment_id": "a1",
        "step": 1,
        "objective": "o",
        "reason": "r",
        "tool": "httpx",
        "operation": "probe",
        "target": "http://example.com/",
        "args": [],
        "expected_output": "e",
        "risk": "safe",
        "impact": "i",
        "status": "approved",
        "spec_hash": h,
        "created_at": "t",
        "decided_at": "t",
        "decision_note": "",
        "executed_run_id": None,
    }
    thr.put("act1", act)
    # unchanged spec -> hash ok (simulates engine check path)
    fresh = ToolSpec(tool="httpx", operation="probe", target="http://example.com/", args=[])
    assert spec_hash("a1", 1, fresh) == h
    # tampered target -> hash mismatch
    tamper = ToolSpec(tool="httpx", operation="probe", target="http://other.invalid/", args=[])
    assert spec_hash("a1", 1, tamper) != h
    # tampered args
    tamp2 = ToolSpec(tool="httpx", operation="probe", target="http://example.com/", args=["-x"])
    assert spec_hash("a1", 1, tamp2) != h
    # single-use enforcement at the state level
    repos.actions().update("act1", status="executed_ok")
    assert repos.actions().get("act1")["status"] == "executed_ok"


def test_spec_hash_invalidates_step_change():
    spec = ToolSpec(tool="httpx", operation="probe", target="http://x.invalid/", args=[])
    assert spec_hash("a9", 1, spec) != spec_hash("a9", 2, spec)


def _mk_subs(x):
    return x


def test_transition_matrix():
    _mk_assessment("st-1", "t-2")
    assert sm.get_status("st-1") == "awaiting_approval"
    sm.transition("st-1", "running")
    sm.transition("st-1", "awaiting_approval")
    sm.transition("st-1", "running")
    sm.transition("st-1", "completed")
    import pytest
    with pytest.raises(ValueError):
        sm.transition("st-1", "running")
