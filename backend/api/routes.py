import json
import time
from urllib.parse import urlsplit

from flask import Blueprint, Response, jsonify, request

from backend.agent import engine
from backend.analysis import validator as validator_mod
from backend.api.middleware import require_auth
from backend.execution import runner
from backend.execution.scope import ScopeError, ScopeValidator  # noqa: F401 (used by tests)
from backend.intelligence.cve_lookup import lookup_cve  # noqa: F401
from backend.reporting.reports import build_assessment_report
from backend.schemas.agent import AssessmentCreate, Assessment  # noqa: F401
from backend.schemas.common import AuthRequest, DecisionRequest, FindingStatusRequest, ReportRequest, TargetCreate
from backend.storage import repos, agent_event, audit_event
from backend.storage import state_manager as sm
from backend.tools import registry

api = Blueprint("api", __name__)


def _json(payload, code=200):
    return jsonify(payload), code


def _bad(msg, code=400):
    return _json({"error": msg}, code)


def _assessment_public(a: dict) -> dict:
    t = repos.targets().get(a["target_id"]) or {}
    find_rows = [f for f in repos.findings().all().values() if f["assessment_id"] == a["id"]]
    active = [x for x in find_rows if x["status"] != "FALSE_POSITIVE"]
    sev_dist = {}
    for f in active:
        sev = ((f.get("cvss") or {}).get("severity", "None")) or "None"
        sev_dist[sev] = sev_dist.get(sev, 0) + 1
    proposed = [x for x in repos.actions().all().values() if x["assessment_id"] == a["id"] and x["status"] == "proposed"]
    return {
        **{k: a.get(k) for k in ("id", "target_id", "status", "phase", "max_steps", "steps_done", "error", "deficiencies", "llm_disabled", "created_at", "updated_at", "summary")},
        "target": {"id": t.get("id"), "name": t.get("name"), "url": t.get("url")},
        "stats": {
            "findings_total": len(find_rows),
            "verified": sum(1 for f in find_rows if f["status"] == "VERIFIED"),
            "potential": sum(1 for f in find_rows if f["status"] == "POTENTIAL"),
            "false_positives": sum(1 for f in find_rows if f["status"] == "FALSE_POSITIVE"),
            "severity_distribution": sev_dist,
            "steps": a.get("steps_done", 0),
        },
        "pending_proposals": [
            {
                "id": x["id"],
                "objective": x["objective"],
                "reason": x["reason"],
                "tool": x["tool"],
                "operation": x["operation"],
                "target": x["target"],
                "args": x["args"],
                "expected_output": x["expected_output"],
                "risk": x["risk"],
                "impact": x["impact"],
                "spec_hash": x["spec_hash"],
                "step": x["step"],
                "created_at": x["created_at"],
            }
            for x in sorted(proposed, key=lambda p: p["created_at"])
        ],
    }


# ------------------------------- auth ------------------------------------------------

@api.post("/api/auth/login")
def post_login():
    data = AuthRequest.model_validate(request.get_json(force=True, silent=True) or {})
    token = _login_password(data.password)
    if not token:
        return _bad("invalid password", 401)
    return _json({"token": token, "expiry_seconds": 60 * 3600})


def _login_password(pw: str):
    from backend.api.middleware import login

    return login(pw)


@api.get("/api/auth/status")
@require_auth
def auth_status():
    from backend.api.middleware import request  # noop to satisfy lint
    from backend.llm.client import llm_status
    from backend.execution import docker
    from backend import config

    tops = registry.list_metadata()
    return _json(
        {
            "llm": llm_status(),
            "docker": docker.daemon_info(),
            "images": {t: config.TOOL_IMAGES[t] for t in config.TOOL_WHITELIST},
            "templates_volume": config.TEMPLATES_VOLUME,
            "tools": tops,
        }
    )


# ------------------------------- targets ---------------------------------------------

@api.post("/api/targets")
@require_auth
def post_target():
    data = TargetCreate.model_validate(request.get_json(force=True, silent=True) or {})
    if not data.authorized:
        return _bad("authorization acknowledgment required (authorized=true)")
    tid = f"tgt-{len(repos.targets().all()) + 1}"
    rec = {
        "id": tid,
        "name": data.name,
        "url": data.url,
        "scope": data.scope.model_dump(),
        "notes": data.notes,
        "authorized": data.authorized,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    # scope sanity: target host must be covered by the scope the user declared
    try:
        s = ScopeValidator(tid)  # will construct again after put
    except ScopeError:
        pass
    repos.targets().put(tid, rec)
    try:
        ScopeValidator(tid).check_url(data.url)
    except ScopeError as e:
        repos.targets().delete(tid)
        return _bad(f"target url not covered by declared scope: {e}")
    audit_event("target_created", target_id=tid, url=data.url)
    return _json(rec, 201)


@api.get("/api/targets")
@require_auth
def get_targets():
    return _json([repos.targets().get(k) for k in repos.targets().all()])


# ------------------------------- assessments ------------------------------------------

@api.post("/api/assessments")
@require_auth
def post_assessment():
    data = AssessmentCreate.model_validate(request.get_json(force=True, silent=True) or {})
    target = repos.targets().get(data.target_id)
    if not target:
        return _bad("target not found", 404)
    # a target can only have one non-terminal assessment
    for a in repos.assessments().all().values():
        if a["target_id"] == target["id"] and not sm.is_terminal(a["status"]):
            return _bad(f"target already has an active assessment {a['id']}", 409)
    from backend.schemas.agent import Assessment as A

    a = A(target_id=target["id"], max_steps=data.max_steps or 12)
    repos.assessments().put(a.id, a.model_dump())
    sm.transition(a.id, "initializing", phase="engine_boot")
    engine.ensure_engine(a.id)
    audit_event("assessment_created", assessment_id=a.id, target=target["url"])
    return _json(_assessment_public(repos.assessments().get(a.id)), 201)


@api.get("/api/assessments")
@require_auth
def get_assessments():
    return _json([_assessment_public(x) for x in repos.assessments().all().values()])


@api.get("/api/assessments/<aid>")
@require_auth
def get_assessment_detail(aid: str):
    a = repos.assessments().get(aid)
    if not a:
        return _bad("assessment not found", 404)
    out = _assessment_public(a)
    out["actions"] = sorted(
        [x for x in repos.actions().all().values() if x["assessment_id"] == aid], key=lambda x: (x["step"], x["created_at"])
    )
    out["runs"] = sorted(
        [{k: r.get(k) for k in ("id", "tool", "operation", "target", "status", "duration", "stdout_truncated", "stderr")}
         for r in repos.runs().all().values() if r.get("assessment_id") == aid],
        key=lambda r: r["id"],
    )
    out["activity"] = [e for e in repos.events().read_all(400) if e.get("assessment_id") == aid][-60:]
    return _json(out)


@api.post("/api/assessments/<aid>/cancel")
@require_auth
def post_cancel(aid: str):
    a = repos.assessments().get(aid)
    if not a:
        return _bad("assessment not found", 404)
    if sm.is_terminal(a["status"]):
        return _bad(f"assessment already terminal ({a['status']})", 409)
    eng = engine.ensure_engine(aid)
    if eng:
        eng.cancel()
    # kill any in-flight tool containers for this assessment
    killed_containers = []
    from backend.execution import docker as docker_mod

    for r in repos.runs().all().values():
        if r.get("assessment_id") == aid and r.get("status") == "running" and r.get("container"):
            docker_mod.kill_container(r["container"])
            repos.runs().update(r["id"], status="error", stderr="cancelled by user", finished_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
            killed_containers.append(r["container"])
    sm.transition(aid, "cancelled", phase="user_cancelled")
    pending = [x["id"] for x in repos.actions().all().values() if x["assessment_id"] == aid and x["status"] == "proposed"]
    for pid in pending:
        repos.actions().update(pid, status="expired", decided_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    audit_event("assessment_cancelled", assessment_id=aid, pending_expired=pending)
    return _json({"status": "cancelled"})


@api.post("/api/assessments/<aid>/resume")
@require_auth
def post_resume(aid):
    a = repos.assessments().get(aid)
    if not a:
        return _bad("assessment not found", 404)
    if a["status"] != "paused":
        return _bad(f"cannot resume from status {a['status']}", 409)
    sm.transition(aid, "running", phase="resumed")
    engine.ensure_engine(aid)
    return _json({"status": "running"})


# ------------------------------- approvals --------------------------------------------

@api.post("/api/assessments/<aid>/actions/<actid>/decision")
@require_auth
def post_decision(aid: str, actid: str):
    a = repos.assessments().get(aid)
    if not a:
        return _bad("assessment not found", 404)
    data = DecisionRequest.model_validate(request.get_json(force=True, silent=True) or {})
    action = repos.actions().get(actid)
    if not action or action["assessment_id"] != aid:
        return _bad("action not found", 404)
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    if sm.is_terminal(a["status"]) or a["status"] in ("running",):
        return _bad(f"decision window closed (assessment {a['status']})", 409)
    # approval binds to the exact immutable spec: recompute hash; any change invalidates
    from backend.schemas.agent import ToolSpec

    spec = ToolSpec(tool=action["tool"], operation=action["operation"], target=action["target"], args=action["args"])
    h = engine.spec_hash(aid, action["step"], spec)
    if h != action["spec_hash"]:
        repos.actions().update(actid, status="expired", decided_at=now)
        audit_event("approval_rejected_hash_mismatch", assessment_id=aid, action_id=actid)
        return _bad("action specification changed since proposal (hash mismatch); approval invalidated", 409)
    if data.decision == "reject":
        repos.actions().update(actid, status="rejected", decided_at=now, decision_note=data.note)
        audit_event("action_rejected", assessment_id=aid, action_id=actid, note=data.note)
        agent_event(aid, "approval", f"User rejected step {action['step']} ({action['tool']}; {data.note})")
        # respawning engine lets re-planning happen with rejection feedback
        engine.ensure_engine(aid)
        return _json({"status": "rejected"})
    # approve
    allowed, reason = _validate_scope_for_action(aid, action)
    if not allowed:
        repos.actions().update(actid, status="expired", decided_at=now, decision_note=f"scope check failed: {reason}")
        audit_event("approval_scope_block", assessment_id=aid, action_id=actid, reason=reason)
        return _bad(f"backend scope validation refused this action: {reason}", 403)
    repos.actions().update(actid, status="approved", decided_at=now, decision_note=data.note)
    audit_event("action_approved", assessment_id=aid, action_id=actid, spec_hash=h, note=data.note)
    agent_event(aid, "approval", f"User approved step {action['step']} ({action['tool']} {action['operation']})")
    engine.ensure_engine(aid)
    return _json({"status": "approved"})


def _validate_scope_for_action(aid: str, action: dict) -> tuple[bool, str]:
    from backend.schemas.agent import ToolSpec

    spec = ToolSpec(tool=action["tool"], operation=action["operation"], target=action["target"], args=action["args"])
    try:
        tool = registry.get(spec.tool)
        tool.validate_spec(spec)
    except Exception as e:
        return False, str(e)
    try:
        target_id = repos.assessments().get(aid)["target_id"]
        validator = ScopeValidator(target_id)
        url = spec.target if "://" in spec.target else "http://" + spec.target
        validator.check_url(url)
    except ScopeError as e:
        return False, str(e)
    except Exception as e:
        return False, f"scope check error: {e}"
    return True, ""


# ------------------------------- findings --------------------------------------------

@api.get("/api/assessments/<aid>/findings")
@require_auth
def get_findings(aid: str):
    if not repos.assessments().get(aid):
        return _bad("assessment not found", 404)
    rows = sorted(
        [f for f in repos.findings().all().values() if f["assessment_id"] == aid],
        key=lambda f: -(f.get("cvss") or {}).get("score", 0),
    )
    return _json(rows)


@api.patch("/api/findings/<id>/status")
@require_auth
def patch_finding_status(id: str):
    data = FindingStatusRequest.model_validate(request.get_json(force=True, silent=True) or {})
    f = repos.findings().get(id)
    if not f:
        return _bad("finding not found", 404)
    f["status"] = data.status
    f["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    f["validated_via"] = f"manual: {data.note}" if data.note else "manual"
    repos.findings().put(id, f)
    audit_event("finding_status_manual", finding_id=id, status=data.status)
    return _json(f)


# ------------------------------- reports ---------------------------------------------

@api.post("/api/assessments/<aid>/report")
@require_auth
def post_report(aid: str):
    data = ReportRequest.model_validate(request.get_json(force=True, silent=True) or {})
    try:
        rec = build_assessment_report(aid)
    except ValueError as e:
        return _bad(str(e), 404)
    if data.format == "json":
        return _json(rec["json"])
    return Response(rec["content"], mimetype="text/html")


@api.get("/api/reports/<rid>")
@require_auth
def get_report(rid: str):
    rec = repos.reports().get(rid)
    if not rec:
        return _bad("report not found", 404)
    if "format=json" in (request.args.get("fmt") or "html"):
        return _json(rec["json"])
    return Response(rec["content"], mimetype="text/html")


@api.get("/api/summary")
@require_auth
def get_summary():
    """Aggregate, authenticated-only market overview for the dashboard.

    Everything here is computed from the live JSON stores — no placeholders.
    """
    assessments = list(repos.assessments().all().values())
    targets = list(repos.targets().all().values())
    findings = list(repos.findings().all().values())
    runs = list(repos.runs().all().values())

    active = sum(1 for a in assessments if a["status"] not in ("completed", "cancelled", "failed"))
    awaiting = sum(1 for a in assessments if a["status"] == "awaiting_approval")
    completed = sum(1 for a in assessments if a["status"] == "completed")
    cancelled = sum(1 for a in assessments if a["status"] == "cancelled")
    failed = sum(1 for a in assessments if a["status"] == "failed")

    sev_dist: dict[str, int] = {}
    for f in findings:
        if f.get("status") == "FALSE_POSITIVE":
            continue
        sev = ((f.get("cvss") or {}).get("severity") or "None") or "None"
        sev_dist[sev] = sev_dist.get(sev, 0) + 1

    pending = sorted(
        [
            x
            for x in repos.actions().all().values()
            if x.get("status") == "proposed"
        ],
        key=lambda x: x.get("created_at", ""),
        reverse=True,
    )[:20]

    pending_out = []
    for x in pending:
        a = repos.assessments().get(x["assessment_id"]) or {}
        t = repos.targets().get(a.get("target_id", "")) or {}
        pending_out.append(
            {
                "id": x["id"],
                "assessment_id": x["assessment_id"],
                "step": x["step"],
                "assessment_target": t.get("url"),
                "assessment_name": t.get("name"),
                "tool": x["tool"],
                "operation": x["operation"],
                "objective": x["objective"],
                "reason": x["reason"],
                "target": x["target"],
                "args": x["args"],
                "impact": x["impact"],
                "expected_output": x["expected_output"],
                "risk": x["risk"],
                "created_at": x["created_at"],
            }
        )

    try:
        events = (repos.events().read_all(800) or [])[-30:]
    except Exception:
        events = []
    recent_activity = [
        {
            "assessment_id": e.get("assessment_id"),
            "kind": e.get("kind"),
            "message": e.get("message"),
            "ts": e.get("_ts"),
        }
        for e in events
    ]

    # discovered technologies across all whatweb runs (real data)
    tech_counts: dict[str, int] = {}
    for r in runs:
        parsed = r.get("parsed") or {}
        techs = parsed.get("technology") or []
        for item in techs:
            plugin = item.get("plugin")
            if not plugin:
                continue
            tech_counts[plugin] = tech_counts.get(plugin, 0) + 1
    discovered_technologies = sorted(
        ({"name": k, "count": v} for k, v in tech_counts.items()),
        key=lambda x: (-x["count"], x["name"]),
    )[:25]

    recent_findings = sorted(
        findings,
        key=lambda f: -float(((f.get("cvss") or {}).get("score") or 0) or 0),
    )[:8]

    recent_assessments = sorted(assessments, key=lambda a: a.get("created_at") or "", reverse=True)[:6]

    return _json(
        {
            "stats": {
                "assessments_total": len(assessments),
                "targets_total": len(targets),
                "active": active,
                "awaiting_approval": awaiting,
                "completed": completed,
                "cancelled": cancelled,
                "failed": failed,
                "findings_total": len(findings),
                "verified": sum(1 for f in findings if f.get("status") == "VERIFIED"),
                "potential": sum(1 for f in findings if f.get("status") == "POTENTIAL"),
                "false_positives": sum(1 for f in findings if f.get("status") == "FALSE_POSITIVE"),
                "severity_distribution": sev_dist,
                "pending_approvals": len(pending),
                "runs_total": len(runs),
            },
            "recent_activity": recent_activity,
            "pending_proposals": pending_out,
            "recent_assessments": [
                {
                    **{k: a.get(k) for k in ("id", "target_id", "status", "phase", "steps_done", "max_steps", "created_at")},
                    "target": ((repos.targets().get(a.get("target_id", "")) or {}).get("url")),
                }
                for a in recent_assessments
            ],
            "recent_findings": recent_findings,
            "discovered_technologies": discovered_technologies,
        }
    )


@api.get("/api/findings")
@require_auth
def get_all_findings():
    rows = sorted(
        repos.findings().all().values(),
        key=lambda f: -float(((f.get("cvss") or {}).get("score") or 0) or 0),
    )
    return _json(rows)


# ------------------------------- tools & system --------------------------------------

@api.get("/api/tools")
@require_auth
def get_tools():
    return _json(registry.list_metadata())


# ------------------------------- SSE ---------------------------------------------------

@api.get("/api/assessments/<aid>/events")
def get_events(aid: str):
    # token via ?auth_token= (EventSource cannot set headers)
    from backend.api.middleware import _valid_token

    if not _valid_token(request.args.get("auth_token", "")):
        return _bad("unauthorized", 401)

    def gen():
        cursor = 0
        import time as _t

        yield "retry: 2000\n\n"
        while True:
            rows = [e for e in repos.events().read_all(800) if e.get("assessment_id") == aid]
            while cursor < len(rows):
                ev = rows[cursor]
                cursor += 1
                payload = json.dumps({"kind": ev.get("kind"), "message": ev.get("message"), "ts": ev.get("_ts"), "data": (ev.get("data") or {})})
                yield f"id: {cursor}\nevent: agent\ndata: {payload}\n\n"
            rec = repos.assessments().get(aid)
            if not rec or sm.is_terminal(rec["status"]):
                yield "event: done\ndata: {}\n\n"
                return
            _t.sleep(1.2)

    return Response(gen(), mimetype="text/event-stream")
