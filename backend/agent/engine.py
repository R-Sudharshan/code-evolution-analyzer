"""Observe -> analyze -> plan -> approval -> execute -> evaluate agent engine.

The engine NEVER blocks a request thread: it spawns a daemon thread per
assessment and stops (terminating the thread) whenever approval is required.
State is fully persisted (JSON stores), so the process can restart and pending
approved actions resume via ensure_engine().
"""

import hashlib
import json
import threading
import time
from urllib.parse import urlparse

from backend import config
from backend.agent.planner import Planner
from backend.execution import runner
from backend.execution.scope import ScopeError
from backend.llm.client import LLMDisabled, LLMError
from backend.schemas.agent import PlannedAction, ToolSpec
from backend.storage import repos, audit_event, agent_event
from backend.storage import state_manager as sm
from backend.tools import registry
from backend.tools.base import ToolError

_ENGINES: dict[str, "Engine"] = {}
_ENGINES_LOCK = threading.Lock()


def spec_hash(assessment_id: str, step: int, spec: ToolSpec) -> str:
    payload = {
        "assessment_id": assessment_id,
        "step": step,
        "tool": spec.tool,
        "operation": spec.operation,
        "target": spec.target,
        "args": spec.args,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class Engine:
    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self.planner = Planner()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self._llm_retries = 0
        self._last_action_id: str | None = None

    # --- public ---------------------------------------------------------------

    @classmethod
    def spawn(cls, assessment_id: str) -> "Engine":
        eng = cls(assessment_id)
        t = threading.Thread(target=eng._main, name=f"engine-{assessment_id}", daemon=True)
        eng.thread = t
        with _ENGINES_LOCK:
            _ENGINES[assessment_id] = eng
        t.start()
        return eng

    @classmethod
    def ensure_engine(cls, assessment_id: str) -> "Engine | None":
        with _ENGINES_LOCK:
            eng = _ENGINES.get(assessment_id)
        if eng is not None and eng.thread is not None and eng.thread.is_alive():
            return eng
        return cls.spawn(assessment_id)

    def cancel(self):
        self.stop_event.set()

    # --- main loop ------------------------------------------------------------

    def _main(self):
        try:
            self._loop()
        except Exception as e:  # engine crash
            self._fail(f"engine crashed: {e}")

    def _fail(self, msg: str):
        rec = repos.assessments().get(self.assessment_id)
        if rec and not sm.is_terminal(rec["status"]):
            sm.transition(self.assessment_id, "failed", error=msg)
        with _ENGINES_LOCK:
            _ENGINES.pop(self.assessment_id, None)

    def _loop(self):
        aid = self.assessment_id
        rec = repos.assessments().get(aid)
        target = repos.targets().get(rec["target_id"])
        while not self.stop_event.is_set():
            rec = repos.assessments().get(aid)
            status = rec["status"]
            # 1) execute any approved-but-unexecuted action (resume path)
            pending_approved = [
                a for a in repos.actions().all().values()
                if a["assessment_id"] == aid and a["status"] == "approved"
            ]
            if pending_approved:
                for action in sorted(pending_approved, key=lambda x: x["created_at"]):
                    self._execute_action(action, target)
                    if self.stop_event.is_set():
                        return
                continue
            if sm.is_terminal(status) or status in ("awaiting_approval", "paused"):
                # approval/resume API re-spawns the engine via ensure_engine()
                break
            # 2) plan the next step
            if rec["steps_done"] >= rec["max_steps"]:
                sm.transition(aid, "completed", phase="max_steps")
                agent_event(aid, "agent", "Max steps reached; assessment complete.")
                return
            try:
                planned, reason = self._plan(rec, target, rejected_note=None)
            except LLMDisabled as e:
                deficiency = llm_setup_note()
                rec = repos.assessments().get(aid)
                defs = list(rec.get("deficiencies", []))
                if not any("llm" in d for d in defs):
                    defs.append("llm_disabled: " + e.reason)
                    repos.assessments().update(aid, deficiencies=defs, updated_at=nows())
                sm.transition(aid, "paused", phase="llm_disabled", extra={"llm_disabled": True})
                agent_event(aid, "agent", "LLM unavailable: paused. " + deficiency)
                return
            except LLMError as e:
                if self._llm_retries >= 3:
                    self._fail(f"LLM repeated invalid responses: {e}")
                    return
                self._llm_retries += 1
                agent_event(aid, "llm", f"Invalid LLM response ({e}); retrying")
                time.sleep(1.5)
                continue
            self._llm_retries = 0
            if planned.assessment_complete or planned.action.tool == "none":
                summary = planned.summary or "agent concluded"
                sm.transition(aid, "completed", phase="concluded", extra={"summary": summary})
                agent_event(aid, "agent", f"Assessment complete: {summary}")
                return
            self._create_proposal(rec, target, planned)
            sm.transition(aid, "awaiting_approval",
                          phase=self._phase_for(planned))
            agent_event(
                aid,
                "proposal",
                f"Proposed {planned.action.tool}/{planned.action.operation} on {planned.action.target}",
                data={"action_id": self._last_action_id},
            )
            return  # stop the thread; approval will re-spawn via ensure_engine

    _llm_retries = 0
    _last_action_id: str | None = None

    # --- helpers (kept for API compatibility) ---------------------------------
    @staticmethod
    def _phase_for(planned) -> str:
        risk = planned.risk
        return {"informational": "recon", "safe": "recon", "active": "active_scan", "authenticated": "authenticated"}.get(
            risk, "active_scan"
        )

    def _plan(self, rec, target, rejected_note):
        planned = self.planner.propose(rec, target, rejected_step_note=rejected_note)
        return planned, ""

    def _create_proposal(self, rec_assessment, target, planned):
        aid = rec_assessment["id"]
        spec = planned.action
        step = rec_assessment["steps_done"] + 1
        h = spec_hash(aid, step, spec)
        action = PlannedAction(
            assessment_id=aid,
            step=step,
            objective=planned.objective,
            reason=planned.reason,
            tool=spec.tool,
            operation=spec.operation,
            target=spec.target,
            args=spec.args,
            expected_output=planned.expected_output,
            risk=planned.risk,
            impact=planned.impact,
            spec_hash=h,
        )
        repos.actions().put(action.id, action.model_dump())
        audit_event(
            "action_proposed",
            assessment_id=aid,
            action_id=action.id,
            spec_hash=h,
            tool=action.tool,
            operation=action.operation,
            target=action.target,
        )
        self._last_action_id = action.id

    def _execute_action(self, action: dict, target: dict):
        aid = action["assessment_id"]
        step = action["step"]
        # verify the exact action spec (approval immutability)
        spec = ToolSpec(
            tool=action["tool"], operation=action["operation"], target=action["target"], args=action["args"]
        )
        h = spec_hash(aid, step, spec)
        if h != action["spec_hash"]:
            repos.actions().update(action["id"], status="expired", decided_at=nows())
            audit_event("action_spec_mismatch", assessment_id=aid, action_id=action["id"])
            sm.transition(aid, "failed", phase="spec_mismatch", error="approved action spec changed after approval")
            self.stop_event.set()
            return
        try:
            sm.transition(aid, "running", phase=f"executing:{action['tool']}/{action['operation']}")
        except ValueError:
            pass
        agent_event(aid, "exec", f"Executing {action['tool']} {action['operation']} on {action['target']}")
        try:
            run = runner.execute(spec, aid, rec_target_id(aid), timeout=None)
        except (ToolError, ScopeError) as e:
            repos.actions().update(action["id"], status="executed_fail")
            agent_event(aid, "exec", f"Execution failed: {e}")
            self._next_step(aid, action, fail=True)
            return
        repos.actions().update(
            action["id"],
            status="executed_ok" if run["status"] == "ok" else "executed_fail",
            executed_run_id=run["id"],
        )
        # analyze + findings
        try:
            from backend.analysis import pipeline as analysis_pipeline

            analysis_pipeline.process_run(run)
        except Exception as e:
            agent_event(aid, "analysis", f"Analysis pipeline error: {e}")
        self._next_step(aid, action, fail=False)

    def _next_step(self, aid: str, action: dict, fail: bool):
        rec = repos.assessments().get(aid)
        done = rec["steps_done"] + 1
        repos.assessments().update(aid, steps_done=done, updated_at=nows())
        agent_event(aid, "agent", f"Step {done} {'finished' if not fail else 'failed'}.")


def ensure_engine(assessment_id: str) -> Engine | None:
    return Engine.ensure_engine(assessment_id)


def spec_hash_mod(assessment_id: str, step: int, spec: ToolSpec) -> str:  # re-export
    return spec_hash(assessment_id, step, spec)


def rec_target_id(assessment_id: str) -> str:
    rec = repos.assessments().get(assessment_id)
    return rec["target_id"]


def llm_setup_note() -> str:
    from backend.llm.client import llm_status

    return llm_status().get("reason", "")


def nows() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")
