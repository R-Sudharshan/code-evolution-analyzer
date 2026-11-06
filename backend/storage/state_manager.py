import time
from typing import Any

from backend.schemas.agent import VALID_STATUSES
from backend.storage import repos

# Legal transitions of the assessment lifecycle.
TRANSITIONS: dict[str, set[str]] = {
    "created": {"initializing", "cancelled", "failed"},
    "initializing": {"awaiting_approval", "running", "paused", "completed", "cancelled", "failed"},
    "awaiting_approval": {
        "running",  # approval granted
        "completed",  # agent declared assessment complete instead of proposing
        "cancelled",
        "failed",
    },
    "running": {"awaiting_approval", "paused", "completed", "cancelled", "failed"},
    "paused": {"awaiting_approval", "running", "cancelled", "failed"},
    "completed": set(),
    "cancelled": set(),
    "failed": set(),
}

TERMINAL = {"completed", "cancelled", "failed"}


def transition(assessment_id: str, new_status: str, phase: str = "", extra: dict | None = None) -> dict[str, Any]:
    rec = repos.assessments().get(assessment_id)
    if rec is None:
        raise ValueError(f"assessment {assessment_id} not found")
    cur = rec["status"]
    if cur == new_status:
        pass
    elif new_status not in TRANSITIONS.get(cur, set()):
        raise ValueError(f"illegal transition {cur} -> {new_status}")
    fields: dict[str, Any] = {
        "status": new_status,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    if phase:
        fields["phase"] = phase
    if extra:
        fields.update(extra)
    if new_status == "running" and not rec.get("started_at"):
        fields["started_at"] = fields["updated_at"]
    if new_status in TERMINAL:
        fields["completed_at"] = fields["updated_at"]
    updated = {**rec, **fields}
    from backend.schemas.agent import Assessment

    Assessment.model_validate(updated)  # schema revalidation
    repos.assessments().put(assessment_id, updated)
    repos.events().append(
        dict(assessment_id=assessment_id, kind="state", message=f"{cur} -> {new_status}", data={"phase": phase})
    )
    return updated


def get_status(assessment_id: str) -> str | None:
    rec = repos.assessments().get(assessment_id)
    return rec["status"] if rec else None


def is_terminal(status: str) -> bool:
    return status in TERMINAL
