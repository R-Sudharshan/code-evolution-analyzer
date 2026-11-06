import time
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

VALID_STATUSES = [
    "created",
    "initializing",
    "awaiting_approval",
    "running",
    "paused",
    "completed",
    "cancelled",
    "failed",
]


class AssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: str
    max_steps: int | None = Field(default=None, ge=1, le=50)


class Assessment(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    target_id: str
    status: str = "created"
    phase: str = ""
    max_steps: int = 12
    steps_done: int = 0
    error: str = ""
    deficiencies: list[str] = Field(default_factory=list)
    llm_disabled: bool = False
    created_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    updated_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    started_at: str | None = None
    completed_at: str | None = None
    summary: str = ""

    def public(self) -> dict[str, Any]:
        return self.model_dump()


class ToolSpec(BaseModel):
    """The immutable, infalible specification of an executed operation."""

    model_config = ConfigDict(extra="forbid")
    tool: str
    operation: str
    target: str
    args: list[str]


class PlannedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    assessment_id: str
    step: int
    objective: str
    reason: str
    tool: str
    operation: str
    target: str
    args: list[str]
    expected_output: str
    risk: Literal["informational", "safe", "active", "authenticated"] = "active"
    impact: str = ""
    status: str = "proposed"  # proposed|approved|rejected|expired|executed_ok|executed_fail
    spec_hash: str
    created_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    decided_at: str | None = None
    decision_note: str = ""
    executed_run_id: str | None = None


class PlannedResponse(BaseModel):
    """Strict contract the LLM must follow for its next-step decision."""

    model_config = ConfigDict(extra="forbid")
    assessment_complete: bool = False
    summary: str = ""
    action: ToolSpec
    objective: str
    reason: str
    expected_output: str
    risk: Literal["informational", "safe", "active", "authenticated"]
    impact: str = ""
