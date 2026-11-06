import time
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = "match"
    description: str = ""
    url: str = ""
    snippet: str = ""
    meta: dict[str, Any] = Field(default_factory=dict)


class CVSS4(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vector: str
    score: float
    severity: str
    basis: str = "category_baseline"  # or "cve_nvd" when NVD provided base


class Finding(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    assessment_id: str
    target_id: str = ""
    fingerprint: str  # dedupe key
    status: Literal["POTENTIAL", "VERIFIED", "FALSE_POSITIVE"] = "POTENTIAL"
    title: str
    category: str = "other"
    source_tool: str
    source_ref: str = ""  # e.g., nuclei template id
    url: str = ""
    matcher_status: str = ""
    confidence_scanner: Literal["low", "medium", "high"] = "medium"
    severity_scanner: str = ""
    validated_via: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    cves: list[dict[str, Any]] = Field(default_factory=list)
    cvss: CVSS4 | None = None
    created_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    updated_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    enrichment: dict[str, Any] = Field(default_factory=dict)
