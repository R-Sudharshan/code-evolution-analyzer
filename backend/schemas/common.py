from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)  # empty = only port from target url

    @field_validator("domains")
    @classmethod
    def clean_domains(cls, v):
        out = []
        for d in v:
            d = str(d).strip().lower().rstrip(".")
            if d and len(d) <= 253:
                out.append(d)
        return out


class TargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=80)
    url: str
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    notes: str = ""
    authorized: bool = False  # explicit ack: "I am authorized to test this target"

    @field_validator("url")
    @classmethod
    def valid_url(cls, v):
        import re as _re

        if not _re.match(r"^https?://[\w.\[\]:-]+(:\d+)?(/[^\s]*)?$", v):
            raise ValueError("url must be http(s) with hostname/address and optional port")
        return v


class TargetOut(BaseModel):
    id: str
    name: str
    url: str
    scope: ScopeConfig
    notes: str
    authorized: bool
    created_at: str


class AuthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    password: str = Field(min_length=1, max_length=256)


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    decision: str = Field(pattern="^(approve|reject)$")
    note: str = ""


class FindingStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(pattern="^(POTENTIAL|VERIFIED|FALSE_POSITIVE)$")
    note: str = ""


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: str = Field(default="html", pattern="^(html|json)$")
