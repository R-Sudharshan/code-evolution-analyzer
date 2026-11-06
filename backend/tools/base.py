import re
import time
from urllib.parse import urlparse

from backend.schemas.agent import ToolSpec


class ToolError(Exception):
    pass


URLISH = re.compile(r"^(http[s]?://[^\s]+|[A-Za-z0-9_.\-]+\.[A-Za-z]{2,}(:\d+)?(/.*)?)$")


def urls_in_args(args: list[str]) -> list[str]:
    out = []
    for a in args:
        if URLISH.match(a):
            out.append(a)
    return out


class ToolOperation:
    def __init__(self, id: str, description: str, active: bool, default_args: list[str] | None = None):
        self.id = id
        self.description = description
        self.active = active
        self.default_args = default_args or []


class BaseTool:
    """Common tool contract: metadata, operations, input validation, safe argv."""
    id: str = ""
    name: str = ""
    description: str = ""
    risk_level: str = "active"
    default_image: str = ""
    default_timeout: int = 300
    executable: str = ""

    def __init__(self, image: str | None = None):
        self.operations: dict[str, ToolOperation] = {}
        self.image = image or self.default_image
        self._define()

    def _define(self):  # operations defined by subclass
        pass

    def op(self, op_id: str) -> ToolOperation:
        o = self.operations.get(op_id)
        if not o:
            raise ToolError(f"unknown operation {op_id!r} for tool {self.id}")
        return o

    def validate_spec(self, spec: ToolSpec) -> list[str]:
        """Validate and build argv. Always returns an argument array (no shell)."""
        if spec.tool != self.id:
            raise ToolError("tool mismatch")
        self.op(spec.operation)
        if not spec.target:
            raise ToolError("missing target")
        if " " in spec.target or ";" in spec.target:
            raise ToolError("target contains forbidden characters")
        p = urlparse(spec.target if "://" in spec.target else "http://" + spec.target)
        if p.scheme not in ("http", "https"):
            raise ToolError("target scheme must be http(s)")
        argv = self.build_argv(spec)
        for a in argv:
            if not a:
                raise ToolError("empty argument not allowed")
            if any(ch in a for ch in "\\\n\r`$&|<>"):
                raise ToolError(f"forbidden character in argument {a!r}")
        return [self.executable] + argv

    def build_argv(self, spec: ToolSpec) -> list[str]:
        raise NotImplementedError

    def metadata(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level,
            "image": self.image,
            "operations": [
                {"id": o.id, "description": o.description, "active": o.active} for o in self.operations.values()
            ],
        }


def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s or "")


def now_ms() -> float:
    return time.time()
