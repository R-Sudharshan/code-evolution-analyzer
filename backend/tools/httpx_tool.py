"""ProjectDiscovery httpx CLI wrapper (whitelisted tool #1).

Argument arrays only, never a shell. Behavior follows the official httpx CLI
documentation: https://github.com/projectdiscovery/httpx
"""

from backend.schemas.agent import ToolSpec
from backend.tools.base import BaseTool, ToolOperation, ToolError


class HttpxTool(BaseTool):
    id = "httpx"
    name = "ProjectDiscovery httpx"
    description = "HTTP probing: live host detection, status, title, technology detection"
    executable = "httpx"
    default_timeout = 300

    def _define(self):
        self.operations = {
            "probe": ToolOperation(
                "probe",
                "Probe authorized target URL for liveness, title, status code and technologies via tech-detect",
                active=False,
            )
        }

    def build_argv(self, spec: ToolSpec) -> list[str]:
        if spec.operation != "probe":
            raise ToolError(f"httpx: unsupported operation {spec.operation!r}")
        extra = list(spec.args or [])
        allowed_extra = {"-irh", "-H", "-pa"}
        for a in extra:
            if a.startswith("-") and a not in allowed_extra:
                raise ToolError(f"httpx: disallowed extra flag {a!r}")
        # NOTE: httpx v1.12 does NOT follow redirects by default; -location only
        # reports the Location header so redirects stay observable but never followed.
        return [
            "-u", spec.target,
            "-jsonl",
            "-no-color",
            "-td",           # tech-detect (wappalyzer dataset)
            "-title",
            "-sc",           # status code
            "-rt",           # response time
            "-irh",          # include response headers -> missing header evidence
            "-location",     # record redirect location without following it
            "-retries", "1",
        ] + extra
