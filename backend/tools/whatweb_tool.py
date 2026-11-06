"""WhatWeb wrapper (whitelisted tool #3).

Official project: https://github.com/urbanadventurer/whatweb
Runs inside the restricted pentai-tools image. `whatweb --log-json=-`
writes the JSON log to STDOUT (see Logging(f=STDOUT) in lib/logging.rb;
f=='-' maps to stdout). Output is a JSON array of per-target results.

--log-json is used instead of XML because it is the structured output the
parser consumes; no extra files or host mounts needed.
"""

from backend.schemas.agent import ToolSpec
from backend.tools.base import BaseTool, ToolOperation, ToolError


class WhatWebTool(BaseTool):
    id = "whatweb"
    name = "WhatWeb"
    description = "Technology fingerprinting: web server, CMS, frameworks and versions"
    executable = "whatweb"
    default_timeout = 300

    def _define(self):
        self.operations = {
            "fingerprint": ToolOperation(
                "fingerprint",
                "Fingerprint the target with one HTTP request (aggression 1, follows redirects off)",
                active=False,
            )
        }

    def build_argv(self, spec: ToolSpec) -> list[str]:
        if spec.operation != "fingerprint":
            raise ToolError(f"whatweb: unsupported operation {spec.operation!r}")
        extra = list(spec.args or [])
        parsed: list[str] = []
        i = 0
        while i < len(extra):
            a = extra[i]
            if a == "--no-redirect":
                parsed.append(a)
                i += 1
            elif a in ("-a", "--aggression") and i + 1 < len(extra) and extra[i + 1] in ("1", "3"):
                parsed += [a, extra[i + 1]]
                i += 2
            else:
                raise ToolError(f"whatweb: disallowed extra argument {a!r}")
        return [
            spec.target,
            "-a", "1",                 # stealthy default (1 HTTP request)
            "--no-redirect",           # never follow redirects (redirects recorded, not followed)
            "--colour=never",
            "--quiet",
            "--log-json=-",            # JSON array to stdout
        ] + parsed
