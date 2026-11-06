"""ProjectDiscovery nuclei wrapper (whitelisted tool #2).

Template-based scanning inside a restricted container. Only the controlled
template subset mounted read-only from the `pentai-nuclei-templates` volume is
allowed; -duc disables template auto-update.

Docs: https://docs.projectdiscovery.io/tools/nuclei/run
"""

from backend.schemas.agent import ToolSpec
from backend.tools.base import BaseTool, ToolOperation, ToolError

_TMPL_MOUNT = "/templates"


class NucleiTool(BaseTool):
    id = "nuclei"
    name = "ProjectDiscovery nuclei"
    description = "Template-based vulnerability scanning with controlled official template subset"
    executable = "nuclei"
    default_timeout = 900

    def _define(self):
        self.operations = {
            "template_scan": ToolOperation(
                "template_scan",
                "Run curated template set (misconfiguration/exposures/technologies) against the target",
                active=True,
            )
        }

    def build_argv(self, spec: ToolSpec) -> list[str]:
        if spec.operation != "template_scan":
            raise ToolError(f"nuclei: unsupported operation {spec.operation!r}")
        # allowed extra flags: -tags for filter, -severity filter
        extra = list(spec.args or [])
        allowed = {"-tags", "-severity"}
        i = 0
        parsed_extra: list[str] = []
        while i < len(extra):
            a = extra[i]
            if a in allowed and i + 1 < len(extra):
                v = extra[i + 1]
                if not v.replace(",", "").replace("-", "").isalnum():
                    raise ToolError(f"nuclei: invalid value for {a}")
                parsed_extra += [a, v]
                i += 2
                continue
            raise ToolError(f"nuclei: disallowed extra argument {a!r}")
        argv = [
            "-u", spec.target,
            "-t", f"{_TMPL_MOUNT}/http/misconfiguration",
            "-t", f"{_TMPL_MOUNT}/http/exposures",
            "-t", f"{_TMPL_MOUNT}/http/technologies",
            "-jsonl",
            "-duc",                         # template auto-update OFF (pinned)
            "-dr",                          # disable redirects for http templates
            "-nc",
            "-silent",
            "-rl", "20",                    # rate limit req/s
            "-c", "10",
            "-timeout", "15",
            "-retries", "1",
            "-ept", "dns,ssl,tcp,headless,code,javascript",
        ] + parsed_extra
        return argv
