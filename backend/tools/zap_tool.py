"""OWASP ZAP wrapper (whitelisted tool #4).

Official project: https://github.com/zaproxy/zaproxy
Runs the official ZAP Baseline scan inside the upstream zaproxy image. The
baseline scan spiders the target (bounded) and runs passive rules only — it
does not perform active payload attacks.

The full Traditional JSON report is written by ZAP itself to a file under
/zap/wrk (per the official docs, report files must live in the mounted work
directory). The execution runner mounts a fresh, temporary, world-writable
host directory at /zap/wrk, reads `pentai_zap_report.json` back after the
container exits, and deletes the directory. No other host files or folders
are mounted. `-I` keeps informational alerts non-fatal so exit code 0 =
scan succeeded; scanner severity/confidence are stored as untrusted input and
never taken as final severity (the normalizer re-scores via CVSS 4.0).
"""

from backend.schemas.agent import ToolSpec
from backend.tools.base import BaseTool, ToolOperation, ToolError

REPORT_NAME = "pentai_zap_report.json"
WORK_DIR = "/zap/wrk"


class ZapTool(BaseTool):
    id = "zap"
    name = "OWASP ZAP (baseline)"
    description = "Passive baseline scan: spider + passive rules; no active payloads"
    # Upstream zaproxy image; pinned to a released version tag.
    executable = "zap-baseline.py"
    default_timeout = 900

    def _define(self):
        self.operations = {
            "baseline_scan": ToolOperation(
                "baseline_scan",
                "Spider the target (bounded) and run passive rules; writes a JSON report",
                active=True,
            )
        }

    def build_argv(self, spec: ToolSpec) -> list[str]:
        if spec.operation != "baseline_scan":
            raise ToolError(f"zap: unsupported operation {spec.operation!r}")
        extra = list(spec.args or [])
        if extra:
            raise ToolError(f"zap: extra args are not allowed for baseline_scan ({extra!r})")
        return [
            "-t", spec.target,
            "-I",                 # warnings do not fail the scan (findings are parsed, not obeyed)
            "-m", "1",            # spider for 1 minute (bounded, polite)
            "-J", f"{WORK_DIR}/{REPORT_NAME}",
        ]
