import json
from urllib.parse import urlparse

from pydantic import ValidationError

from backend.agent import prompts
from backend.llm.client import LLMClient, LLMDisabled, LLMError
from backend.schemas.agent import PlannedResponse, ToolSpec
from backend.storage import repos

STEP_TYPE_INSTRUCTIONS = """
Call the tool catalog and assessment context to decide the SINGLE best next step.

Considerations in order:
1. If no probe has been run yet, start with httpx probe of the base target.
2. After httpx confirms the target is alive, consider whatweb fingerprint for a
   deeper technology inventory (servers, CMS, versions).
3. If probing revealed interesting technologies/endpoints, consider nuclei
   template_scan to check for known misconfiguration/exposure issues, or zap
   baseline_scan for passive web-app alerts (spider-bounded, no active payloads).
4. If high-value findings (e.g., default credentials, exposed configs) surfaced,
   a more focused nuclei scan with -tags filter is preferred over breadth.
5. If further tool execution would add no value, say assessment_complete=true.

Return JSON only:
{
  "assessment_complete": false,
  "summary": "one-line current state",
  "action": {"tool": "<id>", "operation": "<op>", "target": "<url>", "args": []},
  "objective": "what this step achieves",
  "reason": "why now/this tool",
  "expected_output": "what the tool returns and how it will be used",
  "risk": "informational|safe|active|authenticated",
  "impact": "potential impact on the target"
}
"""


def build_context(assessment: dict, target: dict) -> str:
    runs = [r for r in repos.runs().all().values() if r.get("assessment_id") == assessment["id"]]
    findings = [f for f in repos.findings().all().values() if f.get("assessment_id") == assessment["id"]]
    actions = [a for a in repos.actions().all().values() if a.get("assessment_id") == assessment["id"]]

    parts: list[str] = []
    parts.append("== AUTHORIZED TARGET ==")
    parts.append("Target (user-declared): " + target["name"] + " " + target["url"])
    parts.append(json.dumps(target["scope"], indent=0)[:1000])
    parts.append(prompts.fence_block("target_url", target["url"]))
    parts.append("")
    parts.append("== EXISTING PROPOSED/DECIDED ACTIONS ==")
    for a in actions[-20:]:
        parts.append(json.dumps({k: a[k] for k in ("step", "tool", "operation", "target", "status", "decision_note")}))
    parts.append("")
    parts.append("== TOOL RUN HISTORY (raw-ish; untrusted) ==")
    for r in runs[-10:]:
        rw = r.get("tool", "")
        sample = (r.get("stdout") or "")[:500]
        findings_txt = "n/a"
        if rw == "nuclei":
            findings_txt = sample
        elif rw == "zap":
            findings_txt = sample
        elif rw == "whatweb":
            tech = (r.get("parsed") or {}).get("technology") or []
            findings_txt = json.dumps(tech[:25])
        parts.append(prompts.fence_block(f"run_{r['id']}_{rw}", findings_txt, 8000))
    parts.append("")
    parts.append("== CURRENT FINDINGS (do not invent new details; raw untrusted) ==")
    for f in findings[-30:]:
        parts.append(
            json.dumps({k: f.get(k) for k in ("title", "source_tool", "url", "matcher_status", "confidence_scanner", "status")})
        )
    parts.append("")
    parts.append("== AGENT ACTIVITY (last steps) ==")
    ev = [e for e in repos.events().read_all(300) if e.get("assessment_id") == assessment["id"]][-25:]
    for e in ev:
        parts.append(f"{e.get('_ts')} {e.get('kind')}: {e.get('message')[:160]}")
    parts.append("")
    parts.append("== REJECTED-STEP FEEDBACK (apply it, do not repeat the step) ==")
    rejected = [a for a in actions if a.get("status") == "rejected"][-3:]
    for a in rejected:
        parts.append(json.dumps({k: a[k] for k in ("tool", "operation", "target", "decision_note")}))
    return "\n".join(parts)


class Planner:
    def __init__(self):
        self.llm = LLMClient()

    def catalog(self) -> str:
        from backend.tools import registry

        return json.dumps(registry.list_metadata(), indent=1)

    def propose(self, assessment: dict, target: dict, rejected_step_note: str | None = None) -> PlannedResponse:
        tool_cat = self.catalog()
        user_message = prompts.fence_block("tool_catalog", tool_cat, 8000)
        user_message += "\n" + build_context(assessment, target)
        vt = urlparse(target["url"])
        user_message += f"\n== TARGET BASE ==\n{vt.scheme}://{vt.netloc}"
        if rejected_step_note:
            user_message += f"\n== USER REJECTED the previous step with note ==\n{json.dumps(rejected_step_note)}"
        user_message += STEP_TYPE_INSTRUCTIONS

        raw = self.llm.chat_json(prompts.SYSTEM_PROMPT, user_message)
        # strict schema validation -> invalid LLM output is surfaced, never guessed
        try:
            planned = PlannedResponse.model_validate(raw)
        except ValidationError as e:
            raise LLMError(f"LLM response failed schema validation: {e} ; raw={json.dumps(raw)[:400]}") from e
        # enforce sanity: tool/operation existence
        from backend.tools import registry

        reg = registry.registry()
        if planned.action.tool not in reg:
            raise LLMError(f"LLM chose unregistered/whitelist-violating tool: {planned.action.tool!r}")
        tool = reg[planned.action.tool]
        tool.op(planned.action.operation)
        if planned.assessment_complete:
            planned.action = ToolSpec(
                tool="none", operation="none", target=target["url"], args=[]
            )
        return planned
