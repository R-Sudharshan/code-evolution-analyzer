import time
from datetime import datetime, timezone

from jinja2 import Environment, BaseLoader

from backend.storage import repos

HTML_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>pentai - {{assessment.name or assessment.id}} Assessment Report</title>
<style>
body{background:#0b1220;color:#e2e8f0;font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;margin:0}
.wrap{max-width:1100px;margin:0 auto;padding:32px}
h1,h2,h3{font-weight:600}
.badge{padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;display:inline-block}
.b-critical{background:#ff3b5c33;color:#ff8098;border:1px solid #ff3b5c55}
.b-high{background:#ff7a4533;color:#ffab80;border:1px solid #ff7a4555}
.b-medium{background:#ffc04d33;color:#ffd88a;border:1px solid #ffc04d55}
.b-low{background:#3ba0ff33;color:#8fc7ff;border:1px solid #3ba0ff55}
.b-none{background:#64748b33;color:#94a3b8;border:1px solid #64748b55}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:10px 12px;border-bottom:1px solid #1e293b;text-align:left;vertical-align:top}
th{color:#94a3b8;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:12px;overflow:auto;font-size:12px}
.muted{color:#94a3b8;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}
.card{background:#101a2d;border:1px solid #1e293b;border-radius:12px;padding:16px}
.card .n{font-size:26px;font-weight:700}
.section{margin-top:36px}
footer{margin-top:48px;border-top:1px solid #1e293b;padding-top:16px;color:#64748b;font-size:12px}
</style></head>
<body><div class="wrap">
<h1>AI-Assisted Web Application Penetration Test</h1>
<div class="muted">Assessment {{assessment.id}} &middot; Target {{target.name}} ({{target.url}}) &middot; Status {{assessment.status}}</div>
<div class="muted">Generated {{generated_at}} &mdash; authorized scope: {{target.scope.domains|join(', ')}} {{target.scope.ips|join(', ')}}</div>

<div class="grid">
  <div class="card"><div class="n">{{stats.findings.total}}</div>Findings</div>
  <div class="card"><div class="n">{{stats.findings.verified}}</div>Verified</div>
  <div class="card"><div class="n">{{stats.findings.potential}}</div>Potential</div>
  <div class="card"><div class="n">{{stats.actions}}</div>Approved actions</div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <p>{{summary}}</p>
  <p class="muted">Severity distribution:
    {% for sev,count in stats.cvss.items() %}<span class="badge b-{{sev|lower}}">{{sev}}: {{count}}</span> {% endfor %}
  </p>
</div>

{% if assessment.deficiencies %}
<div class="section">
  <h2>Deficiencies &amp; Setup Notes</h2>
  <ul>{% for d in assessment.deficiencies %}<li><code>{{d}}</code></li>{% endfor %}</ul>
</div>
{% endif %}

<div class="section">
  <h2>Findings</h2>
  <table>
    <tr><th>Severity</th><th>CVSS 4.0</th><th>Finding</th><th>Status</th><th>URL</th><th>CWE</th></tr>
    {% for f in findings %}
    <tr>
      <td><span class="badge b-{{(f.cvss.severity if f.cvss else 'none')|lower}}">{{f.cvss.severity if f.cvss else 'none'}} ({{f.cvss.score if f.cvss else 0}})</span></td>
      <td><code>{{f.cvss.vector if f.cvss else '-'}}</code></td>
      <td><b>{{f.title}}</b><br><span class="muted">{{f.source_tool}}/{{f.source_ref}} &middot; scanner severity: {{f.severity_scanner}} &middot; confidence: {{f.confidence_scanner}}</span></td>
      <td>{{f.status}}</td>
      <td><code>{{f.url}}</code></td>
      <td>{{f.cwe_ids|join(', ')}}{% if f.cves %}<br>{% for c in f.cves %}<span class="muted">{{c.id}}</span> {% endfor %}{% endif %}</td>
    </tr>
    {% endfor %}
    {% if not findings %}<tr><td colspan="6" class="muted">No findings persisted.</td></tr>{% endif %}
  </table>
</div>

{% for f in findings_detailed %}
<div class="section">
  <h3>{{loop.index}}. {{f.title}} ({{f.status}}, CVSS {{f.cvss.score if f.cvss else 0}})</h3>
  <table>
    <tr><th>Vector</th><th><code>{{f.cvss.vector if f.cvss else '-'}}</code></th></tr>
    <tr><th>URL</th><td><code>{{f.url}}</code></td></tr>
    <tr><th>Remediation</th><td>{{f.remediation}}</td></tr>
    <tr><th>Evidence</th><td>
      {% for e in f.evidence %}<pre>{{e.description}}\nurl={{e.url or '-'}}\n{{e.snippet}}</pre>{% endfor %}
      <span class="muted">{{f.validated_via}}</span>
    </td></tr>
  </table>
</div>
{% endfor %}

<div class="section">
  <h2>Methodology &amp; Tool Execution Record</h2>
  <table>
    <tr><th>Tool</th><th>Operation</th><th>Target</th><th>Approval</th><th>Result</th><th>Duration</th></tr>
    {% for a in actions_log %}
    <tr><td>{{a.tool}}</td><td>{{a.operation}}</td><td><code>{{a.target}}</code></td><td>{{a.status}}</td><td>{{a.run_status}}</td><td>{{a.duration}}s</td></tr>
    {% endfor %}
  </table>
  <p class="muted">All executions ran inside restricted Docker containers (non-root, caps dropped, read-only fs,
  resource limits, timeouts). Every action required explicit human approval bound to a specification hash.
  {{stats.steps}} agent steps were executed.</p>
</div>

<div class="section">
  <h2>Agent Activity (audit trail)</h2>
  <table>
    {% for e in activity[:250] %}<tr><td style="width:170px">{{e._ts}}</td><td>{{e.kind}}</td><td>{{e.message}}</td></tr>{% endfor %}
  </table>
</div>

<footer>Generated by pentai. CVSS scores computed with the FIRST CVSS 4.0 reference table;
scanner severities are informational only and recomputed via the CVSS 4.0 calculator.</footer>
</div></body></html>"""


def _severity_distro(findings: list[dict]) -> dict:
    out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
    for f in findings:
        if f.get("status") == "FALSE_POSITIVE":
            continue
        sev = (f.get("cvss") or {}).get("severity", "None")
        out[sev] = out.get(sev, 0) + 1
    return {k: v for k, v in out.items() if v}


def build_assessment_report(assessment_id: str) -> dict:
    a = repos.assessments().get(assessment_id)
    if not a:
        raise ValueError("assessment not found")
    target = repos.targets().get(a["target_id"]) or {}
    findings = sorted(
        [f for f in repos.findings().all().values() if f["assessment_id"] == assessment_id and f["status"] != "FALSE_POSITIVE"],
        key=lambda f: -(f.get("cvss") or {}).get("score", 0),
    )
    all_findings = [f for f in repos.findings().all().values() if f["assessment_id"] == assessment_id]
    actions = sorted([x for x in repos.actions().all().values() if x["assessment_id"] == assessment_id], key=lambda x: x["created_at"])
    runs = {r["id"]: r for r in repos.runs().all().values() if r.get("assessment_id") == assessment_id}
    activity = [e for e in repos.events().read_all(2000) if e.get("assessment_id") == assessment_id]

    env = Environment(loader=BaseLoader(), autoescape=True)
    html = env.from_string(HTML_TEMPLATE).render(
        assessment=a,
        target=target,
        summary=a.get("summary") or "AI-assisted assessment executed with human-in-the-loop approvals.",
        findings=findings,
        findings_detailed=findings,
        stats={
            "findings": {
                "total": len(all_findings),
                "verified": sum(1 for f in all_findings if f["status"] == "VERIFIED"),
                "potential": sum(1 for f in all_findings if f["status"] == "POTENTIAL"),
            },
            "cvss": _severity_distro(all_findings),
            "actions": len(actions),
            "steps": a.get("steps_done", 0),
        },
        actions_log=[
            {
                "tool": x["tool"],
                "operation": x["operation"],
                "target": x["target"],
                "status": x["status"],
                "duration": (runs.get(x.get("executed_run_id") or "") or {}).get("duration", "-"),
                "run_status": (runs.get(x.get("executed_run_id") or "") or {}).get("status", "-"),
            }
            for x in actions
        ],
        activity=activity,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        time=time,
    )
    record = {
        "id": f"rep-{assessment_id}",
        "assessment_id": assessment_id,
        "format": "html",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "content": html,
        "json": {
            "assessment": a,
            "target": target,
            "findings": all_findings,
            "actions": actions,
            "stats": {
                "findings_total": len(all_findings),
                "verified": sum(1 for f in all_findings if f["status"] == "VERIFIED"),
                "potential": sum(1 for f in all_findings if f["status"] == "POTENTIAL"),
                "cvss_severity_distribution": _severity_distro(all_findings),
            },
        },
    }
    repos.reports().put(record["id"], record)
    return record
