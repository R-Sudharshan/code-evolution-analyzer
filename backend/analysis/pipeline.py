from backend.analysis.parser import parse_tool_output
from backend.analysis.normalizer import dedupe_merge, normalize
from backend.analysis.validator import validate_batch
from backend.storage import repos, agent_event


def process_run(run: dict) -> dict:
    """Full pipeline: parse -> normalize -> dedupe -> validate -> persist."""
    aid = run["assessment_id"]
    target_id = run["target_id"]
    tool = run["tool"]
    rows = parse_tool_output(tool, run.get("stdout") or "")
    if tool == "httpx":
        # probe intel -> summary kept for planner context (no vulnerability claims)
        summary = {
            "urls": [
                {
                    "url": r.get("url"),
                    "status_code": r.get("status_code"),
                    "title": r.get("title"),
                    "tech": (r.get("technology") or [])[:12],
                    "ip": (r.get("ip") or [])[:3],
                    "location": r.get("location"),
                    "security_headers_present": sorted((r.get("headers") or {}).keys()),
                }
                for r in rows
            ]
        }
        run["parsed"] = summary
        repos.runs().put(run["id"], run)
        agent_event(aid, "analysis", f"httpx probe parsed: {len(rows)} result(s)", data={"probe": summary})
        return {"created": 0, "merged": 0, "verified": 0, "false_positives": 0, "parsed": len(rows)}
    if tool == "whatweb":
        # fingerprinting intel -> summary kept for planner context (no vulnerability claims)
        summary = {
            "technology": [
                {
                    "plugin": r.get("plugin"),
                    "version": r.get("version"),
                    "string": r.get("string"),
                    "os": r.get("os"),
                    "module": r.get("module"),
                    "certainty": r.get("certainty"),
                    "target": r.get("target"),
                }
                for r in rows[:60]
            ]
        }
        run["parsed"] = summary
        repos.runs().put(run["id"], run)
        agent_event(aid, "analysis", f"whatweb parsed: {len(rows)} technology record(s)", data={"tech": summary["technology"][:15]})
        return {"created": 0, "merged": 0, "verified": 0, "false_positives": 0, "parsed": len(rows)}
    findings = normalize(aid, target_id, tool, rows)
    created, merged = dedupe_merge(findings)
    # validate only POTENTIAL findings of this run
    from backend.schemas.finding import Finding

    to_validate = [f.model_validate(x) for x in repos.findings().all().values() if x["assessment_id"] == aid and x["status"] == "POTENTIAL"]
    verified, fp = validate_batch([f.model_dump() for f in to_validate])
    run["parsed"] = {"rows": len(rows), "created_findings": created, "merged": merged}
    repos.runs().put(run["id"], run)
    agent_event(
        aid,
        "analysis",
        f"{tool}: parsed {len(rows)} hits; findings created={created} merged={merged} verified={verified} fp={fp}",
    )
    return {"created": created, "merged": merged, "verified": verified, "false_positives": fp, "parsed": len(rows)}
