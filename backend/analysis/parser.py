import json
import re
from urllib.parse import urlparse

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _lines(stdout: str):
    for line in (stdout or "").splitlines():
        line = ANSI.sub("", line).strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
                continue
            except Exception:
                pass
        ls = line
        try:
            yield json.loads(ls)
        except Exception:
            continue


def parse_httpx(stdout: str) -> list[dict]:
    out = []
    for o in _lines(stdout):
        if not isinstance(o, dict):
            continue
        url = o.get("final_url") or o.get("url") or o.get("input")
        if not url:
            continue
        rec = {
            "url": url,
            "input": o.get("input"),
            "scheme": o.get("scheme") or urlparse(url).scheme,
            "host": (urlparse(url).hostname or "").lower(),
            "status_code": o.get("status_code") or o.get("status"),
            "title": o.get("title"),
            "technology": o.get("tech") or o.get("technologies") or [],
            "ip": o.get("a") or o.get("ip") or [],
            "location": o.get("location"),
            "response_time": o.get("response_time"),
            "headers": o.get("header", {}) or o.get("headers", {}) or {},
            "csp": o.get("csp"),
        }
        if isinstance(rec["ip"], str):
            rec["ip"] = [rec["ip"]]
        out.append(rec)
    return out


def parse_nuclei(stdout: str) -> list[dict]:
    out = []
    for o in _lines(stdout):
        if not isinstance(o, dict):
            continue
        info = o.get("info") or {}
        cls = info.get("classification") or {}
        out.append(
            {
                "template_id": o.get("template-id") or o.get("id") or "",
                "template_url": o.get("template-url") or "",
                "name": info.get("name") or o.get("template-id") or "nuclei-finding",
                "severity": (info.get("severity") or "unknown").lower(),
                "tags": info.get("tags") or [],
                "description": info.get("description") or "",
                "author": info.get("author") or "",
                "reference": info.get("reference") or [],
                "cwe": cls.get("cwe-id") or cls.get("cwe") or [],
                "cve": [c for c in (cls.get("cve") or cls.get("cve-id") or []) if c],
                "cvss_score_nvd": cls.get("cvss-score"),
                "cvss_metrics_nvd": cls.get("cvss-metrics"),
                "matcher_status": o.get("matcher-status"),
                "matched_at": o.get("matched-at") or o.get("matched"),
                "url": o.get("url") or o.get("matched-at") or "",
                "host": o.get("host") or (o.get("matched-at") or ""),
                "ip": o.get("ip"),
                "extracted": o.get("extracted-results") or o.get("extracted") or [],
                "matcher_name": o.get("matcher-name"),
                "type": o.get("type") or "http",
            }
        )
    return out


def parse_tool_output(tool: str, stdout: str) -> list[dict]:
    if tool == "httpx":
        return parse_httpx(stdout)
    if tool == "nuclei":
        return parse_nuclei(stdout)
    return []
