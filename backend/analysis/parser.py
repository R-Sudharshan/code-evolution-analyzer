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


def parse_whatweb(stdout: str) -> list[dict]:
    """WhatWeb --log-json=- emits a single JSON array on stdout."""
    text = stdout or ""
    raw = None
    try:
        raw = json.loads(text)
    except Exception:
        # some whatweb builds buffer prelude bytes; recover the JSON array if it
        # is embedded in surrounding log lines
        s, e = text.find("["), text.rfind("]")
        if 0 <= s < e:
            try:
                raw = json.loads(text[s:e + 1])
            except Exception:
                raw = None
    if raw is None:
        return []
    if isinstance(raw, dict):
        raw = [raw]
    out: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        plugins = item.get("plugins") or {}
        if not isinstance(plugins, dict):
            continue

        def _ls(v):
            if v is None:
                return []
            if isinstance(v, list):
                return v
            return [v]

        for name, meta in plugins.items():
            if not isinstance(meta, dict):
                continue
            out.append(
                {
                    "target": item.get("target") or "",
                    "status_code": item.get("http_status"),
                    "plugin": str(name),
                    "version": _ls(meta.get("version")),
                    "string": _ls(meta.get("string")),
                    "os": _ls(meta.get("os")),
                    "module": _ls(meta.get("module")),
                    "filepath": _ls(meta.get("filepath")),
                    "certainty": meta.get("certainty"),
                }
            )
    return out


def parse_zap(stdout: str) -> list[dict]:
    """ZAP Traditional JSON report (written to /zap/wrk/<report>.json).

    Real schema (report-traditional-json.html): top-level keys @version,
    @generated, site[]; each site holds an `alerts` array with pluginid,
    alertRef, name/alert, riskcode, confidence, riskdesc, desc, solution,
    reference, cweid, wascid and an `instances` array with uri/method/param/
    evidence. If that structure is missing we return an empty list — NO data
    is ever fabricated.
    """
    text = stdout or ""
    try:
        raw = json.loads(text)
    except Exception:
        return []
    if not isinstance(raw, dict):
        return []
    sites = raw.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]
    if not sites and isinstance(raw.get("alerts"), list):
        sites = [{"alerts": raw["alerts"]}]
    out: list[dict] = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        sname = site.get("@name") or site.get("name") or ""
        alerts = site.get("alerts") or []
        if isinstance(alerts, dict):
            alerts = [alerts]
        if not isinstance(alerts, list):
            alerts = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances") or []
            if isinstance(instances, dict):
                instances = [instances]
            if not isinstance(instances, list):
                instances = []
            if not instances:
                instances = [{}]
            for inst in instances:
                if not isinstance(inst, dict):
                    continue
                out.append(
                    {
                        "pluginid": str(alert.get("pluginid") or ""),
                        "alert_ref": str(alert.get("alertRef") or alert.get("alertref") or alert.get("pluginid") or ""),
                        "name": alert.get("name") or alert.get("alert") or "zap-alert",
                        "riskcode": str(alert.get("riskcode") or ""),
                        "confidence": str(alert.get("confidence") or ""),
                        "riskdesc": alert.get("riskdesc") or "",
                        "description": alert.get("desc") or "",
                        "solution": alert.get("solution") or "",
                        "reference": alert.get("reference") or "",
                        "cweid": str(alert.get("cweid") or ""),
                        "wascid": str(alert.get("wascid") or ""),
                        "url": inst.get("uri") or sname,
                        "method": inst.get("method"),
                        "param": inst.get("param"),
                        "evidence": inst.get("evidence"),
                        "otherinfo": inst.get("otherinfo"),
                        "site": sname,
                        "count": alert.get("count"),
                    }
                )
    return out


def parse_tool_output(tool: str, stdout: str) -> list[dict]:
    if tool == "httpx":
        return parse_httpx(stdout)
    if tool == "nuclei":
        return parse_nuclei(stdout)
    if tool == "whatweb":
        return parse_whatweb(stdout)
    if tool == "zap":
        return parse_zap(stdout)
    return []
