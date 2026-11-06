import logging
import time
from urllib.parse import urlparse

import requests

from backend.schemas.finding import Evidence
from backend.storage import repos, audit_event

log = logging.getLogger("pentai.validator")

REQUEST_BUDGET = 10  # requests per validation pass (safety)


def _fetch(url: str, timeout: float = 6.0) -> requests.Response | None:
    try:
        return requests.get(url, timeout=timeout, allow_redirects=False, headers={"User-Agent": "pentai-validator/1.0"})
    except Exception as e:
        log.warning("validator fetch failed %s: %s", url, e)
        return None


def validate_finding(finding: dict) -> dict:
    """Evidence-based revalidation of a POTENTIAL finding. Mutates status:
    VERIFIED when re-probe matches; keeps POTENTIAL when verify is inconclusive
    (connection errors / no rule) and demotes to FALSE_POSITIVE only with clear
    contradiction (e.g., page now 404)."""
    status = finding["status"]
    if status != "POTENTIAL":
        return finding
    url = finding.get("url") or ""
    if not url.startswith("http"):
        return finding
    budget = REQUEST_BUDGET
    title = (finding.get("title") or "").lower()
    rid = finding.get("id")
    r = _fetch(url)
    if r is None:
        return _note(findings=None, f=finding, note="validation_unavailable: target unreachable during validation")
    budget -= 1
    code = r.status_code
    contradiction = code in (404, 410)
    verified = False
    details = f"validation_recheck_status={code}"
    low = (r.text or "").lower() if hasattr(r, "text") else ""

    if contradiction:
        # page disappeared -> cannot confirm exposure
        return _note(findings=None, f=finding, note=f"page_not_found_{code}: marked FALSE_POSITIVE", set_fp=True, details=details)
    # exposure content rules
    rules = {
        "env-file": [".env", "app_key", "database_password"],
        "git-config": ["[core", "repositoryformat"],
        "backup-file": ["#!/bin", "dump", "backup"],
        "composer-lock": ['"packages"', '"name"'],
        "lighttpd": ["lighttpd", "rewr"],
        "htaccess": ["deny", "require"],
        "debug-endpoint": ["debug", "trace", "stack"],
    }
    for key, needles in rules.items():
        if key in title or (finding.get("source_ref") or "").lower().find(key) >= 0:
            if any(n in low for n in needles):
                verified = True
                details += f"; content matched {key} rules"
            break

    if verified:
        ev = Evidence(kind="validation_recheck", url=url, description="Live re-probe confirmed exposure", snippet=low[:300])
        finding["status"] = "VERIFIED"
        finding["validated_via"] = details + "; requests_used=1"
        finding["evidence"] = (finding.get("evidence") or [])[:4] + [ev.model_dump()]
        finding["confidence_scanner"] = "high"
    else:
        finding["validated_via"] = details + "; inconclusive"
        finding["confidence_scanner"] = "low" if contradiction else (finding.get("confidence_scanner") or "medium")
        finding["enrichment"] = {**finding.get("enrichment", {}), "validation": "inconclusive"}
    finding["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    audit_event(
        "finding_validated",
        assessment_id=finding.get("assessment_id"),
        finding_id=rid,
        result=finding["status"],
        details=details,
    )
    return finding


def _note(findings, f, note: str, set_fp: bool = False, details: str = ""):
    if set_fp:
        f["status"] = "FALSE_POSITIVE"
    f["validated_via"] = note
    f["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    audit_event("finding_validated", assessment_id=f.get("assessment_id"), finding_id=f.get("id"), result=f["status"], details=note)
    return f


def validate_batch(findings: list[dict]) -> tuple[int, int]:
    verified = 0
    fp = 0
    for f in findings:
        before = f.get("status")
        after = validate_finding(f)
        if after["status"] != before:
            repos.findings().put(after["fingerprint"], after)
            if after["status"] == "VERIFIED":
                verified += 1
            elif after["status"] == "FALSE_POSITIVE":
                fp += 1
    return verified, fp
