import hashlib
import time
from urllib.parse import urlparse

from backend.intelligence import cve_lookup, cwe_map
from backend.intelligence.cvss4 import cvss_score, severity_band
from backend.schemas.finding import CVSS4, Evidence, Finding
from backend.storage import repos

REMEDIATION = {
    "security-misconfiguration": "Restrict exposed resource; remove sensitive file; enforce authentication/authorization and review nginx/Apache/app config.",
    "exposed-directory": "Disable directory indexing, restrict directory listing in server configuration, remove sensitive content.",
    "source-disclosure": "Remove source/config artifacts from deployment; add ignore rules; protect git metadata (-deny .git in web config).",
    "backup-file": "Delete backup artifacts from public roots and restrict access.",
    "stack-disclosure": "Remove version banners; configure server to hide technology fingerprints where feasible.",
    "default-login": "Change default credentials immediately; enforce strong passwords and account lockout.",
    "cors-misconfig": "Restrict CORS allowed origins; avoid wildcard with credentials.",
    "flag-verification": "Restrict debug endpoints in production; require authentication.",
}

CATEGORY_HINTS = (
    ("backup", "backup-file"),
    ("tech", "stack-disclosure"),
    ("technolog", "stack-disclosure"),
    ("git", "source-disclosure"),
    ("env-file", "source-disclosure"),
    ("composer", "source-disclosure"),
    ("debug", "flag-verification"),
    ("index", "exposed-directory"),
    ("directory-listing", "exposed-directory"),
    ("cors", "cors-misconfig"),
    ("lighttpd", "security-misconfiguration"),
    ("htaccess", "security-misconfiguration"),
)


def classify(title: str, template_id: str, tags=None) -> str:
    blob = " ".join([template_id or "", title or ""] + (tags or [])).lower()
    for k, c in CATEGORY_HINTS:
        if k in blob:
            return c
    return "security-misconfiguration"


def fingerprint(aid: str, tool: str, template_id: str, url: str, category: str) -> str:
    p = urlparse(url or "")
    rel = (p.hostname or "") + ":" + str(p.port or "") + (p.path or "").rstrip("/")
    q = ""  # query strings intentionally excluded for stable fingerprints
    blob = f"{aid}|{tool}|{template_id}|{category}|{rel}{q}"
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def from_nuclei(aid: str, target_id: str, hit: dict) -> Finding | None:
    if not hit.get("matcher_status", True):
        return None
    category = classify(hit.get("name", ""), hit.get("template_id", ""), hit.get("tags"))
    fp = fingerprint(aid, "nuclei", hit.get("template_id", ""), hit.get("matched_at") or hit.get("url", ""), category)
    ev = Evidence(
        kind="template_match",
        url=hit.get("matched_at") or hit.get("url") or "",
        description=f"nuclei template {hit.get('template_id')} matched ({hit.get('matcher_name') or 'matcher'})",
        snippet="; ".join(str(x) for x in (hit.get("extracted") or []))[:400],
        meta={"template_id": hit.get("template_id"), "matcher_status": hit.get("matcher_status")},
    )
    cwes = hit.get("cwe") or cwe_map.guess_cwe(category, hit.get("tags"))
    return Finding(
        assessment_id=aid,
        target_id=target_id,
        fingerprint=fp,
        title=hit.get("name") or hit.get("template_id") or "Unknown finding",
        category=category,
        source_tool="nuclei",
        source_ref=hit.get("template_id") or "",
        url=hit.get("matched_at") or hit.get("url") or "",
        matcher_status=str(hit.get("matcher_status")),
        confidence_scanner="medium",
        severity_scanner=hit.get("severity") or "unknown",
        evidence=[ev],
        remediation=REMEDIATION.get(category, "Review the exposure and apply platform-specific hardening guidance."),
        cwe_ids=cwes,
        enrichment={"tags": hit.get("tags"), "description": (hit.get("description") or "")[:1500]},
    )


def from_httpx_runtime(aid: str, target_id: str, probe: dict) -> Finding | None:
    """HTTP probing itself yields informational assets, not vulnerabilities.
    These become findings with status POTENTIAL, category stack-disclosure, only
    when a redirect chain leaves the target or tech reveals versions."""
    return None


def normalize(aid: str, target_id: str, tool: str, parsed_rows: list[dict]) -> list[Finding]:
    findings = []
    for row in parsed_rows:
        if tool == "nuclei":
            f = from_nuclei(aid, target_id, row)
            if f:
                findings.append(f)
    return findings


def dedupe_merge(new_findings: list[Finding]) -> tuple[int, int]:
    """Dedupe by fingerprint; returns (created, merged)."""
    created = merged = 0
    for f in new_findings:
        existing = repos.findings().get(f.fingerprint)
        if existing:
            if existing["assessment_id"] != f.assessment_id:
                # same fingerprint across assessments is possible; create separate
                pass
            evidence = existing.get("evidence") or []
            existing["evidence"] = (evidence + [e.model_dump() for e in f.evidence])[:6]
            existing["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            existing["enrichment"]["seen_count"] = (existing.get("enrichment", {}).get("seen_count", 1)) + 1
            repos.findings().put(f.fingerprint, existing)
            merged += 1
            continue
        f = _enrich_and_score(f)
        repos.findings().put(f.fingerprint, f.model_dump())
        created += 1
    return created, merged


def _enrich_and_score(f: Finding) -> Finding:
    # 1) CWE from template (higher priority) else category mapping
    if not f.cwe_ids:
        f.cwe_ids = cwe_map.guess_cwe(f.category, None)
    # 2) CVE via NVD
    cves = []
    template = f.source_ref or ""
    import re as _re

    inline_cves = _re.findall(r"CVE-\d{4}-\d{4,7}", (template + " " + f.title + " " + (f.enrichment.get("description") or "")), _re.I)
    inline_cves = [c.upper() for c in inline_cves]
    for c in dict.fromkeys(inline_cves[:3]):
        info = cve_lookup.lookup_cve(c)
        if info:
            cves.append(info)
    f.cves = cves
    # 3) CVSS 4.0: if NVD provides CVSS-Metrics v4.0 base -> use it; else category baseline
    nvd_cvss4 = None
    for c in cves:
        for metricset in ((c.get("metrics") or {}).get("cvssMetricV40") or []):
            data = metricset.get("cvssData") or {}
            if data.get("version") == "4.0" and data.get("vectorString"):
                nvd_cvss4 = data["vectorString"]
                break
        if nvd_cvss4:
            break
    if nvd_cvss4:
        score, macro = cvss_score(nvd_cvss4)
        f.cvss = CVSS4(vector=nvd_cvss4, score=score, severity=severity_band(score), basis="cve_nvd")
        f.enrichment["cvss_macro"] = macro
    else:
        f.cvss = resolve_baseline_cvss(f)
    f.enrichment["enrichment_used"] = "nvd" if cves else "offline"
    return f


# Deliberate, documented baseline vectors by category (not invented scores:
# they are fixed policy templates then scored by the official CVSS 4.0 formula).
BASELINE_VECTORS: dict[str, str] = {
    "source-disclosure": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N",
    "backup-file": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N",
    "exposed-directory": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:L/SA:N",
    "stack-disclosure": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N",
    "cors-misconfig": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "default-login": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "security-misconfiguration": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:L/SA:N",
    "flag-verification": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N",
    "other": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:L/SA:N",
}


def resolve_baseline_cvss(f: Finding) -> CVSS4:
    cv = BASELINE_VECTORS.get(f.category, BASELINE_VECTORS["other"])
    score, macro = cvss_score(cv)
    out = CVSS4(vector=cv, score=score, severity=severity_band(score), basis="category_baseline")
    f.enrichment["cvss_macro"] = macro
    f.enrichment["cvss_rationale"] = f"baseline template for category {f.category}, scored via official CVSS 4.0 formula"
    return out
