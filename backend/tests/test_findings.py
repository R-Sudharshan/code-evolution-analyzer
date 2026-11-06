import time

from backend.analysis.normalizer import (
    dedupe_merge,
    fingerprint,
    normalize,
    resolve_baseline_cvss,
    classify,
)
from backend.analysis.parser import parse_httpx, parse_nuclei
from backend.schemas.finding import Finding
from backend.storage import repos

NUCLEI_SAMPLE = (
    '{"template-id":"exposed-git","info":{"name":"GIT Repository Exposure","severity":"high",'
    '"tags":["exposure","tech","git"],"classification":{"cwe":["CWE-615"]},"description":"git repo exposed"},'
    '"matcher-status":true,"matched-at":"http://x.test/.git/HEAD","url":"http://x.test/.git/HEAD"}'
)
HTTPX_SAMPLE = (
    '{"url":"http://x.test/","input":"http://x.test/","status_code":200,"title":"Juice Shop",'
    '"tech":["Node.js"],"ip":["10.0.0.5"],"response_time":0.9,"scheme":"http","host":"x.test"}'
)


def test_parse_nuclei():
    rows = parse_nuclei(NUCLEI_SAMPLE + "\n" + "not-json-line")
    assert len(rows) == 1
    r = rows[0]
    assert r["template_id"] == "exposed-git"
    assert r["severity"] == "high"
    assert r["matcher_status"] is True


def test_parse_httpx():
    rows = parse_httpx(HTTPX_SAMPLE)
    assert rows and rows[0]["url"].startswith("http://x.test")


def test_normalize_and_dedupe():
    aid, tid = "an1", "t9"
    rows = parse_nuclei(NUCLEI_SAMPLE)
    findings = normalize(aid, tid, "nuclei", rows)
    assert len(findings) == 1
    f = findings[0]
    assert f.status == "POTENTIAL"
    assert f.source_tool == "nuclei"
    created, merged = dedupe_merge(findings)
    assert created == 1 and merged == 0
    # re-run -> same fingerprint is merged, not duplicated
    c3, m3 = dedupe_merge(normalize(aid, tid, "nuclei", rows))
    assert c3 == 0 and m3 == 1
    c4, m4 = dedupe_merge(normalize(aid, tid, "nuclei", rows))
    assert c4 == 0 and m4 == 1
    stored = repos.findings().get(f.fingerprint)
    assert stored and stored["title"] == "GIT Repository Exposure"
    assert stored["enrichment"]["seen_count"] == 3


def test_evidence_and_cwe():
    rows = parse_nuclei(NUCLEI_SAMPLE)
    f = normalize("an2", "t9", "nuclei", rows)[0]
    assert f.evidence and f.evidence[0].kind == "template_match"
    assert f.cwe_ids  # from classification
    assert f.cvss is None  # computed at enrich stage only


def test_cve_extraction_no_fabrication():
    row = parse_nuclei(
        '{"template-id":"CVE-2021-41773","info":{"name":"Path Traversal","severity":"critical",'
        '"tags":["cve","traversal"],"classification":{"cve-id":["CVE-2021-41773"]}},'
        '"matcher-status":true,"matched-at":"http://x.test/cgi"}'
    )
    f = normalize("an3", "t9", "nuclei", row)[0]
    assert "CVE-2021-41773" in (f.source_ref + f.title) or f.source_ref == "CVE-2021-41773"
    assert f.category == "security-misconfiguration" or "traversal" in f.category
    assert not f.cves  # enrichment adds CVEs; normalizer must not fabricate


def test_fingerprint_stability():
    a = fingerprint("a", "nuclei", "t", "http://x.test/p/?iter=1", "cat")
    b = fingerprint("a", "nuclei", "t", "http://x.test/p/?iter=2", "cat")
    assert a == b  # query excluded


def test_baseline_cvss_scored_by_solver():
    f = Finding(assessment_id="z", fingerprint="fp1", title="T", source_tool="nuclei", category="source-disclosure")
    cv = resolve_baseline_cvss(f)
    assert cv.vector.startswith("CVSS:4.0/")
    assert 0 <= cv.score <= 10
    assert cv.severity in ("None", "Low", "Medium", "High", "Critical")
    assert cv.basis == "category_baseline"


def test_classify_categories():
    assert classify("Directory Listing technology", "dir-index", ["tech"]) == "stack-disclosure"
    assert classify("Backup file exposed", "backup-file", []) in ("backup-file", "security-misconfiguration")
