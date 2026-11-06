"""CVE enrichment via the NVD 2.0 REST API. Results are cached in the JSON store.
Never invents data: when the API is unreachable, enrichment is marked unavailable.
"""

from backend.storage import repos


def lookup_cve(cve_id: str, timeout: int = 8) -> dict | None:
    if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
        return None
    payload = repos.llm_cache().get(f"cve::{cve_id}")
    if payload:
        return payload["result"]
    import requests

    try:
        r = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            timeout=timeout,
            headers={"User-Agent": "pentai-assessment/1.0"},
        )
        if r.status_code != 200:
            repos.llm_cache().put(f"cve::{cve_id}", {"result": {"id": cve_id, "available": False, "reason": f"NVD status {r.status_code}"}, "created_at": _now()})
            return {"id": cve_id, "available": False, "reason": f"NVD status {r.status_code}"}
        data = r.json()
        items = (data.get("vulnerabilities") or [{}]) or []
        rec = {}
        if items:
            c = items[0].get("cve", {})
            descs = c.get("descriptions", [])
            rec = {
                "id": c.get("id", cve_id),
                "available": True,
                "description": next((d.get("value") for d in descs if d.get("lang") == "en"), ""),
                "published": c.get("published"),
                "metrics": c.get("metrics", {}),
                "references": [x.get("url") for x in (c.get("references") or [])][:4],
            }
        else:
            rec = {"id": cve_id, "available": False, "reason": "not found in NVD"}
        repos.llm_cache().put(f"cve::{cve_id}", {"result": rec, "created_at": _now()})
        return rec
    except Exception as e:
        rec = {"id": cve_id, "available": False, "reason": f"NVD unreachable: {e}"}
        repos.llm_cache().put(f"cve::{cve_id}", {"result": rec, "created_at": _now()})
        return rec


def _now() -> str:
    import time

    return time.strftime("%Y-%m-%dT%H:%M:%S%z")
