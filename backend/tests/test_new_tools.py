import json

from backend.analysis.normalizer import normalize, dedupe_merge
from backend.analysis.parser import parse_whatweb, parse_zap

WHATWEB_SAMPLE = json.dumps(
    [
        {
            "target": "http://x.test/",
            "http_status": 200,
            "request_config": {},
            "plugins": {
                "HTTPServer": {"version": ["Apache/2.4.57"]},
                "Title": {"string": ["Juice Shop"]},
                "IP": {"string": ["10.0.0.5"]},
            },
        }
    ]
)

ZAP_SAMPLE = json.dumps(
    {
        "@version": "2.17.0",
        "site": [
            {
                "@name": "http://x.test",
                "@host": "x.test",
                "@port": "80",
                "@ssl": "false",
                "alerts": [
                    {
                        "pluginid": "10020",
                        "alertRef": "10020",
                        "alert": "X-Frame-Options Header Not Set",
                        "name": "X-Frame-Options Header Not Set",
                        "riskcode": "1",
                        "confidence": "2",
                        "riskdesc": "Low (Medium)",
                        "desc": "<p>missing header</p>",
                        "solution": "add header",
                        "reference": "<p>ref</p>",
                        "cweid": "1021",
                        "wascid": "15",
                        "sourceid": "1",
                        "instances": [
                            {"uri": "http://x.test/", "method": "GET", "param": "", "attack": "", "evidence": ""}
                        ],
                        "count": "1",
                    }
                ],
            }
        ],
    }
)


def test_parse_whatweb():
    rows = parse_whatweb(WHATWEB_SAMPLE)
    assert len(rows) == 3
    http = next(r for r in rows if r["plugin"] == "HTTPServer")
    assert http["version"] == ["Apache/2.4.57"]


def test_parse_whatweb_broken_json_returns_empty():
    assert parse_whatweb("not json") == []


def test_parse_zap():
    rows = parse_zap(ZAP_SAMPLE)
    assert len(rows) == 1
    assert rows[0]["pluginid"] == "10020"
    assert rows[0]["url"] == "http://x.test/"
    assert rows[0]["cweid"] == "1021"


def test_parse_zap_broken_json_returns_empty():
    assert parse_zap("not json") == []


def test_normalize_zap_finding():
    rows = parse_zap(ZAP_SAMPLE)
    aid, tid = "za1", "tz1"
    findings = normalize(aid, tid, "zap", rows)
    assert len(findings) == 1
    f = findings[0]
    assert f.source_tool == "zap"
    assert f.status == "POTENTIAL"
    assert f.cwe_ids == ["CWE-1021"]
    assert f.evidence and f.evidence[0].kind == "passive_scan_alert"
    created, merged = dedupe_merge(findings)
    assert created == 1 and merged == 0
    c2, m2 = dedupe_merge(normalize(aid, tid, "zap", rows))
    assert c2 == 0 and m2 == 1
