"""Static knowledge base for CWE mapping (scanner tags/paths -> CWE ids).
This is a curated, non-exhaustive mapping; ids are standard MITRE CWE."""

CWE_BY_CATEGORY: dict[str, list[str]] = {
    # generic categories -> CWE
    "security-misconfiguration": ["CWE-16"],
    "server-config": ["CWE-16"],
    "exposed-directory": ["CWE-538"],
    "source-disclosure": ["CWE-615"],
    "backup-file": ["CWE-530"],
    "xoops": ["CWE-16"],
    "xss": ["CWE-79"],
    "injection": ["CWE-74"],
    "sqli": ["CWE-89"],
    "lfi": ["CWE-22"],
    "rfi": ["CWE-98"],
    "ssrf": ["CWE-918"],
    "xxe": ["CWE-611"],
    "traversal": ["CWE-22"],
    "redirect": ["CWE-601"],
    "captcha-bypass": ["CWE-804"],
    "nosql-injection": ["CWE-95"],
    "cors-misconfig": ["CWE-942"],
    "arbitrary-file-read": ["CWE-73"],
    "default-login": ["CWE-1188"],
    "protocol": ["CWE-16"],
    "sensitive-exposure": ["CWE-200"],
}


def _norm(tags) -> list[str]:
    t = (x.lower().replace("-", " ").replace("_", " ") for x in (tags or []))
    return list(t)


def guess_cwe(category: str, tags=None) -> list[str]:
    tags_l = _norm(tags)
    cwes: list[str] = []
    for k, v in CWE_BY_CATEGORY.items():
        if k in tags_l:
            cwes += v
    if not cwes:
        # keyword matching within description-ish category/title
        cat = (category or "").lower()
        for k, v in CWE_BY_CATEGORY.items():
            for word in k.split("-"):
                if word and word in cat:
                    cwes += v
    out = []
    for c in cwes:
        if c not in out:
            out.append(c)
    return out[:3]
