# pentai — AI Penetration Test Agent

Human-in-the-loop, AI-assisted web-application penetration testing platform.

**Authorized targets only.** Every step requires explicit operator approval. The agent proposes; you decide; the backend enforces scope, tool limits and approvals independently.

## What it does

1. Register an authorized target (domains/IPs/CIDRs/ports, explicit `authorized=true`).
2. Agent probes with **httpx**, fingerprints with **WhatWeb**.
3. LLM analyzes results and proposes the next step (nuclei template scan or ZAP passive baseline).
4. You approve or reject the **exact immutable spec** (hash-bound).
5. Approved actions run in restricted Docker containers (non-root, read-only root FS, capabilities dropped, resource limits, timeouts, output caps).
6. Findings are parsed, deduplicated, evidence-validated, CWE/CVE-enriched and scored with **CVSS 4.0** (scanner severity is never used as final severity).
7. Findings appear in the dashboard; generate professional HTML/JSON reports.

Tools: `httpx`, `whatweb`, `nuclei`, `zap` (passive baseline).

## Quick start

### Prerequisites
- Linux/WSL2 with Python 3.11+ (3.13/3.14 tested)
- Node.js 20+ (local install used; no system Node required)
- Docker (for running tools)

### 1) Backend
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PENTAI_ADMIN_PASSWORD=<choose-a-strong-password> flask --app backend.app run --host 127.0.0.1 --port 8484
```

### 2) Frontend (dev)
```bash
cd frontend
npm install
npm run dev    # opens http://127.0.0.1:5173, proxies /api to backend
```

### 3) Frontend (production, served by Flask)
```bash
cd frontend
npm run build
cd ..
PENTAI_ADMIN_PASSWORD=<choose-a-strong-password> flask --app backend.app run --host 127.0.0.1 --port 8484
# open http://127.0.0.1:8484/  (the built dashboard)
```

### 4) Docker tool images (required for tool execution)
```bash
./deploy/scripts/build_tools_image.sh        # httpx + WhatWeb + nuclei -> pentai-tools:1.0.0
./deploy/scripts/install_templates.sh         # curated nuclei template subset -> docker volume
./deploy/scripts/pull_zap_image.sh            # upstream zaproxy image for ZAP (passive baseline)
```
Without Docker (or the images), execution is refused with a clear deficiency note — it never falls back to running tools on the host.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PENTAI_ADMIN_PASSWORD` | auto-generated | Single-user admin password; if unset, a token is generated and stored at `backend/data/auth.json` |
| `PENTAI_DATA_DIR` | `backend/data` | JSON stores, sessions, audit logs, generated reports |
| `OPENAI_API_KEY` | — | Required for the reasoning agent; without it, assessments pause with `llm_disabled` |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible endpoint |
| `PENTAI_OPENAI_MODEL` | `gpt-4o-mini` | Model name |
| `PENTAI_MAX_STEPS` | `12` | Step budget per assessment |
| `PENTAI_NUCLEI_IMAGE` | `pentai-tools:1.0.0` | Image for httpx/nuclei/whatweb |
| `PENTAI_ZAP_IMAGE` | `ghcr.io/zaproxy/zaproxy:2.17.0` | ZAP baseline image |
| `PENTAI_TEMPLATES_VOLUME` | `pentai-nuclei-templates` | Nuclei template volume |
| `PENTAI_CONTAINER_MEMORY` | `512m` | Per-tool memory limit |
| `PENTAI_ZAP_MEMORY` | `2g` | ZAP memory limit (JVM) |

## Tests
```bash
python3 -m pytest -q          # 62 passed, 1 skipped (Juice Shop e2e requires Docker)
cd frontend && npm run build  # production build
```

## Security model (summary)
- Scope allowlist with DNS revalidation; private ranges blocked unless explicitly scoped; cloud-metadata ranges always blocked.
- Every action is hash-bound to the approved spec; any drift invalidates approval.
- No LLM-generated shell commands; argv arrays only; strict tool whitelist.
- Container execution: non-root, read-only FS, `cap_drop ALL`, `no-new-privileges`, pids/memory/cpu limits, egress via bridge network, output caps.
- Audit trail: `backend/data/audit.jsonl` and `events.jsonl` (approval, execution, findings, state transitions).
- Only `authorized=true` targets; cancel is always available; global stop is the cancel endpoint.

## Repository layout
```
backend/    Flask API, agent, tools, analysis, intelligence, reporting, storage, tests
frontend/   React dashboard (Vite + Tailwind)
deploy/     Dockerfile.tools + image/template setup scripts
```

## Known limitations
- OWASP ZAP integration is implemented and pinned, but **not executed in this sandbox** (no Docker daemon). Pull the image and run a real assessment against an authorized lab (e.g., OWASP Juice Shop) to fully validate the ZAP path.
- Single user; no RBAC/SSO.
- LLM disabled => assessments pause, no results are fabricated.
