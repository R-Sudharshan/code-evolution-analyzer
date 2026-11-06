# Development log — pentai

Authorized web-application penetration-testing platform with a human-in-the-loop approval workflow.

## Implemented modules

### Backend (Flask + pydantic + JSON persistence)
- `backend/app.py` — Flask factory, error handlers, `/health`, serves production React build at `/` and `/assets/**`.
- `backend/config.py` — env-based config; generated/persisted admin password if not set; strict tool whitelist.
- `backend/api/` — blueprint with auth (`/api/auth/login`), target registration, assessment lifecycle (create/list/detail/cancel/resume), approvals, findings (`/api/findings`), dashboard aggregate (`/api/summary`), reports, SSE event stream.
- `backend/api/middleware.py` — token auth with TTL (JSON sessions).
- `backend/agent/engine.py` — iterative observe → plan → approve → execute → evaluate engine in a daemon thread; resumable; never blocks request threads; approval required before execution.
- `backend/agent/planner.py` / `prompts.py` — LLM contract (strict JSON schema, whitelist-only tools, untrusted-content fencing).
- `backend/llm/client.py` — OpenAI-compatible JSON client with cache, disabled state if no API key.
- `backend/tools/` — BaseTool contract + strict registry + whitelist:
  - `httpx` (probe, structured `-jsonl` output)
  - `whatweb` (technology fingerprint; JSON log to stdout)
  - `nuclei` (curated official templates volume, `-duc` auto-update off)
  - `zap` (OWASP ZAP baseline scan in upstream zaproxy image; `-J` report JSON captured through a controlled temp dir and removed after)
- `backend/execution/` — scope validation (domains/IPs/CIDRs/ports, DNS re-resolution, private-range guard unless explicitly scoped, cloud-metadata block), docker runner (non-root, read-only root FS, cap-drop ALL, no-new-privileges, pids/memory/cpu limits, timeout, output cap).
- `backend/analysis/` — parsers (httpx/nuclei/whatweb/zap), normalize + dedupe by fingerprint (+ CVE/CWE mapping), evidence validation, CVSS 4.0 scoring (official FIRST lookup table port — no invented scores).
- `backend/intelligence/` — CVSS 4.0, CWE map, NVD 2.0 CVE lookup with cache.
- `backend/reporting/` — Jinja2 HTML report (template checklist, tool execution record, activity audit log, deficiencies) and JSON report endpoint.
- `backend/storage/` — JSON vault stores + append logs (`audit.jsonl`, `events.jsonl`), state manager with legal assessment transitions.
- `backend/tests/` — 63 tests, 62 passing, 1 skipped (Juice Shop e2e requires Docker + target image).

### Frontend (React + Vite + Tailwind, JS only)
- `frontend/src/pages/` — Dashboard, Targets, Assessments, Assessment detail (live SSE agent feed, approval cards, findings, runs, report generation), Findings (global aggregate with status workflow), Reports.
- `frontend/src/components/` — Modal, StatCard, SeverityBars, FindingModal (CVSS evidence/remediation view + status workflow), PendingApprovalCard.
- Production build served by Flask (`frontend/dist`); dev server proxies `/api` to `localhost:8484`.

## Pending / not executed in this environment
- Docker daemon is **not installed** in the current WSL sandbox; ZAP/httpx/nuclei/WhatWeb images cannot be built/pulled or executed end-to-end here. E2E Juice Shop test is skipped.
- Playwright browser tests against built UI (not added; manual smoke of API + static serving done).
- Role-based access / multi-user auth (single-user MVP only).

## Dependencies
Backend: Flask, pydantic v2, openai (OpenAI-compatible API), requests, Jinja2.
Frontend: React 18, Vite 8, Tailwind CSS 3, react-router-dom 7, axios.

## Test results (2026-11-06)
- Backend unit/integration: **62 passed, 1 skipped** (`pytest`)
- Frontend: **0 vulnerabilities** (`npm audit`), production build succeeds (`vite build`)
- Static serving smoke: `/` → 200 HTML, `/assets/*` → 200, `/api/*` → 401 without token

## Known limitations
- LLM reasoning requires a configured OpenAI-compatible key; without it the engine pauses with a deficiency note rather than fabricating results.
- ZAP baseline scan is passive (bounded spider + passive rules, no active payloads). Scanner severity/confidence are never treated as final; CVSS 4.0 is computed from documented baseline vectors or NVD data.
- The ZAP host mount is a fresh temp directory under `/tmp` (deleted after the run). It is not a user-controlled path and grants no host-wide access.
- The Docker image `ghcr.io/zaproxy/zaproxy:2.17.0` must be pulled before first ZAP run (`deploy/scripts/pull_zap_image.sh`).
