"""Execution runner: docker-only execution of the whitelisted tools.

Validation order: whitelist -> tool spec/argv -> scope/dns -> container launch.
No host fallback: if Docker or the pinned image is unavailable we record a
deficiency and refuse to execute.
"""

import time
import uuid
from urllib.parse import urlparse

from backend import config
from backend.execution import docker as docker_mod
from backend.execution.scope import ScopeError, ScopeValidator, resolve
from backend.schemas.agent import ToolSpec
from backend.storage import repos, audit_event
from backend.tools import registry as tool_registry
from backend.tools.base import ToolError


def _record_deficiency(assessment_id: str, code: str, message: str):
    rec = repos.assessments().get(assessment_id)
    if rec:
        defs = list(rec.get("deficiencies", []))
        if not any(d.startswith(code) for d in defs):
            defs.append(f"{code}: {message}")
            repos.assessments().update(assessment_id, deficiencies=defs, updated_at=_ts())
    audit_event("deficiency", assessment_id=assessment_id, code=code, message=message)


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _scope_validator(target_id: str) -> ScopeValidator:
    validator = ScopeValidator(target_id)
    # caching by name for validator construction errors is unnecessary
    return validator


def execute(spec: ToolSpec, assessment_id: str, target_id: str, timeout: int | None = None) -> dict:
    run_id = uuid.uuid4().hex[:12]
    container_name = f"pentai-run-{run_id}"
    started_ts = _ts()
    t0 = time.time()
    # pre-register so cancel can find/kill the in-flight container
    repos.runs().put(
        run_id,
        {
            "id": run_id,
            "assessment_id": assessment_id,
            "target_id": target_id,
            "tool": spec.tool,
            "operation": spec.operation,
            "target": spec.target,
            "status": "running",
            "container": container_name,
            "started_at": started_ts,
        },
    )
    audit_event("run_start", assessment_id=assessment_id, run_id=run_id, tool=spec.tool, target=spec.target)

    if spec.tool not in config.TOOL_WHITELIST:  # belt & suspenders (registry also enforces)
        try:
            raise ToolError(f"tool {spec.tool} not in whitelist")
        except ToolError:
            _finish_run(run_id, spec, assessment_id, target_id, None, started_ts, t0, "error", "tool not in whitelist", None)
            raise
    tool = tool_registry.get(spec.tool)

    def _abort(code: str, message: str, exc):
        _record_deficiency(assessment_id, code, message)
        _finish_run(run_id, spec, assessment_id, target_id, None, started_ts, t0, "error", message, None)
        raise exc

    if not docker_mod.docker_available():
        _abort("docker_unavailable", "Docker daemon unavailable; refusing execution.", ToolError("docker unavailable"))
    if not docker_mod.image_exists(tool.image):
        _abort(
            "image_missing",
            f"image {tool.image} missing; run deploy/scripts/build_tools_image.sh",
            ToolError(f"image missing: {tool.image}"),
        )
    if spec.tool == "nuclei" and not docker_mod.volume_exists(config.TEMPLATES_VOLUME):
        _abort(
            "templates_missing",
            f"volume {config.TEMPLATES_VOLUME} missing; run deploy/scripts/install_templates.sh",
            ToolError("templates volume missing"),
        )

    # --- scope validation + DNS re-resolve at execution time -------------------
    try:
        validator = _scope_validator(target_id)
        target_url = spec.target if "://" in spec.target else "http://" + spec.target
        ips = validator.check_url(target_url)
        snapshot = {"host": urlparse(target_url).hostname, "ips": ips, "port": urlparse(target_url).port}
        # revalidate DNS immediately before exec (protects against DNS rebinding between approval and exec)
        validator.check_destination_strict(snapshot["host"], snapshot.get("port"))

        # any additional url-ish arguments (httpx -u targets) are also validated
        validator2 = _scope_validator(target_id)
        for a in spec.args:
            if a.startswith("http"):
                validator2.check_url(a)

        # --- container launch --------------------------------------------------
        argv = tool.validate_spec(spec)
        timeout_s = timeout or tool.default_timeout
        limits = dict(
            user=config.CONTAINER_USER,
            network="bridge",
            memory=config.CONTAINER_MEMORY,
            cpus=config.CONTAINER_CPUS,
            pids=config.CONTAINER_PIDS,
            timeout=timeout_s,
            volumes=[f"{config.TEMPLATES_VOLUME}:{config.TEMPLATES_VOLUME_MOUNT}:ro"] if spec.tool == "nuclei" else [],
        )
        result = docker_mod.run_container(tool.image, argv, limits, name=container_name)
    except ScopeError as e:
        _abort("scope_rejected_at_execution", str(e), e)
    except ToolError as e:
        _abort("execution_refused", str(e), e)
    except docker_mod.DockerError as e:
        _abort("docker_error", str(e), e)

    status = "ok" if result["returncode"] in (0,) else ("error" if result["returncode"] < 0 else "ok_with_errors")
    run = _finish_run(run_id, spec, assessment_id, target_id, argv, started_ts, t0, status, result["stderr"][-4000:], result)
    audit_event("run_done", assessment_id=assessment_id, run_id=run_id, status=status)
    return run


def validator_probable_ips(validator: ScopeValidator) -> set:
    return {str(ip) for ip in validator.ips} | {str(n.network_address) for n in validator.cidrs}  # helper kept for tests


def _finish_run(run_id, spec, assessment_id, target_id, argv, started_ts, t0, status, stderr, result):
    duration = round(time.time() - t0, 2)
    stdout = (result or {}).get("stdout", "")
    capped = stdout[: config.OUTPUT_MAX_BYTES]
    run = {
        "id": run_id,
        "assessment_id": assessment_id,
        "target_id": target_id,
        "tool": spec.tool,
        "operation": spec.operation,
        "target": spec.target,
        "argv": argv,
        "status": status,
        "started_at": started_ts,
        "finished_at": _ts(),
        "duration": duration,
        "returncode": (result or {}).get("returncode"),
        "stdout": capped,
        "stderr": (stderr or "")[:4000],
        "stdout_truncated": len(stdout) > len(capped),
    }
    repos.runs().put(run_id, run)
    # store execution-time snapshot for audit
    audit_event(
        "run_recorded",
        assessment_id=assessment_id,
        run_id=run_id,
        target=spec.target,
        status=status,
        duration=duration,
    )
    return run
