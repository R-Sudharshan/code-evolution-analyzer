import json
import subprocess
import threading
import time

import requests


class DockerError(Exception):
    pass


def _docker(*args, timeout: int = 60, check: bool = True) -> str:
    try:
        proc = subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise DockerError("docker CLI not available on host") from e
    except subprocess.TimeoutExpired as e:
        raise DockerError(f"docker {args[0]} timed out") from e
    if check and proc.returncode != 0:
        raise DockerError(proc.stderr.strip() or f"docker {args[0]} failed ({proc.returncode})")
    return proc.stdout


def docker_available() -> bool:
    try:
        return _docker("version", "--format", "ok", timeout=10).strip() == "ok"
    except Exception:
        return False


def daemon_info() -> dict:
    try:
        out = _docker("system", "df", "--format", "{{json .}}", timeout=20)
        stats = {}
        for line in out.splitlines():
            if line.strip():
                d = json.loads(line)
                stats[d.get("Type")] = d.get("Size")
        return {"available": True, "df": stats}
    except Exception as e:
        return {"available": False, "error": str(e)}


def image_exists(image: str) -> bool:
    try:
        _docker("image", "inspect", image, timeout=15)
        return True
    except Exception:
        return False


def volume_exists(volume: str) -> bool:
    try:
        _docker("volume", "inspect", volume, timeout=15)
        return True
    except Exception:
        return False


def ensure_volume(volume: str) -> bool:
    if volume_exists(volume):
        return True
    try:
        _docker("volume", "create", volume, timeout=30)
        return True
    except Exception:
        return False


def list_volumes() -> list[str]:
    try:
        out = _docker("volume", "ls", "--format", "{{.Name}}", timeout=20)
        return [l for l in out.splitlines() if l.strip()]
    except Exception:
        return []


def run_container(image: str, argv: list[str], limits: dict, env: dict | None = None, name: str | None = None) -> dict:
    """Run an image with hardened settings and capture stdout. No host exec of tools."""
    container_name = name or f"pentai-run-{int(time.time()*1000)}"
    cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "-u",
        limits.get("user", "10001:10001"),
        "--network",
        limits.get("network", "bridge"),
        "--memory",
        limits.get("memory", "512m"),
        "--cpus",
        str(limits.get("cpus", 1.0)),
        "--pids-limit",
        str(limits.get("pids", 128)),
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--tmpfs",
        "/output:rw,noexec,nosuid,size=32m",
    ]
    for k, v in (env or {}).items():
        cmd += ["--env", f"{k}={v}"]
    for vol_spec in limits.get("volumes", []):
        cmd += ["-v", vol_spec]
    for host_path, container_path in limits.get("host_mounts", []):
        # bind-mount a controlled temp dir; never mount user-supplied paths
        cmd += ["-v", f"{host_path}:{container_path}"]
    cmd += [image] + argv
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=limits.get("timeout", 900),
        )
    except subprocess.TimeoutExpired:
        kill_container(container_name)
        raise DockerError("execution timeout (container killed)")
    duration = time.time() - started
    out = (proc.stdout or "")[-2000000:]
    return {
        "returncode": proc.returncode,
        "stdout": out,
        "stderr": (proc.stderr or "")[-100000:],
        "duration": duration,
        "command": cmd,
        "container": container_name,
    }


def kill_container(container_id: str):
    try:
        _docker("kill", container_id, timeout=20, check=False)
    except Exception:
        pass
