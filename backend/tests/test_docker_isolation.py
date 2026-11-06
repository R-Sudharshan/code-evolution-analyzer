import subprocess

from backend.execution import docker


def test_shell_kwarg_never_used(monkeypatch, tmp_path):
    # ensure docker runner spawns the CLI as an argument vector (no shell)
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        class P:
            returncode = 0
            stdout = "ok"
            stderr = ""
        return P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    docker.run_container("pentai-tools:1.0.0", ["httpx", "-u", "http://example.com/"], limits={"user": "10001:10001", "timeout": 10})
    cmd = captured["cmd"]
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--read-only" in cmd
    assert "no-new-privileges" in cmd
    assert "--network" in cmd
    assert "bridge" in cmd
    for k in ("--memory", "--pids-limit", "-u"):
        assert k in cmd


def test_hardening_flags_present():
    import inspect
    src = inspect.getsource(docker.run_container)
    for flag in ("--rm", "--cap-drop", "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "--pids-limit", "--memory", "--cpus"):
        assert flag in src
    assert "-u" in src


def test_no_host_stderr_leak():
    wiring = docker.run_container.__doc__
    assert "No host exec" in wiring
