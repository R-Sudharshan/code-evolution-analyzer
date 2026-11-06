import json

from backend.tools import registry
from backend.schemas.agent import ToolSpec
from backend.tools.base import ToolError


def test_only_whitelisted_tools():
    assert set(registry.registry()) == {"httpx", "whatweb", "nuclei", "zap"}


def test_httpx_argv_is_shell_safe():
    spec = ToolSpec(tool="httpx", operation="probe", target="http://example.com/", args=[])
    tool = registry.get("httpx")
    argv = tool.validate_spec(spec)
    assert argv[0] == "httpx"
    assert "-u" in argv and "http://example.com/" in argv
    for a in argv:
        assert a
    assert "-jsonl" in argv
    # json + tech-detect + no redirects following (httpx never follows by default)
    assert "-td" in argv and "-irh" in argv


def test_httpx_reject_unknown_flag():
    tool = registry.get("httpx")
    with pytest.raises(ToolError):
        tool.validate_spec(ToolSpec(tool="httpx", operation="probe", target="http://example.com/", args=["-evil-flag"]))


def test_nuclei_deps_fixed_and_restricted():
    tool = registry.get("nuclei")
    spec = ToolSpec(tool="nuclei", operation="template_scan", target="http://example.com/", args=[])
    argv = tool.validate_spec(spec)
    assert argv[0] == "nuclei"
    joined = " ".join(argv)
    # pinned template dirs only
    assert "/templates/http/misconfiguration" in joined and "/templates/http/exposures" in joined and "/templates/http/technologies" in joined
    # auto-update off + no redirects
    assert "-duc" in argv and "-dr" in argv
    # fuzzing/dast excluded
    assert "-ept" in argv
    idx = argv.index("-ept")
    assert "dast" not in argv[idx + 1] and "fuzz" not in argv[idx + 1]


def test_nuclei_whitelisted_extra_args_only():
    tool = registry.get("nuclei")
    tool.validate_spec(
        ToolSpec(tool="nuclei", operation="template_scan", target="http://example.com/", args=["-tags", "exposed"])
    )
    with pytest.raises(ToolError):
        tool.validate_spec(
            ToolSpec(tool="nuclei", operation="template_scan", target="http://example.com/", args=["-lfa", "1"])
        )


def test_forbidden_characters_rejected():
    with pytest.raises(ToolError):
        registry.get("httpx").validate_spec(
            ToolSpec(tool="httpx", operation="probe", target="http://example.com/; cat /etc/passwd", args=[])
        )


def test_whatweb_argv_is_shell_safe():
    spec = ToolSpec(tool="whatweb", operation="fingerprint", target="http://example.com/", args=[])
    tool = registry.get("whatweb")
    argv = tool.validate_spec(spec)
    assert argv[0] == "whatweb"
    assert "-a" in argv and "1" in argv
    assert "--no-redirect" in argv
    assert "--log-json=-" in argv


def test_whatweb_rejects_unknown_flag():
    tool = registry.get("whatweb")
    with pytest.raises(ToolError):
        tool.validate_spec(
            ToolSpec(tool="whatweb", operation="fingerprint", target="http://example.com/", args=["--proxy", "127.0.0.1:8080"])
        )


def test_zap_argv_is_shell_safe():
    spec = ToolSpec(tool="zap", operation="baseline_scan", target="http://example.com/", args=[])
    tool = registry.get("zap")
    argv = tool.validate_spec(spec)
    assert argv[0] == "zap-baseline.py"
    assert "-t" in argv and "http://example.com/" in argv
    joined = " ".join(argv)
    assert "-J" in argv
    assert "/zap/wrk/pentai_zap_report.json" in joined


def test_zap_rejects_extra_args():
    tool = registry.get("zap")
    with pytest.raises(ToolError):
        tool.validate_spec(
            ToolSpec(tool="zap", operation="baseline_scan", target="http://example.com/", args=["-r", "report.html"])
        )


def test_unknown_operation():
    with pytest.raises(ToolError):
        registry.get("httpx").validate_spec(ToolSpec(tool="httpx", operation="nope", target="http://example.com/", args=[]))


import pytest  # noqa: E402
