from backend import config
from backend.tools.base import BaseTool, ToolError
from backend.tools.httpx_tool import HttpxTool
from backend.tools.nuclei_tool import NucleiTool

_registry: dict[str, BaseTool] | None = None
WHITELIST = ("httpx", "nuclei")


def _build() -> dict[str, BaseTool]:
    tools = [HttpxTool(image=config.TOOL_IMAGES["httpx"]), NucleiTool(image=config.TOOL_IMAGES["nuclei"])]
    reg = {}
    for t in tools:
        if t.id not in WHITELIST:
            raise RuntimeError(f"tool {t.id} violates strict whitelist {WHITELIST}")
        reg[t.id] = t
    assert set(reg) == set(WHITELIST), f"registry incomplete: {set(reg)} vs {WHITELIST}"
    return reg


def registry() -> dict[str, BaseTool]:
    global _registry
    if _registry is None:
        _registry = _build()
    return _registry


def get(tool_id: str) -> BaseTool:
    t = registry().get(tool_id)
    if not t:
        raise ToolError(f"tool {tool_id!r} not registered (whitelist: {WHITELIST})")
    return t


def list_metadata() -> list[dict]:
    return [t.metadata() for t in registry().values()]
