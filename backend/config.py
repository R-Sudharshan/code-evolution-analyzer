import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("PENTAI_DATA_DIR", BASE_DIR / "backend" / "data"))


def env(name: str, default=None):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except (TypeError, ValueError):
        return default


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except (TypeError, ValueError):
        return default


DATA_DIR.mkdir(parents=True, exist_ok=True)

# Tool whitelist (STRICT) -> httpx probe, WhatWeb fingerprint, nuclei managed templates, ZAP passive baseline
TOOL_WHITELIST = ["httpx", "whatweb", "nuclei", "zap"]

TOOL_IMAGES = {
    "nuclei": env("PENTAI_NUCLEI_IMAGE", "pentai-tools:1.0.0"),
    "httpx": env("PENTAI_HTTPX_IMAGE", "pentai-tools:1.0.0"),
    "whatweb": env("PENTAI_WHATWEB_IMAGE", "pentai-tools:1.0.0"),
    "zap": env("PENTAI_ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:2.17.0"),
}

TEMPLATES_VOLUME = env("PENTAI_TEMPLATES_VOLUME", "pentai-nuclei-templates")
TEMPLATES_VOLUME_MOUNT = env("PENTAI_TEMPLATES_VOLUME_MOUNT", "/templates")

DEFAULT_TEMPLATES = env(
    "PENTAI_TEMPLATE_SET",
    "/templates/http/misconfiguration,/templates/http/exposures,/templates/http/technologies",
)

# Container limits
CONTAINER_USER = env("PENTAI_CONTAINER_USER", "10001:10001")
CONTAINER_MEMORY = env("PENTAI_CONTAINER_MEMORY", "512m")
CONTAINER_CPUS = env_float("PENTAI_CONTAINER_CPUS", 1.0)
CONTAINER_PIDS = env_int("PENTAI_CONTAINER_PIDS", 128)
OUTPUT_MAX_BYTES = env_int("PENTAI_OUTPUT_MAX_BYTES", 8 * 1024 * 1024)

# zap is a JVM; it needs more headroom than the other (CLI) tools
ZAP_CONTAINER_MEMORY = env("PENTAI_ZAP_MEMORY", "2g")
ZAP_CONTAINER_CPUS = env_float("PENTAI_ZAP_CPUS", 2.0)

# Auth
ADMIN_PASSWORD = env("PENTAI_ADMIN_PASSWORD")
AUTO_PASSWORD_FILE = DATA_DIR / "auth.json"
if not ADMIN_PASSWORD:
    if AUTO_PASSWORD_FILE.exists():
        try:
            ADMIN_PASSWORD = AUTO_PASSWORD_FILE.read_text().strip()
        except Exception:
            ADMIN_PASSWORD = None
    if not ADMIN_PASSWORD:
        ADMIN_PASSWORD = secrets.token_urlsafe(12)
        AUTO_PASSWORD_FILE.write_text(ADMIN_PASSWORD)
        print(
            f"[pentai] PENTAI_ADMIN_PASSWORD not set; generated password stored at {AUTO_PASSWORD_FILE}",
            flush=True,
        )

# LLM (OpenAI-compatible)
OPENAI_API_KEY = env("OPENAI_API_KEY") or env("PENTAI_OPENAI_API_KEY")
OPENAI_BASE_URL = env("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL = env("PENTAI_OPENAI_MODEL", "gpt-4o-mini")
OPENAI_TIMEOUT = env_int("OPENAI_TIMEOUT", 60)
OPENAI_MAX_RETRIES = env_int("OPENAI_MAX_RETRIES", 2)

# Engine
MAX_STEPS = env_int("PENTAI_MAX_STEPS", 12)
MAX_UNTRUSTED_CHARS = env_int("PENTAI_MAX_UNTRUSTED_CHARS", 60000)

# Scope safety
ALWAYS_BLOCKED_CIDRS = (
    "169.254.0.0/16",  # cloud metadata (not reachable unless explicitly authorized)
    "fd00:ec2::254/128",
)
