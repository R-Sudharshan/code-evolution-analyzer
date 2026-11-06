import functools
import secrets
import time

from flask import jsonify, request

from backend.config import ADMIN_PASSWORD
from backend.storage import repos, audit_event

SESSION_TTL = 60 * 60 * 6  # 6h


def login(password: str) -> str | None:
    if not ADMIN_PASSWORD or not secrets.compare_digest(password, ADMIN_PASSWORD):
        audit_event("auth_failed")
        return None
    token = secrets.token_urlsafe(32)
    repos.sessions().put(token, {"created_at": time.time()})
    audit_event("auth_login_ok")
    return token


def _valid_token(token: str) -> bool:
    s = repos.sessions().get(token or "")
    if not s:
        return False
    if time.time() - s["created_at"] > SESSION_TTL:
        repos.sessions().delete(token)
        return False
    return True


def require_auth(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else request.args.get("auth_token", "")
        if not _valid_token(token):
            return jsonify({"error": "unauthorized: POST /api/auth/login first"}), 401
        return fn(*args, **kwargs)

    return wrapper
