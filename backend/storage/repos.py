# Stores: one JSON file per entity type + append logs.
import threading
from pathlib import Path

from backend.config import DATA_DIR
from backend.storage.json_store import AppendLog, JsonStore

_lock = threading.Lock()
_stores: dict[str, JsonStore] = {}
_logs: dict[str, AppendLog] = {}


def _get(kind: str) -> JsonStore | AppendLog:
    with _lock:
        if kind in _stores:
            return _stores[kind]
        if kind in _logs:
            return _logs[kind]
        path = DATA_DIR / f"{kind}.json"
        log_path = DATA_DIR / f"{kind}.jsonl"
        if kind in ("events", "audit"):
            obj = AppendLog(log_path)
            _logs[kind] = obj
        else:
            obj = JsonStore(path)
            _stores[kind] = obj
        return obj


class Repos:
    @staticmethod
    def targets() -> JsonStore:
        return _get("targets")

    @staticmethod
    def assessments() -> JsonStore:
        return _get("assessments")

    @staticmethod
    def actions() -> JsonStore:
        return _get("actions")

    @staticmethod
    def runs() -> JsonStore:
        return _get("runs")

    @staticmethod
    def findings() -> JsonStore:
        return _get("findings")

    @staticmethod
    def reports() -> JsonStore:
        return _get("reports")

    @staticmethod
    def sessions() -> JsonStore:
        return _get("sessions")

    @staticmethod
    def llm_cache() -> JsonStore:
        return _get("llm_cache")

    @staticmethod
    def events() -> AppendLog:
        return _get("events")

    @staticmethod
    def audit() -> AppendLog:
        return _get("audit")


db = Repos()


# Module-level accessors: `repos.findings()` etc.
def targets():
    return db.targets()


def assessments():
    return db.assessments()


def actions():
    return db.actions()


def runs():
    return db.runs()


def findings():
    return db.findings()


def reports():
    return db.reports()


def sessions():
    return db.sessions()


def llm_cache():
    return db.llm_cache()


def events() -> AppendLog:
    return db.events()


def audit() -> AppendLog:
    return db.audit()


def audit_event(event: str, **fields):
    db.audit().append(dict(event=event, **fields))


def agent_event(assessment_id: str, kind: str, message: str, data=None):
    db.events().append(
        dict(
            assessment_id=assessment_id,
            kind=kind,
            message=message,
            data=data or {},
        )
    )
