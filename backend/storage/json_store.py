import json
import os
import threading
from pathlib import Path


class JsonStore:
    """Thread-safe JSON file store with atomic writes and in-memory index by item id."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cache: dict | None = None
        if self.path.exists():
            try:
                self._cache = json.loads(self.path.read_text() or "{}")
            except Exception as e:
                raise RuntimeError(f"Corrupt store {self.path}: {e}") from e

    def _persist(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._cache or {}, indent=1, sort_keys=True))
        os.replace(tmp, self.path)

    def get(self, item_id: str):
        with self.lock:
            return (self._cache or {}).get(item_id)

    def put(self, item_id: str, data: dict):
        with self.lock:
            self._cache = self._cache or {}
            self._cache[item_id] = data
            self._persist()
            return data

    def update(self, item_id: str, **fields):
        with self.lock:
            item = (self._cache or {}).get(item_id)
            if item is None:
                return None
            item.update(fields)
            self._persist()
            return item

    def delete(self, item_id: str):
        with self.lock:
            if self._cache and item_id in self._cache:
                del self._cache[item_id]
                self._persist()

    def all(self):
        with self.lock:
            return dict(self._cache or {})

    def count(self):
        return len(self._cache or {})


class AppendLog:
    """Append-only JSONL log for audit trail and agent activity."""

    def __init__(self, path: Path, max_lines: int = 100000):
        self.path = Path(path)
        self.max_lines = max_lines
        self.lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: dict):
        with self.lock:
            record = dict(record, _ts=record.get("_ts") or _now())
            with self.path.open("a") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")

    def read_all(self, limit: int = 5000):
        if not self.path.exists():
            return []
        with self.lock:
            return [json.loads(l) for l in self.path.read_text().splitlines()[-limit:] if l.strip()]


import time


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")
