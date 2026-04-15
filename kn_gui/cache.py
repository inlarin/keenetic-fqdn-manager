"""Single-file JSON cache with per-entry TTL. One writer at a time via a Lock."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Optional

from .paths import CACHE_FILE


class DiskCache:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {'version': 1, 'entries': {}}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        try:
            self.data = json.loads(self.path.read_text(encoding='utf-8'))
            if 'entries' not in self.data:
                self.data['entries'] = {}
        except Exception:
            self.data = {'version': 1, 'entries': {}}

    def _save(self) -> None:
        try:
            self.path.write_text(
                json.dumps(self.data, ensure_ascii=False, indent=2),
                encoding='utf-8')
        except Exception:
            # A full disk or permission error should not crash the app;
            # next access will simply see no cache hit and re-fetch.
            pass

    def get(self, key: str, max_age: float):
        with self._lock:
            entry = self.data['entries'].get(key)
            if not entry:
                return None
            age = time.time() - entry.get('fetched_at', 0)
            if age > max_age:
                return None
            return entry.get('value')

    def age(self, key: str) -> Optional[float]:
        with self._lock:
            entry = self.data['entries'].get(key)
            if not entry:
                return None
            return time.time() - entry.get('fetched_at', 0)

    def set(self, key: str, value) -> None:
        with self._lock:
            self.data['entries'][key] = {
                'fetched_at': time.time(),
                'value': value,
            }
            self._save()

    def clear(self) -> None:
        with self._lock:
            self.data = {'version': 1, 'entries': {}}
            self._save()

    def size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except Exception:
            return 0

    def num_entries(self) -> int:
        return len(self.data.get('entries', {}))


# Module-level singleton used across fetchers.
CACHE = DiskCache(CACHE_FILE)
