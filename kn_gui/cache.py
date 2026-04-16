"""Single-file JSON cache with per-entry TTL. One writer at a time via a Lock.

Writes go through a tempfile + os.replace pattern so that a crash or a
concurrent copy of the same app doesn't leave a half-written JSON file
on disk (which _load would then treat as "no cache" and silently re-fetch
every source)."""
from __future__ import annotations

import json
import os
import tempfile
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
        """Atomic write: dump to a sibling temp file, fsync, then os.replace.

        os.replace() is atomic on the same filesystem on both POSIX and
        Windows, so readers will always see either the old complete file
        or the new complete file — never a truncated/corrupt JSON.
        """
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                self.data, ensure_ascii=False, indent=2,
            ).encode('utf-8')
            # NamedTemporaryFile on Windows cannot be opened twice, so we
            # create + close it manually instead.
            fd, tmp_path = tempfile.mkstemp(
                prefix=self.path.name + '.',
                suffix='.tmp',
                dir=str(self.path.parent),
            )
            try:
                with os.fdopen(fd, 'wb') as f:
                    f.write(payload)
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except (AttributeError, OSError):
                        # Some filesystems / platforms (tmpfs, ramdisk) don't
                        # support fsync — non-fatal.
                        pass
                os.replace(tmp_path, self.path)
            except Exception:
                # Best-effort cleanup of the tempfile if os.replace didn't happen.
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
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
