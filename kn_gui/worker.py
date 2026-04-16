"""Single-thread background worker that marshals results back to a UI queue.

Used by App.run_in_background(...). Extracted from app.py so it can be
unit-tested without a live Tk root.

Invariants:
- One background thread at a time. A second .run() while the first is
  active is rejected with a 'log/warn' message (not queued).
- Always emits ('busy', True) on start and ('busy', False) on finish.
- Always emits ('done', (on_done, result_or_None, exc_or_None)).
- Callback on_done is invoked by the caller on the UI thread — the
  worker just posts it, never runs it itself.
"""
from __future__ import annotations

import queue
import threading
from typing import Callable, Optional


class Worker:
    """Background task runner.

    UI events posted to `ui_queue`:
      ('busy', True)   — task started
      ('busy', False)  — task finished (success or failure)
      ('done', (on_done, result, exc))  — result payload
      ('log', ('warn', message))  — non-fatal warnings (e.g. busy collision)
    """

    BUSY_MESSAGE = 'Занят — другая операция в процессе.'

    def __init__(self, ui_queue: queue.Queue):
        self.ui_queue = ui_queue
        self.thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def busy(self) -> bool:
        with self._lock:
            return self.thread is not None and self.thread.is_alive()

    def run(self, fn: Callable, *args, on_done: Optional[Callable] = None) -> None:
        """Post `fn(*args)` to the background thread. When it completes,
        a ('done', (on_done, result, exc)) tuple lands on the UI queue."""
        with self._lock:
            if self.thread is not None and self.thread.is_alive():
                self.ui_queue.put(('log', ('warn', self.BUSY_MESSAGE)))
                return

            def target():
                self.ui_queue.put(('busy', True))
                try:
                    result = fn(*args)
                    self.ui_queue.put(('done', (on_done, result, None)))
                except Exception as e:
                    self.ui_queue.put(('done', (on_done, None, e)))
                finally:
                    self.ui_queue.put(('busy', False))

            self.thread = threading.Thread(target=target, daemon=True)
            self.thread.start()
