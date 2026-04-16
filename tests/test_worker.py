"""Tests for Worker background task runner.

These tests do NOT instantiate the Tk App — Worker is deliberately
decoupled from it via the ui_queue, so we can test it in isolation.
"""
from __future__ import annotations

import queue
import threading
import time

import pytest

from kn_gui.worker import Worker


def drain(q: queue.Queue, timeout: float = 2.0) -> list:
    """Collect queue items until Worker posts ('busy', False), then stop."""
    out: list = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            msg = q.get(timeout=0.1)
        except queue.Empty:
            continue
        out.append(msg)
        if msg == ('busy', False):
            return out
    raise AssertionError(f'did not reach final ("busy", False); collected: {out}')


def test_run_posts_result_and_busy_markers():
    q: queue.Queue = queue.Queue()
    w = Worker(q)
    w.run(lambda: 42, on_done='CALLBACK_TOKEN')
    events = drain(q)

    # Must start with ('busy', True), end with ('busy', False).
    assert events[0] == ('busy', True)
    assert events[-1] == ('busy', False)

    # The 'done' event carries (on_done, result, exc).
    done = [e for e in events if e[0] == 'done']
    assert len(done) == 1
    callback, result, exc = done[0][1]
    assert callback == 'CALLBACK_TOKEN'
    assert result == 42
    assert exc is None


def test_run_captures_exception_in_fn():
    q: queue.Queue = queue.Queue()
    w = Worker(q)

    def boom():
        raise RuntimeError('deliberate')

    w.run(boom, on_done='cb')
    events = drain(q)

    done = [e for e in events if e[0] == 'done']
    _, result, exc = done[0][1]
    assert result is None
    assert isinstance(exc, RuntimeError)
    assert 'deliberate' in str(exc)


def test_second_run_while_busy_is_rejected_with_log_warn():
    """If a task is already running, the next .run() must emit a 'log/warn'
    event instead of starting a parallel thread."""
    q: queue.Queue = queue.Queue()
    w = Worker(q)

    # First task: slow enough that the second run() arrives while busy.
    gate = threading.Event()
    release = threading.Event()

    def slow():
        gate.set()
        release.wait(timeout=2.0)

    w.run(slow, on_done=None)
    assert gate.wait(timeout=1.0), 'first task never started'
    assert w.busy() is True

    # Second call — should NOT spawn a second thread.
    w.run(lambda: 'ignored', on_done='cb2')

    # The warn log should appear almost immediately.
    found_warn = False
    deadline = time.time() + 1.0
    while time.time() < deadline:
        try:
            msg = q.get(timeout=0.1)
        except queue.Empty:
            continue
        if msg[0] == 'log' and msg[1][0] == 'warn':
            found_warn = True
            break
    assert found_warn, 'expected log/warn on collision'

    # Unblock the first task.
    release.set()
    # Drain the rest.
    deadline = time.time() + 2.0
    saw_busy_false = False
    while time.time() < deadline:
        try:
            msg = q.get(timeout=0.1)
        except queue.Empty:
            continue
        if msg == ('busy', False):
            saw_busy_false = True
            break
    assert saw_busy_false


def test_busy_returns_false_after_completion():
    q: queue.Queue = queue.Queue()
    w = Worker(q)
    w.run(lambda: 'ok', on_done=None)
    drain(q)  # waits until ('busy', False) lands
    # Give the thread a tick to actually exit — drain returns as soon as
    # the sentinel arrives, but is_alive can still be True for microseconds.
    for _ in range(20):
        if not w.busy():
            break
        time.sleep(0.01)
    assert w.busy() is False


def test_sequential_runs_work():
    q: queue.Queue = queue.Queue()
    w = Worker(q)

    for expected in (1, 2, 3):
        w.run(lambda x=expected: x * 10, on_done='cb')
        events = drain(q)
        done = [e for e in events if e[0] == 'done']
        assert done[0][1][1] == expected * 10
        # ('busy', False) landed on the queue, but the Thread object can
        # still report is_alive() for a few µs after the target returned.
        # Wait for busy() before kicking the next run() to avoid a race.
        deadline = time.time() + 1.0
        while time.time() < deadline and w.busy():
            time.sleep(0.005)
        assert not w.busy(), 'worker thread did not wind down between runs'


def test_fn_args_passed_through():
    q: queue.Queue = queue.Queue()
    w = Worker(q)
    w.run(lambda a, b: a + b, 3, 4, on_done=None)
    events = drain(q)
    done = [e for e in events if e[0] == 'done']
    assert done[0][1][1] == 7
