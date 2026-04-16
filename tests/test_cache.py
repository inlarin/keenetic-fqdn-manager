"""Tests for DiskCache.

Key invariant: _save() must be atomic — a concurrent crash or reader
must never observe a truncated / corrupt JSON file.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from kn_gui.cache import DiskCache


@pytest.fixture
def cache_path(tmp_path: Path) -> Path:
    return tmp_path / 'cache.json'


def test_set_then_get_roundtrip(cache_path):
    c = DiskCache(cache_path)
    c.set('k', {'a': 1, 'b': [1, 2, 3]})
    assert c.get('k', max_age=3600) == {'a': 1, 'b': [1, 2, 3]}


def test_get_returns_none_when_expired(cache_path):
    c = DiskCache(cache_path)
    c.set('k', 'v')
    # max_age=0 → anything is considered expired
    assert c.get('k', max_age=0) is None


def test_save_creates_valid_json_on_disk(cache_path):
    c = DiskCache(cache_path)
    c.set('k', 'v')
    # Reload in a fresh instance — the data should round-trip.
    c2 = DiskCache(cache_path)
    assert c2.get('k', max_age=3600) == 'v'


def test_save_is_atomic_no_leftover_tempfiles(cache_path):
    """After a normal set(), the cache dir must contain only the final file."""
    c = DiskCache(cache_path)
    c.set('k', 'v')
    siblings = list(cache_path.parent.iterdir())
    assert siblings == [cache_path], (
        f'unexpected tempfiles left on disk: {[p.name for p in siblings]}'
    )


def test_save_failure_does_not_corrupt_existing_file(cache_path):
    """If os.replace fails, the previous valid file must remain untouched."""
    c = DiskCache(cache_path)
    c.set('k', 'original')
    before = cache_path.read_bytes()

    # Simulate os.replace failing (e.g. cross-device). The bad value must not
    # reach the final file.
    with patch('kn_gui.cache.os.replace', side_effect=OSError('simulated')):
        c.set('k', 'new-value-that-should-not-land')

    after = cache_path.read_bytes()
    assert before == after, 'file was corrupted after failed replace'
    # And no tempfile leftover either.
    siblings = list(cache_path.parent.iterdir())
    assert siblings == [cache_path], (
        f'tempfile not cleaned up after failure: {[p.name for p in siblings]}'
    )


def test_file_on_disk_is_valid_json_even_mid_write(cache_path):
    """Simulate a crash between `write` and `os.replace`: the final file
    must still be parseable (because os.replace is all-or-nothing)."""
    c = DiskCache(cache_path)
    c.set('k', 'v1')
    c.set('k', 'v2')
    # Parse manually — raises if corrupt.
    loaded = json.loads(cache_path.read_text(encoding='utf-8'))
    assert loaded['entries']['k']['value'] == 'v2'


def test_clear_wipes_entries(cache_path):
    c = DiskCache(cache_path)
    c.set('k1', 'v1')
    c.set('k2', 'v2')
    c.clear()
    assert c.get('k1', 3600) is None
    assert c.get('k2', 3600) is None
    assert c.num_entries() == 0
