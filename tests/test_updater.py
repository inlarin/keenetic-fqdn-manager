"""Tests for updater.py — version parse + URL/scheme validation.

Self-update flow was removed in v3.4.6; the rest of this suite verifies
the minimal GitHub-check-and-open-browser path that replaced it.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from kn_gui import updater
from kn_gui.updater import (UpdateInfo, _parse_version, check_for_update,
                             open_release_page)


# ── _parse_version ─────────────────────────────────────────────────────────

@pytest.mark.parametrize('tag, expected', [
    ('v3.4.6',        (3, 4, 6)),
    ('v2.1.0',        (2, 1, 0)),
    ('3.0.6',         (3, 0, 6)),     # optional v-prefix
    ('V10.20.30',     (10, 20, 30)),  # case-insensitive prefix
])
def test_parse_version_stable_tags(tag, expected):
    assert _parse_version(tag) == expected


@pytest.mark.parametrize('tag', [
    '',                   # empty
    'not-a-tag',          # nothing numeric
    'v3.0.6-rc1',         # pre-release marker
    'v3.0.6-beta.2',      # dotted pre-release
    'v3.0.6a1',           # PEP 440 alpha
    'v3.0.6rc',           # PEP 440 rc
    'v3.0.6-dev',         # dev marker
    '3.0.6+build123',     # local version
])
def test_parse_version_rejects_prerelease_and_invalid(tag):
    assert _parse_version(tag) is None, (
        f'pre-release / invalid tag {tag!r} must not be treated as '
        'installable — would offer RC builds to stable users otherwise')


# ── check_for_update ───────────────────────────────────────────────────────

def _mock_response(body_dict: dict):
    """Build a fake urlopen context manager returning *body_dict* as JSON."""
    class Resp:
        def __init__(self):
            self._body = json.dumps(body_dict).encode()
        def read(self, n=-1):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
    return Resp()


def test_check_for_update_detects_newer(monkeypatch):
    monkeypatch.setattr(updater, 'APP_VERSION', '3.4.5')
    monkeypatch.setattr(updater._URL_OPENER, 'open',
                         lambda req, timeout=None: _mock_response({
                             'tag_name': 'v3.4.6',
                             'html_url': 'https://github.com/x/y/releases/tag/v3.4.6',
                             'body': 'release notes',
                         }))
    info = check_for_update()
    assert info.available is True
    assert info.latest == '3.4.6'
    assert 'release notes' in info.release_notes


def test_check_for_update_up_to_date(monkeypatch):
    monkeypatch.setattr(updater, 'APP_VERSION', '3.4.6')
    monkeypatch.setattr(updater._URL_OPENER, 'open',
                         lambda req, timeout=None: _mock_response({
                             'tag_name': 'v3.4.6',
                         }))
    info = check_for_update()
    assert info.available is False
    assert info.error == ''


def test_check_for_update_skips_prerelease(monkeypatch):
    """A -rc tag even if numerically higher must not be offered."""
    monkeypatch.setattr(updater, 'APP_VERSION', '3.4.6')
    monkeypatch.setattr(updater._URL_OPENER, 'open',
                         lambda req, timeout=None: _mock_response({
                             'tag_name': 'v3.4.7-rc1',
                         }))
    info = check_for_update()
    assert info.available is False, (
        'pre-release tag was offered as an update; would push RCs to '
        'stable users')


def test_check_for_update_rejects_malicious_release_url(monkeypatch):
    """If a compromised GitHub response put javascript: / file:// in
    html_url, we must scrub it — otherwise open_release_page would invite
    the user to click a dangerous URL."""
    monkeypatch.setattr(updater, 'APP_VERSION', '3.4.5')
    monkeypatch.setattr(updater._URL_OPENER, 'open',
                         lambda req, timeout=None: _mock_response({
                             'tag_name': 'v3.4.6',
                             'html_url': 'javascript:alert(1)',
                         }))
    info = check_for_update()
    assert info.available is True
    assert info.release_url.startswith('https://'), (
        f'suspicious release_url survived: {info.release_url}')


def test_check_for_update_handles_garbage_response(monkeypatch):
    """Non-dict JSON (maybe an outage page) must come back as `.error`,
    not raise."""
    monkeypatch.setattr(updater._URL_OPENER, 'open',
                         lambda req, timeout=None: _mock_response([]))  # array!
    info = check_for_update()
    assert info.available is False
    assert info.error  # set


def test_check_for_update_handles_network_error(monkeypatch):
    def boom(req, timeout=None):
        import urllib.error
        raise urllib.error.URLError('no route to host')
    monkeypatch.setattr(updater._URL_OPENER, 'open', boom)
    info = check_for_update()
    assert info.available is False
    assert 'no route' in info.error


# ── UpdateInfo ─────────────────────────────────────────────────────────────

def test_update_info_repr_up_to_date():
    info = UpdateInfo(available=False, current='3.4.6', latest='3.4.6')
    assert 'up-to-date' in repr(info)


def test_update_info_repr_available():
    info = UpdateInfo(available=True, current='3.4.5', latest='3.4.6')
    assert '3.4.5' in repr(info) and '3.4.6' in repr(info)


def test_update_info_repr_error():
    info = UpdateInfo(available=False, current='3.4.6', latest='?',
                       error='timeout')
    assert 'timeout' in repr(info)


# ── open_release_page ──────────────────────────────────────────────────────

def test_open_release_page_uses_default_when_empty(monkeypatch):
    calls: list = []
    monkeypatch.setattr(updater.webbrowser, 'open', calls.append)
    open_release_page()
    assert calls == [updater.RELEASES_PAGE]


def test_open_release_page_uses_custom_url(monkeypatch):
    calls: list = []
    monkeypatch.setattr(updater.webbrowser, 'open', calls.append)
    open_release_page('https://example.com/r')
    assert calls == ['https://example.com/r']
