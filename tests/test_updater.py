"""Tests for updater.py — version parse, URL validation, download integrity.

Covers the main post-release hotfix area (v3.0.2..v3.0.6 were all
updater.py changes with zero unit tests — that gap closes here).
Network I/O is mocked via monkeypatch; no real GitHub calls.
"""
from __future__ import annotations

import hashlib
import io
import json
from unittest.mock import patch

import pytest

from kn_gui import updater
from kn_gui.updater import (MAX_UPDATE_BYTES, UpdateInfo,
                              _parse_version, _safe_version_token,
                              _validate_download_url, check_for_update,
                              download_update)


# ── _parse_version ─────────────────────────────────────────────────────────

@pytest.mark.parametrize('tag, expected', [
    ('v3.0.6',        (3, 0, 6)),
    ('v2.1.0',        (2, 1, 0)),
    ('3.0.6',         (3, 0, 6)),        # optional v-prefix
    ('V10.20.30',     (10, 20, 30)),
])
def test_parse_version_release(tag, expected):
    assert _parse_version(tag) == expected


@pytest.mark.parametrize('tag', [
    'v3.0.7-rc1',       # PEP 440 pre-release
    'v3.0.7-beta.2',
    'v3.0.6-dev',
    'v3.0.6-pre',
    'v3.0.0a1',         # alpha suffix
    'v3.0.0b2',
    'v3.0.0rc3',
    'v3.0.1+meta',      # local version metadata
    '',
    'garbage',
    'v-3',
])
def test_parse_version_prerelease_and_garbage_return_none(tag):
    """Pre-release / garbage tags must NOT be a candidate for auto-update.

    The old re.findall heuristic turned 'v3.0.7-rc1' into (3,0,7,1) and
    treated it as newer than (3,0,7) — we explicitly guard against that.
    """
    assert _parse_version(tag) is None


def test_parse_version_ordering():
    assert _parse_version('v3.0.6') > _parse_version('v3.0.5')
    assert _parse_version('v3.1.0') > _parse_version('v3.0.99')
    assert _parse_version('v4.0.0') > _parse_version('v3.9.9')


# ── _safe_version_token ────────────────────────────────────────────────────

@pytest.mark.parametrize('raw, expected', [
    ('3.0.6',         '3.0.6'),
    ('v3.0.6',        'v3.0.6'),
    ('3.0.6-rc1',     '3.0.6-rc1'),
    ('2.1.0',         '2.1.0'),
    # Rejected — would be path-traversal / shell-injection in a filename.
    ('../../../etc/passwd', ''),
    ('v3.0.0 & rm -rf /', ''),
    ('3.0.0\nmalicious', ''),
    ('',              ''),
    ('v"3"',          ''),
    ('v3;cat',        ''),
    # First character must be alnum — leading dash forbidden because
    # it would look like a CLI flag if substituted into argv.
    ('-3.0.0',        ''),
])
def test_safe_version_token(raw, expected):
    assert _safe_version_token(raw) == expected


# ── _validate_download_url ─────────────────────────────────────────────────

def test_validate_url_accepts_http_and_https():
    _validate_download_url('https://github.com/foo.exe')
    _validate_download_url('http://example.com/x')


@pytest.mark.parametrize('bad', [
    '',
    'file:///C:/Windows/System32/calc.exe',
    'ftp://server/file.exe',
    'javascript:alert(1)',
    'data:text/html,<script>',
    '/local/path/no/scheme',
])
def test_validate_url_rejects_non_http(bad):
    with pytest.raises(ValueError):
        _validate_download_url(bad)


# ── check_for_update ───────────────────────────────────────────────────────

class _FakeResp:
    def __init__(self, body: bytes, headers: dict | None = None):
        self._body = body
        self.headers = headers or {}
        self.status = 200

    def read(self, *_a, **_k):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _mock_github(monkeypatch, payload: dict):
    """Replace the urlopen used by `updater._URL_OPENER.open` with a stub."""
    body = json.dumps(payload).encode()
    monkeypatch.setattr(
        updater._URL_OPENER, 'open',
        lambda req, timeout=None: _FakeResp(body))


def test_check_for_update_newer_release(monkeypatch):
    monkeypatch.setattr(updater, 'APP_VERSION', '3.0.5')
    _mock_github(monkeypatch, {
        'tag_name': 'v3.0.6',
        'body': 'notes',
        'html_url': 'https://github.com/inlarin/keenetic-fqdn-manager/releases/tag/v3.0.6',
        'assets': [{
            'name': 'KeeneticFqdnManager.exe',
            'browser_download_url': 'https://github.com/x/y/z/foo.exe',
            'digest': 'sha256:abcd1234',
        }],
    })
    info = check_for_update(timeout=1.0)
    assert info.available is True
    assert info.latest == '3.0.6'
    assert info.download_url.endswith('.exe')
    assert info.sha256 == 'abcd1234'
    assert not info.error


def test_check_for_update_uptodate(monkeypatch):
    monkeypatch.setattr(updater, 'APP_VERSION', '3.0.6')
    _mock_github(monkeypatch, {
        'tag_name': 'v3.0.6',
        'assets': [{'name': 'KeeneticFqdnManager.exe',
                    'browser_download_url': 'https://x/y.exe'}],
    })
    info = check_for_update(timeout=1.0)
    assert info.available is False
    assert info.latest == '3.0.6'


def test_check_for_update_prerelease_ignored(monkeypatch):
    """A pre-release tag must NOT surface as available — even if it
    parses to a bigger tuple than the current version under the old
    naive `re.findall` logic."""
    monkeypatch.setattr(updater, 'APP_VERSION', '3.0.6')
    _mock_github(monkeypatch, {
        'tag_name': 'v3.0.7-rc1',
        'assets': [],
    })
    info = check_for_update(timeout=1.0)
    assert info.available is False


def test_check_for_update_assets_null_no_crash(monkeypatch):
    """GitHub can return `assets: null` for yanked releases — must not
    TypeError-out in the enumeration."""
    monkeypatch.setattr(updater, 'APP_VERSION', '3.0.5')
    _mock_github(monkeypatch, {
        'tag_name': 'v3.0.6',
        'assets': None,
    })
    info = check_for_update(timeout=1.0)
    assert info.available is True
    assert info.download_url == ''  # no asset → no URL


def test_check_for_update_strips_bad_release_url(monkeypatch):
    """A hostile release_url (javascript:, file://) must be replaced
    with the canonical releases-page URL before handing to the UI."""
    monkeypatch.setattr(updater, 'APP_VERSION', '3.0.5')
    _mock_github(monkeypatch, {
        'tag_name': 'v3.0.6',
        'html_url': 'javascript:alert(1)',
        'assets': [],
    })
    info = check_for_update(timeout=1.0)
    assert info.release_url == updater.RELEASES_PAGE


def test_check_for_update_network_error_is_silent(monkeypatch):
    """Errors bubble up into UpdateInfo.error, never raise."""
    def boom(*_a, **_k):
        raise OSError('network down')
    monkeypatch.setattr(updater._URL_OPENER, 'open', boom)
    info = check_for_update(timeout=1.0)
    assert info.available is False
    assert info.error == 'network down'


# ── download_update ────────────────────────────────────────────────────────

def test_download_update_rejects_non_http_scheme(tmp_path):
    dest = str(tmp_path / 'out.exe')
    with pytest.raises(ValueError):
        download_update('file:///etc/passwd', dest)
    with pytest.raises(ValueError):
        download_update('ftp://x/y', dest)


def test_download_update_happy_path(tmp_path, monkeypatch):
    body = b'FAKE-EXE-CONTENTS' * 100
    digest = hashlib.sha256(body).hexdigest()

    class Resp:
        headers = {'Content-Length': str(len(body))}
        def __init__(self):
            self._data = io.BytesIO(body)
        def read(self, n=-1):
            return self._data.read(n)
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False

    monkeypatch.setattr(updater._URL_OPENER, 'open',
                         lambda req, timeout=None: Resp())

    dest = str(tmp_path / 'out.exe')
    progress_calls: list = []
    download_update('https://example.com/x.exe', dest,
                     on_progress=lambda d, t: progress_calls.append((d, t)),
                     expected_sha256=digest)

    assert open(dest, 'rb').read() == body
    # Progress was reported at least once per chunk.
    assert progress_calls
    assert progress_calls[-1][0] == len(body)


def test_download_update_detects_truncation(tmp_path, monkeypatch):
    body = b'X' * 100

    class Resp:
        # Server lies: advertises 200 bytes, sends only 100.
        headers = {'Content-Length': '200'}
        def __init__(self):
            self._data = io.BytesIO(body)
        def read(self, n=-1):
            return self._data.read(n)
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False

    monkeypatch.setattr(updater._URL_OPENER, 'open',
                         lambda req, timeout=None: Resp())

    dest = str(tmp_path / 'out.exe')
    with pytest.raises(RuntimeError, match='incomplete'):
        download_update('https://example.com/x.exe', dest)
    # Tempfile cleaned up, final dest not created.
    import os
    assert not os.path.exists(dest)
    assert not any(p.name.startswith('kfm_dl_') for p in tmp_path.iterdir())


def test_download_update_verifies_sha256(tmp_path, monkeypatch):
    body = b'HELLO' * 10

    class Resp:
        headers = {'Content-Length': str(len(body))}
        def __init__(self):
            self._data = io.BytesIO(body)
        def read(self, n=-1):
            return self._data.read(n)
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False

    monkeypatch.setattr(updater._URL_OPENER, 'open',
                         lambda req, timeout=None: Resp())

    dest = str(tmp_path / 'out.exe')
    with pytest.raises(RuntimeError, match='SHA-256 mismatch'):
        download_update('https://example.com/x.exe', dest,
                         expected_sha256='0' * 64)
    import os
    assert not os.path.exists(dest)


def test_download_update_cancellation_cleans_up(tmp_path, monkeypatch):
    """Cancellation must raise AND leave no leftover tempfile."""
    body = b'X' * (1 << 20)  # 1 MB

    class Resp:
        headers = {'Content-Length': str(len(body))}
        def __init__(self):
            self._data = io.BytesIO(body)
        def read(self, n=-1):
            return self._data.read(n)
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False

    monkeypatch.setattr(updater._URL_OPENER, 'open',
                         lambda req, timeout=None: Resp())

    dest = str(tmp_path / 'out.exe')
    cancelled = {'v': False}

    def cancel_on_second_call():
        # First invocation returns False; after that, True.
        prev = cancelled['v']
        cancelled['v'] = True
        return prev

    with pytest.raises(RuntimeError, match='cancelled'):
        download_update('https://example.com/x.exe', dest,
                         is_cancelled=cancel_on_second_call)
    import os
    assert not os.path.exists(dest)
    # No stray .part tempfiles.
    assert not any(p.name.startswith('kfm_dl_') for p in tmp_path.iterdir())


def test_download_update_refuses_oversize_advertisement(tmp_path, monkeypatch):
    """Server advertising 200 MB must be rejected before we start reading."""
    class Resp:
        headers = {'Content-Length': str(MAX_UPDATE_BYTES + 1)}
        def read(self, n=-1):
            return b''
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False

    monkeypatch.setattr(updater._URL_OPENER, 'open',
                         lambda req, timeout=None: Resp())

    dest = str(tmp_path / 'out.exe')
    with pytest.raises(RuntimeError, match='exceeds cap'):
        download_update('https://example.com/x.exe', dest)


# ── UpdateInfo ─────────────────────────────────────────────────────────────

def test_update_info_repr_up_to_date():
    info = UpdateInfo(available=False, current='3.0.6', latest='3.0.6')
    assert 'up-to-date' in repr(info)


def test_update_info_repr_error():
    info = UpdateInfo(available=False, current='3.0.6', latest='?',
                       error='timeout')
    assert 'timeout' in repr(info)
