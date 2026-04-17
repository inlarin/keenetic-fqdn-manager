"""Tests for updater.py — version parse, URL validation, download integrity.

Covers the main post-release hotfix area (v3.0.2..v3.0.6 were all
updater.py changes with zero unit tests — that gap closes here).
Network I/O is mocked via monkeypatch; no real GitHub calls.
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
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


# ── apply_update ───────────────────────────────────────────────────────────
#
# The real apply_update:
#  - does nothing unless IS_FROZEN
#  - spawns a detached PowerShell process with DEVNULL stdio
#  - calls sys.exit(0) at the end
#
# Tests below monkeypatch IS_FROZEN + subprocess.Popen + sys.exit so we can
# verify the right arguments without actually restarting the test process.


def _patched_apply(monkeypatch, *, is_frozen=True,
                    new_exe_exists=True, popen_raises=None):
    """Build a monkeypatched environment and return (popen_spy, exit_spy)."""
    monkeypatch.setattr(updater, 'IS_FROZEN', is_frozen)
    monkeypatch.setattr(updater.os.path, 'exists',
                         lambda p: new_exe_exists)

    popen_calls: list = []

    class _FakePopen:
        def __init__(self, argv, **kwargs):
            popen_calls.append({'argv': argv, 'kwargs': kwargs})
            if popen_raises is not None:
                raise popen_raises

    exit_calls: list = []
    # Patch via the already-imported subprocess module inside updater.
    import subprocess as _sp
    monkeypatch.setattr(_sp, 'Popen', _FakePopen)
    monkeypatch.setattr(updater.sys, 'exit',
                         lambda code=0: exit_calls.append(code))
    # Fast-forward the 0.25 s detach pause so the suite stays snappy.
    import time as _time
    monkeypatch.setattr(_time, 'sleep', lambda *_: None)
    return popen_calls, exit_calls


def test_apply_update_noop_when_not_frozen(monkeypatch, tmp_path):
    popen_calls, exit_calls = _patched_apply(monkeypatch, is_frozen=False)
    updater.apply_update(str(tmp_path / 'new.exe'))
    assert popen_calls == []
    assert exit_calls == []


def test_apply_update_refuses_empty_path(monkeypatch):
    popen_calls, exit_calls = _patched_apply(monkeypatch, is_frozen=True)
    updater.apply_update('')
    assert popen_calls == []
    assert exit_calls == []


def test_apply_update_refuses_missing_new_exe(monkeypatch, tmp_path):
    popen_calls, exit_calls = _patched_apply(
        monkeypatch, is_frozen=True, new_exe_exists=False)
    updater.apply_update(str(tmp_path / 'gone.exe'))
    assert popen_calls == []
    assert exit_calls == []


def test_apply_update_spawns_detached_powershell(monkeypatch, tmp_path):
    """Verify the critical flags: DEVNULL stdio + DETACHED_PROCESS."""
    import subprocess as _sp
    popen_calls, exit_calls = _patched_apply(monkeypatch, is_frozen=True)
    # Stub mkstemp so we don't litter /tmp with real files.
    fake_fd = 99
    fake_ps = str(tmp_path / 'fake.ps1')
    monkeypatch.setattr(updater.tempfile, 'mkstemp',
                         lambda prefix='', suffix='', dir=None: (fake_fd, fake_ps))
    # fdopen → actual temp file so the write succeeds.
    real = open(fake_ps, 'w', encoding='utf-8-sig')
    monkeypatch.setattr(updater.os, 'fdopen',
                         lambda fd, mode='r', **kw: real)

    updater.apply_update('C:\\some\\new.exe')

    assert len(popen_calls) == 1, 'expected exactly one subprocess.Popen'
    call = popen_calls[0]
    argv = call['argv']
    kwargs = call['kwargs']

    # PowerShell invocation
    assert argv[0] == 'powershell.exe'
    assert '-ExecutionPolicy' in argv and 'Bypass' in argv
    assert '-NoProfile' in argv
    assert '-WindowStyle' in argv and 'Hidden' in argv
    assert '-File' in argv and fake_ps in argv

    # CRITICAL: stdio must be DEVNULL — this was the v3.2.0 bug. In
    # PyInstaller --windowed, inheriting the parent's (None) stdio
    # handles causes PowerShell to fail to start.
    assert kwargs['stdin']  == _sp.DEVNULL
    assert kwargs['stdout'] == _sp.DEVNULL
    assert kwargs['stderr'] == _sp.DEVNULL
    assert kwargs['close_fds'] is True

    # The Windows-specific creationflags are guarded by getattr() so the
    # code runs on Linux CI too. On Windows they should all be present;
    # on Linux they're 0 (falsy) and the assertion below stays truthful.
    if sys.platform == 'win32':
        flags = kwargs['creationflags']
        assert flags & _sp.DETACHED_PROCESS
        assert flags & _sp.CREATE_NO_WINDOW
        assert flags & _sp.CREATE_NEW_PROCESS_GROUP

    # sys.exit must be called at the end.
    assert exit_calls == [0]


def test_apply_update_falls_back_to_explorer_when_powershell_missing(
        monkeypatch, tmp_path):
    """If powershell.exe is blocked (AppLocker) we should at least open
    Explorer on the downloaded exe so the user can replace it manually."""
    popen_calls, exit_calls = _patched_apply(
        monkeypatch, is_frozen=True,
        popen_raises=FileNotFoundError('powershell blocked'))

    # Stub mkstemp so the PS1 write path succeeds before the Popen failure.
    fake_ps = str(tmp_path / 'fake.ps1')
    fd = os.open(fake_ps, os.O_WRONLY | os.O_CREAT, 0o600)
    monkeypatch.setattr(updater.tempfile, 'mkstemp',
                         lambda prefix='', suffix='', dir=None: (fd, fake_ps))

    # Second Popen call (explorer fallback) must succeed.
    real_popen = popen_calls.append
    explorer_calls: list = []

    class _Popen2:
        def __init__(self, argv, **kw):
            # First call: simulated PowerShell failure.
            # Second call: explorer.exe /select, new.exe — must record.
            if argv and argv[0] == 'explorer.exe':
                explorer_calls.append(argv)
            else:
                raise FileNotFoundError('powershell blocked')

    import subprocess as _sp
    monkeypatch.setattr(_sp, 'Popen', _Popen2)

    updater.apply_update('C:\\some\\new.exe')

    # We should NOT have exited (nothing was restarted).
    assert exit_calls == []
    # We should have opened Explorer on the new exe.
    assert len(explorer_calls) == 1
    assert explorer_calls[0][0] == 'explorer.exe'
    assert 'C:\\some\\new.exe' in explorer_calls[0]


def test_apply_update_ps_script_escapes_apostrophes_in_path(monkeypatch,
                                                              tmp_path):
    """If the exe path contains single quotes (unusual but legal on NTFS),
    the generated PS1 must double them — otherwise the single-quoted
    string literal breaks and the script is malformed."""
    popen_calls, _ = _patched_apply(monkeypatch, is_frozen=True)
    fake_ps = str(tmp_path / 'fake.ps1')
    fd = os.open(fake_ps, os.O_WRONLY | os.O_CREAT, 0o600)
    monkeypatch.setattr(updater.tempfile, 'mkstemp',
                         lambda prefix='', suffix='', dir=None: (fd, fake_ps))

    evil_path = "C:\\Users\\O'Brien\\new.exe"
    monkeypatch.setattr(updater.sys, 'executable', "C:\\O'Connor.exe")
    updater.apply_update(evil_path)

    # Read the script back from disk and check escaping.
    ps_text = open(fake_ps, 'r', encoding='utf-8-sig').read()
    # Single quotes must be doubled inside single-quoted PS strings.
    assert "'C:\\Users\\O''Brien\\new.exe'" in ps_text
    assert "'C:\\O''Connor.exe'" in ps_text


# import os at the tail so test helpers above can use it
import os  # noqa: E402


# ── pop_update_status ──────────────────────────────────────────────────────
#
# Status file is PS1's way of telling the next-run Python process that
# the restart failed. Python reads + deletes + shows a messagebox.
# Guarantees: called twice in a row, the second call sees nothing
# (consume-on-read). Corrupt/unknown content returns None.


def _status_path(tmp_path):
    """Put UPDATE_STATUS_NAME into an isolated tmpdir via monkeypatching."""
    return tmp_path / updater.UPDATE_STATUS_NAME


def test_pop_update_status_returns_none_when_file_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(updater.tempfile, 'gettempdir', lambda: str(tmp_path))
    assert updater.pop_update_status() is None


def test_pop_update_status_parses_valid_rolled_back(monkeypatch, tmp_path):
    monkeypatch.setattr(updater.tempfile, 'gettempdir', lambda: str(tmp_path))
    sp = _status_path(tmp_path)
    sp.write_text('ROLLED_BACK\nAV locked file\nC:\\Temp\\new.exe\n',
                  encoding='utf-8')
    info = updater.pop_update_status()
    assert info == {
        'kind':    'ROLLED_BACK',
        'reason':  'AV locked file',
        'new_exe': 'C:\\Temp\\new.exe',
    }
    # Consume-on-read: second call returns None because the file is gone.
    assert not sp.exists()
    assert updater.pop_update_status() is None


@pytest.mark.parametrize('kind', ['VANISHED', 'TRUNCATED', 'ROLLBACK_FAILED'])
def test_pop_update_status_recognises_all_known_kinds(monkeypatch, tmp_path, kind):
    monkeypatch.setattr(updater.tempfile, 'gettempdir', lambda: str(tmp_path))
    _status_path(tmp_path).write_text(f'{kind}\nsome reason\n\n',
                                       encoding='utf-8')
    info = updater.pop_update_status()
    assert info is not None
    assert info['kind'] == kind


def test_pop_update_status_rejects_unknown_kind(monkeypatch, tmp_path):
    """An unknown first line (e.g. stale file from an older build) should
    be dropped silently, not shown to the user as an alarming 'GARBAGE'."""
    monkeypatch.setattr(updater.tempfile, 'gettempdir', lambda: str(tmp_path))
    sp = _status_path(tmp_path)
    sp.write_text('GARBAGE_FROM_OLDER_VERSION\nhello\nworld\n',
                  encoding='utf-8')
    assert updater.pop_update_status() is None
    # It's still consumed so the same stale content doesn't linger.
    assert not sp.exists()


def test_pop_update_status_handles_short_file(monkeypatch, tmp_path):
    """Lines < 3 should still parse — missing fields become empty strings."""
    monkeypatch.setattr(updater.tempfile, 'gettempdir', lambda: str(tmp_path))
    _status_path(tmp_path).write_text('ROLLED_BACK\n', encoding='utf-8')
    info = updater.pop_update_status()
    assert info == {
        'kind':    'ROLLED_BACK',
        'reason':  '',
        'new_exe': '',
    }


def test_apply_update_ps_writes_status_on_failure_path(monkeypatch, tmp_path):
    """Regression guard: verify the PS1 we emit actually contains the
    WriteStatus calls and the rollback-then-status-file sequence. Without
    this the user is stuck seeing "update available" forever because PS1
    silently relaunched the old version with no explanation."""
    popen_calls, _ = _patched_apply(monkeypatch, is_frozen=True)
    fake_ps = str(tmp_path / 'fake.ps1')
    fd = os.open(fake_ps, os.O_WRONLY | os.O_CREAT, 0o600)
    monkeypatch.setattr(updater.tempfile, 'mkstemp',
                         lambda prefix='', suffix='', dir=None: (fd, fake_ps))
    updater.apply_update('C:\\new.exe')

    ps_text = open(fake_ps, 'r', encoding='utf-8-sig').read()
    # All four recognised failure kinds must be writable.
    assert 'ROLLED_BACK' in ps_text
    assert 'VANISHED' in ps_text
    assert 'TRUNCATED' in ps_text
    assert 'ROLLBACK_FAILED' in ps_text
    # Pre-flight size check (catches AV-truncated downloads).
    assert '(Get-Item $new).Length' in ps_text
    # Move-Item is the atomic primitive we rely on, not Copy+Remove.
    assert 'Move-Item' in ps_text
