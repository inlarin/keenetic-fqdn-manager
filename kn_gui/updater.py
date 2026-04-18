"""Check for new releases on GitHub, download, and apply the update.

Update flow:
1. check_for_update()   — queries GitHub Releases API (non-blocking).
2. download_update()    — streams the .exe asset to a temp file.
3. apply_update()       — writes a detached PowerShell launcher that waits
                          for the current process to exit, replaces the exe,
                          restarts it, and cleans up. Then calls sys.exit().

When the app runs from source (not frozen by PyInstaller), apply_update()
is a no-op so the download path gracefully degrades to just saving the file.

Privacy: the only data sent is a single GET to the GitHub API with a
User-Agent header. No telemetry, no analytics, no PII.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
import webbrowser
from typing import Callable, Optional
from urllib.error import URLError
from urllib.request import Request

from .constants import APP_NAME, APP_VERSION

LOGGER = logging.getLogger(__name__)

# Shared file names for the PS1 ↔ Python status channel.
# PS1 writes here when the restart fails (AV lock, permission, etc.).
# On next launch App.__init__ reads + shows + deletes.
UPDATE_LOG_NAME = 'kfm_update.log'
UPDATE_STATUS_NAME = 'kfm_update_status.txt'

GITHUB_OWNER = 'inlarin'
GITHUB_REPO = 'keenetic-fqdn-manager'
RELEASES_API = f'https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest'
RELEASES_PAGE = f'https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest'

# True when running as a PyInstaller-frozen single-file exe.
IS_FROZEN: bool = getattr(sys, 'frozen', False)

# Safety caps for the download step.
MAX_UPDATE_BYTES = 100 * 1024 * 1024   # 100 MB — the exe is ~12 MB; anything
                                        # larger than this is almost certainly
                                        # a mis-pointed asset or an attack.

# Characters allowed in a version string we paste into a tempfile name /
# PowerShell script. Whitelist is strict: letters, digits, dot, dash. That
# matches every semver/PEP-440 tag we will ever ship; malicious traversal
# markers like `..\\`, spaces and quotes are rejected.
_SAFE_VERSION_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,63}$')

# Only HTTP/HTTPS scheme is accepted for the asset URL. Without this a
# compromised GitHub response could point `browser_download_url` at a
# `file:///` or `ftp://` URL and `urlopen` would happily fetch it.
_ALLOWED_SCHEMES = ('http', 'https')


def _safe_version_token(raw: str) -> str:
    """Return *raw* only if it matches the whitelist, else ''.

    Used wherever the GitHub-provided `tag_name` / `latest` string is
    interpolated into a filesystem path or a PowerShell script body.
    Prevents path-traversal (`../evil.exe`) and shell-injection through
    quotes that `_ps()` can't escape.
    """
    raw = (raw or '').strip()
    return raw if _SAFE_VERSION_RE.match(raw) else ''


def _validate_download_url(url: str) -> None:
    """Raise ValueError if *url* is not a plain http(s):// URL."""
    if not url:
        raise ValueError('empty download URL')
    scheme = url.split(':', 1)[0].lower() if ':' in url else ''
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f'refusing non-http(s) download URL: {scheme}:… '
            f'(only {_ALLOWED_SCHEMES} are allowed)')


class _StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects to non-http(s) schemes — mirrors net._SafeHTTPRedirectHandler
    so the updater benefits from the same protection."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.split(':', 1)[0].lower() not in _ALLOWED_SCHEMES:
            raise urllib.error.HTTPError(
                newurl, code,
                f'refusing redirect to unsupported scheme: {newurl}',
                headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_URL_OPENER = urllib.request.build_opener(_StrictRedirectHandler())


def _parse_version(tag: str) -> Optional[tuple[int, ...]]:
    """Parse a release tag into a sortable tuple, or ``None`` for pre-releases.

    Examples:
        'v2.1.1'          → (2, 1, 1)
        'v3.0.6'          → (3, 0, 6)
        'v3.0.7-rc1'      → None   (pre-release — skipped by auto-update)
        'v3.0.7-beta.2'   → None
        '' or 'garbage'   → None

    Pre-release tags are intentionally treated as "not a candidate". Under the
    old logic `re.findall(r'\\d+', 'v3.0.7-rc1')` produced `(3,0,7,1)` which
    compared greater than `(3,0,7)` — so an RC would be offered as newer than
    its own final release.
    """
    if not tag:
        return None
    # Strip a leading `v` / `V`, then decide whether this is a release.
    tag = tag.strip().lstrip('vV')
    # Proper release tags contain only digits and dots after the v-strip.
    # Anything else — `-rc1`, `a1`, `+build`, `beta.2` — is treated as
    # pre-release / local metadata and skipped so users on a stable
    # channel aren't offered test builds. The ordering also avoids the
    # trap where `re.findall(r'\d+', 'v3.0.7-rc1')` = (3,0,7,1) > (3,0,7).
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', tag):
        return None
    nums = tag.split('.')
    return tuple(int(n) for n in nums)


class UpdateInfo:
    """Result of a GitHub release check."""

    def __init__(self, available: bool, current: str, latest: str,
                 download_url: str = '', release_url: str = '',
                 release_notes: str = '', sha256: str = '',
                 error: str = ''):
        self.available = available
        self.current = current
        self.latest = latest
        self.download_url = download_url
        self.release_url = release_url
        self.release_notes = release_notes
        # sha256 is the hex-encoded digest of the asset as advertised by
        # GitHub (field `digest` in modern responses). Empty when the API
        # doesn't provide one — in that case `download_update` falls back
        # to size-only verification.
        self.sha256 = sha256
        self.error = error

    def __repr__(self) -> str:
        if self.error:
            return f'UpdateInfo(error={self.error!r})'
        if self.available:
            return f'UpdateInfo(current={self.current}, latest={self.latest})'
        return f'UpdateInfo(up-to-date={self.current})'


def check_for_update(timeout: float = 8.0) -> UpdateInfo:
    """Query GitHub Releases API for the latest version.

    Returns an UpdateInfo with `.available = True` if a newer version
    exists. Never raises — network/parse errors are captured in `.error`.

    Pre-release tags (vX.Y.Z-rc1, -beta, -dev) are silently skipped so
    that users on stable channels aren't offered test builds.
    """
    current = APP_VERSION
    try:
        req = Request(RELEASES_API, headers={
            'Accept': 'application/vnd.github+json',
            'User-Agent': f'{APP_NAME}/{APP_VERSION}',
        })
        with _URL_OPENER.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read(1 << 20).decode('utf-8', 'replace'))

        if not isinstance(data, dict):
            return UpdateInfo(available=False, current=current, latest='?',
                              error='unexpected GitHub response shape')

        tag = data.get('tag_name') or ''
        latest = tag.lstrip('vV')
        body = data.get('body') or ''

        # `assets` can legally be None (yanked release) — guard against
        # TypeError in the enumeration below.
        assets = data.get('assets') or []

        # Find the .exe asset: URL + digest for integrity check.
        download_url = ''
        sha256 = ''
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            name = asset.get('name', '')
            if name.lower().endswith('.exe'):
                download_url = asset.get('browser_download_url', '') or ''
                # `digest` is returned as 'sha256:<hex>' on modern GitHub.
                digest = asset.get('digest', '') or ''
                if isinstance(digest, str) and digest.lower().startswith('sha256:'):
                    sha256 = digest.split(':', 1)[1].strip().lower()
                break

        release_url = data.get('html_url') or RELEASES_PAGE
        # Refuse to echo non-http(s) release_url — otherwise a compromised
        # response could smuggle `javascript:` or `file://` into the dialog
        # that the user then clicks to open the browser.
        if release_url.split(':', 1)[0].lower() not in _ALLOWED_SCHEMES:
            release_url = RELEASES_PAGE

        current_v = _parse_version(current) or (0,)
        latest_v = _parse_version(latest)
        if latest_v is None:
            # Pre-release, unparseable, or garbage — not a candidate.
            return UpdateInfo(available=False, current=current, latest=latest)

        if latest_v > current_v:
            return UpdateInfo(
                available=True, current=current, latest=latest,
                download_url=download_url, release_url=release_url,
                release_notes=body[:2000], sha256=sha256,
            )
        return UpdateInfo(available=False, current=current, latest=latest)

    except (URLError, OSError, json.JSONDecodeError, KeyError, TypeError) as e:
        return UpdateInfo(available=False, current=current, latest='?',
                          error=str(e))


_DOWNLOAD_CHUNK_BYTES = 1 << 15  # 32 KB per read


def download_update(url: str, dest: str,
                    on_progress: Optional[Callable[[int, int], None]] = None,
                    is_cancelled: Optional[Callable[[], bool]] = None,
                    timeout: float = 30.0,
                    expected_sha256: str = '',
                    max_bytes: int = MAX_UPDATE_BYTES) -> None:
    """Stream *url* to *dest* with integrity and size checks.

    Args:
        url:             Direct download URL for the asset. Must be
                         http:// or https://.
        dest:            Local path to write the downloaded file. Any
                         existing file at *dest* is overwritten.
        on_progress:     Called as ``on_progress(bytes_done, total_bytes)``
                         after each chunk. *total_bytes* is 0 if unknown.
        is_cancelled:    Callable that returns True when the caller wants
                         to abort. The partial file is cleaned up.
        timeout:         Connection timeout in seconds.
        expected_sha256: Hex-encoded SHA-256 of the asset body. When
                         non-empty the download is refused unless the
                         computed digest matches exactly.
        max_bytes:       Absolute ceiling on the body size. Anything
                         larger is refused to prevent disk-fill.

    Raises:
        ValueError:      Non-http(s) URL.
        RuntimeError:    Cancelled, truncated, oversize, or digest mismatch.
    """
    _validate_download_url(url)
    req = Request(url, headers={'User-Agent': f'{APP_NAME}/{APP_VERSION}'})
    downloaded = 0
    hasher = hashlib.sha256()

    # We write to a sibling tempfile first, then os.replace to *dest*.
    # That way a mid-flight cancel/error never leaves a half-written
    # file under the final name — it either lands atomically or not at all.
    dest_dir = os.path.dirname(dest) or '.'
    os.makedirs(dest_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix='kfm_dl_', suffix='.part',
                                     dir=dest_dir)
    try:
        try:
            with _URL_OPENER.open(req, timeout=timeout) as resp:
                total = int(resp.headers.get('Content-Length') or 0)
                if total > max_bytes:
                    raise RuntimeError(
                        f'download refused: Content-Length {total} '
                        f'exceeds cap {max_bytes}')
                with os.fdopen(fd, 'wb') as f:
                    fd = -1  # ownership transferred to f
                    while True:
                        if is_cancelled and is_cancelled():
                            raise RuntimeError('cancelled')
                        chunk = resp.read(_DOWNLOAD_CHUNK_BYTES)
                        if not chunk:
                            break
                        downloaded += len(chunk)
                        if downloaded > max_bytes:
                            raise RuntimeError(
                                f'download refused: body exceeds cap '
                                f'{max_bytes} bytes')
                        hasher.update(chunk)
                        f.write(chunk)
                        if on_progress:
                            on_progress(downloaded, total)

            # Truncation detection: if server advertised a size, we must
            # match it exactly.
            if total and downloaded != total:
                raise RuntimeError(
                    f'incomplete download: got {downloaded} of {total} bytes')

            # Integrity: SHA-256 must match the asset.digest from the API.
            if expected_sha256:
                got = hasher.hexdigest()
                if got.lower() != expected_sha256.lower():
                    raise RuntimeError(
                        f'SHA-256 mismatch: expected {expected_sha256}, '
                        f'got {got}')

            # All good — promote tempfile to final name.
            os.replace(tmp_path, dest)
            tmp_path = ''  # disarm cleanup
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# PowerShell self-update retry budget. Windows Defender / corporate AV can
# hold a write-lock on a freshly-downloaded exe for tens of seconds while
# scanning. 40 × 2-second retries (= 80 s) covers slow scanners without
# leaving the app in a limbo state.
_PS_APPLY_RETRIES = 40
_PS_INITIAL_WAIT = 5    # seconds to wait for the Python process to exit
_PS_RETRY_WAIT = 2      # seconds between retry attempts

# Minimum size of a legitimate release .exe. Anything smaller means the
# download was truncated or AV replaced it with a stub; PS1 refuses to
# install.
_MIN_EXE_BYTES = 1_048_576  # 1 MB


def _ps_quote(path: str) -> str:
    """Safely embed a string into a PowerShell single-quoted literal.

    Single-quoted PS strings don't interpolate and only the single-quote
    itself needs doubling — strictly safer than double-quoted strings
    with backtick escapes.
    """
    return "'" + path.replace("'", "''") + "'"


def _build_ps_script(*, current_exe: str, new_exe_path: str,
                      log_path: str, status_path: str,
                      retries: int = _PS_APPLY_RETRIES,
                      initial_wait: int = _PS_INITIAL_WAIT,
                      retry_wait: int = _PS_RETRY_WAIT,
                      min_bytes: int = _MIN_EXE_BYTES,
                      launch_process: bool = True) -> str:
    """Build the self-update PowerShell script as text.

    Extracted from ``apply_update`` so the integration tests can drive
    it against fake files and verify all four code paths (happy +
    VANISHED + TRUNCATED + ROLLED_BACK) without having to actually
    restart a frozen .exe.

    The ``launch_process`` flag controls whether ``Start-Process $cur``
    is emitted; integration tests use ``launch_process=False`` so they
    can work with placeholder files that aren't valid Win32 executables.
    The production call site always leaves it True.

    The PS1 performs:
      1. Verify $new really exists and is >= min_bytes. Windows Defender
         occasionally quarantines freshly-downloaded exes between the
         Python-side "file exists" check and the moment PS1 starts.
      2. Rename $cur → $bak. Rename of a running exe is always allowed
         on NTFS. If this fails, $new is never touched.
      3. Move (not copy) $new → $cur. Move is atomic on same NTFS volume.
      4. Launch the new exe (unless launch_process=False).
      5. If any of 2..4 fail across all retries, rollback and WRITE a
         status file so the next-run App warns the user.
    """
    launch_block = (
        'Start-Process -FilePath $cur -WorkingDirectory (Split-Path $cur) -ErrorAction Stop\n            Start-Sleep -Seconds 1'
        if launch_process else
        '# (launch suppressed for integration test)'
    )
    rollback_launch = (
        'Start-Process -FilePath $cur -WorkingDirectory (Split-Path $cur)'
        if launch_process else
        '# (launch suppressed for integration test)'
    )

    return f"""\
$ErrorActionPreference = 'Continue'
$log     = {_ps_quote(log_path)}
$status  = {_ps_quote(status_path)}
$cur     = {_ps_quote(current_exe)}
$new     = {_ps_quote(new_exe_path)}
$bak     = $cur + '.bak'
$bakName = [System.IO.Path]::GetFileName($bak)
$ok      = $false
$lastErr = ''

function Say($msg) {{
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Add-Content -Path $log -Value "[$ts] $msg" -Encoding UTF8 -ErrorAction SilentlyContinue
}}

function WriteStatus($kind, $reason) {{
    # Overwrite any stale status; Python reads + deletes this on next run.
    Set-Content -Path $status -Value "$kind`n$reason`n$new" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
}}

Say "apply_update started (retries={retries}, initial_wait={initial_wait}s)"
Say "cur = $cur"
Say "new = $new"
Say "bak = $bak"

# Pre-flight: make sure the downloaded file is really there and non-empty.
# $preflightFailed stops the rollback branch below from overwriting the
# more specific VANISHED / TRUNCATED status with a generic ROLLED_BACK.
Start-Sleep -Seconds {initial_wait}
$preflightFailed = $false
if (-not (Test-Path $new)) {{
    $lastErr = "downloaded file disappeared before update (likely AV): $new"
    Say $lastErr
    WriteStatus 'VANISHED' $lastErr
    $preflightFailed = $true
}} elseif ((Get-Item $new).Length -lt {min_bytes}) {{
    # Under {min_bytes} bytes means download was truncated or AV replaced it.
    $lastErr = "downloaded file looks truncated: $((Get-Item $new).Length) bytes"
    Say $lastErr
    WriteStatus 'TRUNCATED' $lastErr
    $preflightFailed = $true
}} else {{
    for ($i = 0; $i -lt {retries}; $i++) {{
        try {{
            if (Test-Path $bak) {{
                Remove-Item $bak -Force -ErrorAction SilentlyContinue
            }}
            Say "attempt $($i+1)/{retries}: rename current -> $bakName"
            Rename-Item -Path $cur -NewName $bakName -Force -ErrorAction Stop
            Say "move $new -> $cur"
            # Move-Item is atomic on the same volume — either succeeds fully
            # or fails fully. No half-copied exe.
            Move-Item -Path $new -Destination $cur -Force -ErrorAction Stop
            # Sanity: size must match what we just moved.
            $sz = (Get-Item $cur).Length
            if ($sz -lt {min_bytes}) {{
                throw "size after move looks wrong: $sz bytes"
            }}
            Say "launching $cur ($sz bytes)"
            {launch_block}
            Remove-Item $bak -Force -ErrorAction SilentlyContinue
            $ok = $true
            Say "SUCCESS"
            break
        }} catch {{
            $lastErr = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
            Say "attempt $($i+1) failed: $lastErr"
            # If we managed to rename but not move/launch, undo rename for
            # the next retry so subsequent iterations start from a clean state.
            if ((Test-Path $bak) -and (-not (Test-Path $cur))) {{
                try {{ Rename-Item -Path $bak -NewName ([System.IO.Path]::GetFileName($cur)) -ErrorAction SilentlyContinue }} catch {{}}
            }}
            Start-Sleep -Seconds {retry_wait}
        }}
    }}
}}

if ((-not $ok) -and (-not $preflightFailed)) {{
    Say "all retries exhausted, attempting rollback"
    # Write status first so even a crashed rollback leaves evidence.
    # Only overwrite status when we actually entered the retry loop —
    # otherwise the more specific VANISHED/TRUNCATED wins.
    WriteStatus 'ROLLED_BACK' $lastErr
    if ((Test-Path $bak) -and (-not (Test-Path $cur))) {{
        try {{
            Rename-Item -Path $bak -NewName ([System.IO.Path]::GetFileName($cur)) -ErrorAction Stop
            Say "rollback OK — launching old version"
            {rollback_launch}
        }} catch {{
            Say "rollback failed: $($_.Exception.Message)"
            WriteStatus 'ROLLBACK_FAILED' "$lastErr | rollback: $($_.Exception.Message)"
        }}
    }} elseif (Test-Path $cur) {{
        # Current exe is still in place (rename didn't happen or was undone).
        Say "current exe still present — launching it"
        try {{
            {rollback_launch}
        }} catch {{
            Say "couldn't launch current: $($_.Exception.Message)"
        }}
    }}
    # Keep $new on disk so the user can retry manually.
}}
Say "script done (ok=$ok)"
Remove-Item $PSCommandPath -Force -ErrorAction SilentlyContinue
"""


def apply_update(new_exe_path: str) -> None:
    """Replace the running exe with *new_exe_path* and restart.

    Windows does not allow overwriting a running executable in-place, so
    the script uses the rename-then-copy pattern:
      1. Wait for the current process to fully exit.
      2. Rename current exe → current.exe.bak (rename works on running files).
      3. Copy new exe → current exe name.
      4. Launch new exe.
      5. Delete .bak and downloaded temp file.

    If all retries fail (AV locking the new exe for too long, etc.) the
    script restores the backup so the user isn't left with a broken
    install. The PS1 is written to a temp file with a random name via
    ``tempfile.mkstemp`` — a fixed public name would let a colocated
    malicious process swap its content before execution.

    Only has an effect when running as a frozen PyInstaller exe (IS_FROZEN).
    Does nothing (no-op) when running from source.
    """
    if not IS_FROZEN:
        return

    import subprocess

    current_exe = sys.executable
    # Double-check both paths look sane before touching PowerShell.
    if not current_exe or not new_exe_path:
        LOGGER.error('apply_update: empty path — refusing to run')
        return
    if not os.path.exists(new_exe_path):
        LOGGER.error('apply_update: new exe not found at %s', new_exe_path)
        return

    log_path = os.path.join(tempfile.gettempdir(), UPDATE_LOG_NAME)
    status_path = os.path.join(tempfile.gettempdir(), UPDATE_STATUS_NAME)
    ps_script = _build_ps_script(
        current_exe=current_exe,
        new_exe_path=new_exe_path,
        log_path=log_path,
        status_path=status_path,
    )

    # mkstemp → path the caller cannot predict. Other processes cannot
    # race to replace our script before PowerShell reads it.
    fd, ps_path = tempfile.mkstemp(prefix='kfm_upd_', suffix='.ps1')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8-sig') as fh:
            fh.write(ps_script)
    except Exception:
        try:
            os.unlink(ps_path)
        except OSError:
            pass
        LOGGER.exception('apply_update: failed to write PS1 script')
        return

    # Drop a Python-side breadcrumb too, so if the PowerShell never starts
    # at all (e.g. AppLocker, missing PowerShell), the user still has
    # evidence of what happened.
    try:
        with open(log_path, 'a', encoding='utf-8') as lf:
            lf.write(
                f'[python] apply_update spawning PS1\n'
                f'    current_exe = {current_exe}\n'
                f'    new_exe     = {new_exe_path}\n'
                f'    ps_path     = {ps_path}\n')
    except OSError:
        pass

    try:
        # CRITICAL on PyInstaller --windowed: the parent has no stdin/
        # stdout/stderr. Without DEVNULL, Popen tries to inherit the
        # parent's (None) handles, and PowerShell fails to start or
        # crashes on first Write-Host. This was the primary cause of
        # "clicked Yes, nothing restarted" reports.
        #
        # Also: CREATE_NEW_PROCESS_GROUP lets PowerShell outlive us even
        # on Windows 7. DETACHED_PROCESS on its own doesn't always break
        # the console tie when we never had a console to begin with.
        # Windows-only flags — use getattr(... , 0) so the module stays
        # importable on Linux/macOS (where the test suite runs in CI).
        # apply_update is a no-op on non-frozen builds anyway.
        #
        # IMPORTANT: we deliberately do NOT set DETACHED_PROCESS here.
        # Under PyInstaller --windowed the parent process has NO console
        # (GUI subsystem). DETACHED_PROCESS asks Windows to detach the
        # child from a console that doesn't exist — on at least some
        # Win10/11 builds this leaves PowerShell with null stdio handles
        # and it crashes before executing the first line of the script.
        # Diagnosed empirically in v3.4.3: PS1 launched cleanly without
        # DETACHED_PROCESS (variants B and C of diagnose_detach.py).
        #
        # CREATE_NEW_PROCESS_GROUP gives the child its own process
        # group so Ctrl-C / SIGBREAK on the parent doesn't cascade.
        # CREATE_NO_WINDOW hides the fleeting console window.
        # That combination is enough to let the updater survive after
        # sys.exit(0) below.
        _CNPG = getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
        _CNW  = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        creationflags = _CNPG | _CNW
        subprocess.Popen(
            [
                'powershell.exe',
                '-ExecutionPolicy', 'Bypass',
                '-NoProfile',
                '-NonInteractive',
                '-WindowStyle', 'Hidden',
                '-File', ps_path,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creationflags,
        )
    except (OSError, FileNotFoundError) as e:
        # PowerShell is present on every supported Windows (7 SP1+), but
        # corporate AppLocker / SRP may block it. Fall back: show the
        # user where the new exe lives, open Explorer on it.
        LOGGER.error('apply_update: PowerShell unavailable: %s', e)
        try:
            with open(log_path, 'a', encoding='utf-8') as lf:
                lf.write(f'[python] PowerShell spawn failed: {e!r}\n')
        except OSError:
            pass
        try:
            os.unlink(ps_path)
        except OSError:
            pass
        try:
            # At least reveal the downloaded exe — the user can replace
            # the current install manually.
            subprocess.Popen(
                ['explorer.exe', '/select,', new_exe_path],
                close_fds=True,
            )
        except OSError:
            pass
        return

    # Give the subprocess a moment to fully detach before we tear down
    # our own process. Without this, very fast sys.exit() can orphan the
    # freshly-started child on some Windows builds.
    import time as _t
    _t.sleep(0.25)
    sys.exit(0)


def open_release_page(url: str = '') -> None:
    """Open the release page in the default browser."""
    webbrowser.open(url or RELEASES_PAGE)


def pop_update_status() -> Optional[dict]:
    """Return status info from a failed prior update attempt, or None.

    Reads + deletes ``%TEMP%/kfm_update_status.txt`` which the PowerShell
    script writes when the restart couldn't complete (AV lock, AppLocker,
    truncated download, etc.). The App calls this once at startup; if a
    dict comes back it shows the user a warning with the reason and a
    link to the still-downloaded new exe, instead of silently relaunching
    the old version as if nothing happened.

    Returns:
        ``{'kind': 'ROLLED_BACK'|'VANISHED'|'TRUNCATED'|'ROLLBACK_FAILED',
           'reason': str, 'new_exe': str}`` or ``None`` if no status file.
    """
    status_path = os.path.join(tempfile.gettempdir(), UPDATE_STATUS_NAME)
    if not os.path.exists(status_path):
        return None
    try:
        # PS1 writes the status file as UTF-8 with BOM (Add-Content
        # -Encoding UTF8 does so on PowerShell 5.1). utf-8-sig strips the
        # BOM transparently; plain 'utf-8' would leave \ufeff on the first
        # line and the 'kind' check below would silently drop every
        # status message.
        with open(status_path, 'r', encoding='utf-8-sig') as f:
            body = f.read()
    except OSError:
        return None
    finally:
        # Whatever happens, consume it — don't spam the user on every launch.
        try:
            os.unlink(status_path)
        except OSError:
            pass

    lines = [line.strip() for line in body.splitlines()]
    while len(lines) < 3:
        lines.append('')
    kind, reason, new_exe = lines[0], lines[1], lines[2]
    # Only recognise known kinds; anything else is noise from a stale file.
    if kind not in ('ROLLED_BACK', 'VANISHED', 'TRUNCATED', 'ROLLBACK_FAILED'):
        return None
    return {'kind': kind, 'reason': reason, 'new_exe': new_exe}
