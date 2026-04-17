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

import json
import os
import re
import sys
import tempfile
import webbrowser
from typing import Callable, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from .constants import APP_NAME, APP_VERSION

GITHUB_OWNER = 'inlarin'
GITHUB_REPO = 'keenetic-fqdn-manager'
RELEASES_API = f'https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest'
RELEASES_PAGE = f'https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest'

# True when running as a PyInstaller-frozen single-file exe.
IS_FROZEN: bool = getattr(sys, 'frozen', False)


def _parse_version(tag: str) -> tuple[int, ...]:
    """'v2.1.1' → (2, 1, 1). Non-numeric parts are ignored."""
    nums = re.findall(r'\d+', tag)
    return tuple(int(n) for n in nums) if nums else (0,)


class UpdateInfo:
    """Result of a GitHub release check."""

    def __init__(self, available: bool, current: str, latest: str,
                 download_url: str = '', release_url: str = '',
                 release_notes: str = '', error: str = ''):
        self.available = available
        self.current = current
        self.latest = latest
        self.download_url = download_url
        self.release_url = release_url
        self.release_notes = release_notes
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
    """
    current = APP_VERSION
    try:
        req = Request(RELEASES_API, headers={
            'Accept': 'application/vnd.github+json',
            'User-Agent': f'{APP_NAME}/{APP_VERSION}',
        })
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(1 << 20).decode('utf-8', 'replace'))

        tag = data.get('tag_name', '')
        latest = tag.lstrip('v')
        body = data.get('body', '') or ''

        # Find the .exe asset download URL.
        download_url = ''
        for asset in data.get('assets', []):
            name = asset.get('name', '')
            if name.lower().endswith('.exe'):
                download_url = asset.get('browser_download_url', '')
                break

        release_url = data.get('html_url', RELEASES_PAGE)

        if _parse_version(latest) > _parse_version(current):
            return UpdateInfo(
                available=True, current=current, latest=latest,
                download_url=download_url, release_url=release_url,
                release_notes=body[:2000],
            )
        return UpdateInfo(available=False, current=current, latest=latest)

    except (URLError, OSError, json.JSONDecodeError, KeyError) as e:
        return UpdateInfo(available=False, current=current, latest='?',
                          error=str(e))


def download_update(url: str, dest: str,
                    on_progress: Optional[Callable[[int, int], None]] = None,
                    is_cancelled: Optional[Callable[[], bool]] = None,
                    timeout: float = 30.0) -> None:
    """Stream *url* to *dest* (binary write).

    Args:
        url:          Direct download URL for the asset.
        dest:         Local path to write the downloaded file.
        on_progress:  Called as ``on_progress(bytes_done, total_bytes)``
                      after each chunk.  *total_bytes* is 0 if unknown.
        is_cancelled: Callable that returns True when the caller wants to
                      abort.  Raises RuntimeError('cancelled') if triggered.
        timeout:      Connection timeout in seconds.
    """
    req = Request(url, headers={'User-Agent': f'{APP_NAME}/{APP_VERSION}'})
    with urlopen(req, timeout=timeout) as resp:
        total = int(resp.headers.get('Content-Length') or 0)
        downloaded = 0
        chunk_size = 1 << 15  # 32 KB
        with open(dest, 'wb') as f:
            while True:
                if is_cancelled and is_cancelled():
                    raise RuntimeError('cancelled')
                data = resp.read(chunk_size)
                if not data:
                    break
                f.write(data)
                downloaded += len(data)
                if on_progress:
                    on_progress(downloaded, total)


def apply_update(new_exe_path: str) -> None:
    """Replace the running exe with *new_exe_path* and restart.

    Writes a small PowerShell script that:
      1. Waits 2 s for the current process to fully exit.
      2. Moves the new exe over the old one.
      3. Launches the new exe.
      4. Deletes itself.

    Then spawns the script detached and calls sys.exit(0).

    Only has an effect when running as a frozen PyInstaller exe (IS_FROZEN).
    Does nothing (no-op) when running from source.
    """
    if not IS_FROZEN:
        return

    current_exe = sys.executable

    # Single-quoted PowerShell paths handle spaces; avoid double-quoting issues.
    ps_lines = [
        'Start-Sleep -Seconds 2',
        f"Move-Item -Force '{new_exe_path}' '{current_exe}'",
        f"Start-Process '{current_exe}'",
    ]
    ps_script = '\n'.join(ps_lines)

    ps_path = os.path.join(tempfile.gettempdir(), '_kfm_update.ps1')
    with open(ps_path, 'w', encoding='utf-8') as fh:
        fh.write(ps_script)

    import subprocess
    subprocess.Popen(
        [
            'powershell.exe',
            '-ExecutionPolicy', 'Bypass',
            '-NonInteractive',
            '-WindowStyle', 'Hidden',
            '-File', ps_path,
        ],
        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
        close_fds=True,
    )
    sys.exit(0)


def open_release_page(url: str = '') -> None:
    """Open the release page in the default browser."""
    webbrowser.open(url or RELEASES_PAGE)
