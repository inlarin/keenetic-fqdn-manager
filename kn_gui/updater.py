"""Check for new releases on GitHub and offer to download.

The check is non-blocking (runs in the Worker thread) and only talks to
the GitHub API — no exe is downloaded automatically. The user clicks a
link to open the release page in their browser.

Privacy: the only data sent is a GET to
`https://api.github.com/repos/<owner>/<repo>/releases/latest`
with a User-Agent header. No telemetry, no analytics, no PII.
"""
from __future__ import annotations

import json
import re
import webbrowser
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from .constants import APP_NAME, APP_VERSION

GITHUB_OWNER = 'inlarin'
GITHUB_REPO = 'keenetic-fqdn-manager'
RELEASES_API = f'https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest'
RELEASES_PAGE = f'https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest'


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


def open_release_page(url: str = '') -> None:
    """Open the release page in the default browser."""
    webbrowser.open(url or RELEASES_PAGE)
