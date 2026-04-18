"""Check GitHub Releases for a newer version and open the release page.

Historical note: v3.2.0 through v3.4.5 also shipped self-update (download
the .exe, PowerShell-based rename-then-launch). It produced an endless
series of edge-cases — DETACHED_PROCESS killing the launcher, AV holding
write-locks, UTF-8-BOM in the status file, browsers de-duplicating
downloaded .exe names into (1).exe so the user ran the *other* copy
after "updating"… After several hotfixes we pulled the whole thing.

What remains: a polite notification when a newer version is on GitHub,
plus a button that opens the releases page in the default browser. The
user downloads the fresh .exe manually and overwrites (or replaces)
the old one themselves. Simple, transparent, no moving parts.

Privacy: one GET to api.github.com with a User-Agent header. No
telemetry.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
import webbrowser
from typing import Optional
from urllib.error import URLError
from urllib.request import Request

from .constants import APP_NAME, APP_VERSION

LOGGER = logging.getLogger(__name__)

GITHUB_OWNER = 'inlarin'
GITHUB_REPO = 'keenetic-fqdn-manager'
RELEASES_API = f'https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest'
RELEASES_PAGE = f'https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest'

_ALLOWED_SCHEMES = ('http', 'https')


class _StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects to non-http(s) schemes — otherwise a compromised
    GitHub response could point at `file://` / `ftp://` and urlopen would
    happily fetch it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.split(':', 1)[0].lower() not in _ALLOWED_SCHEMES:
            raise urllib.error.HTTPError(
                newurl, code,
                f'refusing redirect to unsupported scheme: {newurl}',
                headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_URL_OPENER = urllib.request.build_opener(_StrictRedirectHandler())


def _parse_version(tag: str) -> Optional[tuple[int, ...]]:
    """Parse a release tag into a sortable tuple, or ``None`` for
    pre-releases / non-numeric / empty input.

    Examples::
        'v3.4.5'       -> (3, 4, 5)
        'v3.4.6-rc1'   -> None   (pre-release — skipped)
        '' / 'garbage' -> None
    """
    if not tag:
        return None
    tag = tag.strip().lstrip('vV')
    # A stable tag must consist of dotted numeric segments only.
    # Anything else (-, +, letters, rc/beta/dev markers glued to digits)
    # is treated as a pre-release / local-build and skipped entirely.
    # Examples caught: "3.4.6-rc1", "3.4.6a1", "3.4.6+build123", "3.4.6rc".
    if not re.fullmatch(r'\d+(?:\.\d+)*', tag):
        return None
    nums = re.findall(r'\d+', tag)
    if not nums:
        return None
    return tuple(int(n) for n in nums)


class UpdateInfo:
    """Result of a GitHub release check."""

    def __init__(self, available: bool, current: str, latest: str,
                 release_url: str = '', release_notes: str = '',
                 error: str = ''):
        self.available = available
        self.current = current
        self.latest = latest
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
    """Ask GitHub whether there's a newer release tagged.

    Returns an UpdateInfo. `.available == True` means latest > current.
    Pre-release tags (rc, beta, …) are ignored. Never raises — network
    / parse errors end up in `.error`.
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
        release_url = data.get('html_url') or RELEASES_PAGE
        # Guard against a compromised response smuggling `javascript:` /
        # `file://` into a URL the user will be invited to click.
        if release_url.split(':', 1)[0].lower() not in _ALLOWED_SCHEMES:
            release_url = RELEASES_PAGE

        current_v = _parse_version(current) or (0,)
        latest_v = _parse_version(latest)
        if latest_v is None:
            return UpdateInfo(available=False, current=current, latest=latest)

        if latest_v > current_v:
            return UpdateInfo(
                available=True, current=current, latest=latest,
                release_url=release_url, release_notes=body[:2000],
            )
        return UpdateInfo(available=False, current=current, latest=latest)

    except (URLError, OSError, json.JSONDecodeError, KeyError, TypeError) as e:
        return UpdateInfo(available=False, current=current, latest='?',
                          error=str(e))


def open_release_page(url: str = '') -> None:
    """Open the releases page in the default browser so the user can
    download the fresh .exe manually."""
    webbrowser.open(url or RELEASES_PAGE)
