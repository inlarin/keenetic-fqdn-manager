"""HTTP/TCP networking helpers shared across fetchers.

Safety:
- _http_get caps payload size (MAX_HTTP_BYTES) to prevent OOM on hostile URLs.
- Custom opener refuses file:// and ftp:// schemes so a malicious catalog
  'upstream.url' can't exfiltrate local files through a redirect.
"""
from __future__ import annotations

import socket
import time
import urllib.error
import urllib.request
from typing import Callable

from .cache import CACHE
from .constants import APP_NAME, APP_VERSION, MAX_HTTP_BYTES


_HEADERS = {'User-Agent': f'{APP_NAME}/{APP_VERSION}'}


class _SafeHTTPRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects to non-http(s) schemes (no file://, ftp://, …)."""
    _ALLOWED = {'http', 'https'}

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.split(':', 1)[0].lower() not in self._ALLOWED:
            raise urllib.error.HTTPError(newurl, code,
                f'refusing redirect to unsupported scheme: {newurl}',
                headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeHTTPRedirectHandler())


def _http_get(url: str, timeout: float = 20.0,
              max_bytes: int = MAX_HTTP_BYTES) -> str:
    """GET url as text. Enforces scheme and a byte cap."""
    if url.split(':', 1)[0].lower() not in ('http', 'https'):
        raise ValueError(f'only http/https URLs allowed: {url!r}')
    req = urllib.request.Request(url, headers=_HEADERS)
    with _OPENER.open(req, timeout=timeout) as resp:
        # read() honours the count argument; larger payloads are truncated +
        # we raise so callers don't silently handle a partial response.
        raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(
                f'response exceeds {max_bytes} bytes (refusing to load): {url}')
        return raw.decode('utf-8', errors='replace')


def cached(key: str, ttl: float, producer: Callable, force: bool = False):
    """Return cached value if fresh, else produce, cache, return."""
    if not force:
        hit = CACHE.get(key, ttl)
        if hit is not None:
            return hit
    value = producer()
    CACHE.set(key, value)
    return value


def check_tcp_reachable(host: str, port: int = 443,
                        timeout: float = 3.0) -> tuple[bool, float]:
    """TCP connect probe. Returns (reachable, rtt_ms). rtt_ms is -1 on failure."""
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.time() - t0) * 1000
    except Exception:
        return False, -1
