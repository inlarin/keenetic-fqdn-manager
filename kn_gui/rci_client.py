"""Keenetic RCI (HTTP/JSON) transport.

NDMS 5.x exposes a REST-like endpoint at /rci/ that mirrors the CLI tree:

    GET  /rci/show/version                  → version dict
    GET  /rci/show/interface/PPPoE0         → interface dict
    POST /rci  { ... JSON body ... }        → run arbitrary ops

Auth uses a challenge-response over HTTP:

    1. GET /auth → 401 + X-NDM-Realm, X-NDM-Challenge
    2. password = SHA256( challenge + MD5("user:realm:pass") )
    3. POST /auth { "login": user, "password": sha } → 200 + session cookie
    4. Subsequent requests carry the cookie.

Advantages over Telnet:
- JSON responses parse cleanly (no ANSI, no "(config)>" prompt handling).
- Password is never sent plaintext (the MD5 is hashed again with SHA256
  over a per-session challenge; replay attacks are prevented).
- Multiple concurrent queries work; Telnet gets a single busy session.
- `show running-config` is 5-10x faster.

Still fundamentally HTTP (not HTTPS) — see `use_https` below. The default
Keenetic webconfig runs on port 80 without TLS. If webconfig is exposed
on 443 with a self-signed cert, pass `use_https=True` and `verify=False`
(or supply a pinned cert via `verify=<path>`).
"""
from __future__ import annotations

import http.cookiejar
import json
import ssl
import urllib.error
import urllib.request
from hashlib import md5, sha256
from typing import Any, Optional

from .constants import APP_NAME, APP_VERSION, MAX_HTTP_BYTES


class RCIAuthError(RuntimeError):
    """Raised when /auth handshake fails (wrong creds, missing realm, etc.)."""


class RCICommandError(RuntimeError):
    """Raised when a /rci/... call returns a non-2xx status."""


class RCIClient:
    """Minimal Keenetic RCI client built on the stdlib.

    Usage:
        with RCIClient('192.168.32.1') as rci:
            rci.login('admin', os.environ['ROUTER_PASS'])
            version = rci.get('show/version')
            iface = rci.get('show/interface/PPPoE0')

    The client keeps a single session cookie jar across calls and
    transparently re-authenticates on 401 (session expiry).
    """

    def __init__(self, host: str,
                 port: Optional[int] = None,
                 use_https: bool = False,
                 timeout: float = 8.0,
                 verify: bool | str = True):
        if port is None:
            port = 443 if use_https else 80
        scheme = 'https' if use_https else 'http'
        self.base = f'{scheme}://{host}:{port}'
        self.timeout = timeout
        self._cookies = http.cookiejar.CookieJar()
        ssl_ctx: Optional[ssl.SSLContext]
        if use_https:
            ssl_ctx = ssl.create_default_context()
            if verify is False:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            elif isinstance(verify, str):
                ssl_ctx.load_verify_locations(cafile=verify)
        else:
            ssl_ctx = None
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cookies),
            *([urllib.request.HTTPSHandler(context=ssl_ctx)] if ssl_ctx else []),
        )
        self._authed = False
        self._user: Optional[str] = None
        self._password: Optional[str] = None

    # ── Context manager ──────────────────────────────────────────────────
    def __enter__(self) -> 'RCIClient':
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        # Cookie jar is discarded; server session will expire on its own.
        self._cookies.clear()
        self._authed = False

    # ── HTTP plumbing ────────────────────────────────────────────────────
    def _request(self, method: str, path: str,
                 body: Optional[dict] = None,
                 extra_headers: Optional[dict] = None) -> tuple[int, dict, bytes]:
        url = f'{self.base}/{path.lstrip("/")}'
        headers = {
            'User-Agent': f'{APP_NAME}/{APP_VERSION}',
            'Accept': 'application/json',
        }
        if extra_headers:
            headers.update(extra_headers)
        data: Optional[bytes] = None
        if body is not None:
            data = json.dumps(body).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(MAX_HTTP_BYTES + 1)
                if len(raw) > MAX_HTTP_BYTES:
                    raise RCICommandError(f'response body exceeds {MAX_HTTP_BYTES} bytes: {path}')
                return resp.status, dict(resp.headers), raw
        except urllib.error.HTTPError as e:
            raw = e.read() if hasattr(e, 'read') else b''
            return e.code, dict(e.headers or {}), raw

    # ── Authentication ───────────────────────────────────────────────────
    def login(self, user: str, password: str) -> None:
        """Perform the NDMS challenge-response handshake.

        Raises RCIAuthError on failure. Credentials are remembered so that
        a subsequent 401 (session expiry) can be re-handshaked transparently.
        """
        self._user = user
        self._password = password
        self._authed = False
        self._do_auth_flow()

    def _do_auth_flow(self) -> None:
        if self._user is None or self._password is None:
            raise RCIAuthError('call login() first')

        status, headers, _ = self._request('GET', '/auth')
        if status == 200:
            # Already authenticated (shouldn't happen on first login).
            self._authed = True
            return

        realm = headers.get('X-NDM-Realm', '')
        challenge = headers.get('X-NDM-Challenge', '')
        if not realm or not challenge:
            raise RCIAuthError(
                f'/auth returned {status} without X-NDM-Realm/X-NDM-Challenge; '
                f'either the router lacks the http-proxy component or the '
                f'endpoint is disabled'
            )

        md5_hex = md5(f'{self._user}:{realm}:{self._password}'.encode()).hexdigest()
        sha_hex = sha256(f'{challenge}{md5_hex}'.encode()).hexdigest()

        status, _, body = self._request(
            'POST', '/auth',
            body={'login': self._user, 'password': sha_hex},
        )
        if status != 200:
            snippet = body[:120].decode('utf-8', 'replace') if body else ''
            raise RCIAuthError(f'/auth POST rejected (HTTP {status}): {snippet}')
        self._authed = True

    # ── Command invocation ───────────────────────────────────────────────
    def get(self, rci_path: str) -> Any:
        """GET /rci/<path>. Returns parsed JSON (dict/list) or None on 404.

        `rci_path` is CLI-style, e.g. 'show/version' or 'show/interface/PPPoE0'.
        """
        if not self._authed:
            self._do_auth_flow()
        path = 'rci/' + rci_path.strip('/').replace(' ', '/')
        status, _, body = self._request('GET', path)
        if status == 401:
            # Session expired; one-shot reauth + retry.
            self._authed = False
            self._do_auth_flow()
            status, _, body = self._request('GET', path)
        if status == 404:
            return None
        if status != 200:
            raise RCICommandError(f'GET {path} → HTTP {status}')
        try:
            return json.loads(body.decode('utf-8', 'replace'))
        except json.JSONDecodeError as e:
            raise RCICommandError(f'invalid JSON from {path}: {e}') from e

    def post(self, rci_path: str, body: dict) -> Any:
        """POST /rci/<path> with a JSON body. Returns parsed response JSON
        or None on 404. Used for mutating operations."""
        if not self._authed:
            self._do_auth_flow()
        path = 'rci/' + rci_path.strip('/').replace(' ', '/')
        status, _, raw = self._request('POST', path, body=body)
        if status == 401:
            self._authed = False
            self._do_auth_flow()
            status, _, raw = self._request('POST', path, body=body)
        if status == 404:
            return None
        if status != 200:
            snippet = raw[:200].decode('utf-8', 'replace') if raw else ''
            raise RCICommandError(f'POST {path} → HTTP {status}: {snippet}')
        try:
            return json.loads(raw.decode('utf-8', 'replace'))
        except json.JSONDecodeError:
            # Some endpoints return an empty body on success.
            return None

    # ── Convenience wrappers (read-only; high-value use cases) ───────────
    def show_version(self) -> dict:
        """Firmware version + installed components (flat dict)."""
        return self.get('show/version') or {}

    def show_interfaces(self) -> list[dict]:
        """List of all interface dicts."""
        data = self.get('show/interface') or {}
        if isinstance(data, dict):
            return [dict(v, name=k) for k, v in data.items()]
        if isinstance(data, list):
            return data
        return []

    def show_interface(self, name: str) -> dict:
        """Single interface status dict, or {} on 404."""
        return self.get(f'show/interface/{name}') or {}

    def show_running_config(self) -> str:
        """Raw running-config text (RCI returns a 'message' field with the
        textual dump for this command)."""
        # NDMS 5.x exposes the text at either 'show/running-config' or as
        # part of 'show/configuration' depending on component set. Try both.
        for path in ('show/running-config', 'show/configuration'):
            data = self.get(path)
            if data is None:
                continue
            # Shape varies: sometimes {'message': '...'}, sometimes raw dict.
            if isinstance(data, dict):
                msg = data.get('message')
                if isinstance(msg, str):
                    return msg
                # Fall back to JSON text rendering if no 'message' field.
                return json.dumps(data, indent=2)
            if isinstance(data, str):
                return data
        return ''

    def show_system(self) -> dict:
        """System snapshot: uptime, cpuload, memory."""
        return self.get('show/system') or {}

    def available(self) -> bool:
        """Quick ping: does the router expose /auth at all? Doesn't require
        credentials. Useful for deciding RCI vs Telnet transport."""
        try:
            status, headers, _ = self._request('GET', '/auth')
        except (urllib.error.URLError, OSError):
            return False
        # 200 = already logged in; 401 with challenge headers = auth available.
        return status in (200, 401) and (
            status == 200 or 'X-NDM-Challenge' in headers
        )
