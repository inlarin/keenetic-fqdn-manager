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


def _join_message(msg) -> str:
    """Normalise a 'message' field that may be a string or list of strings.

    Keenetic NDMS (at least on Netcraze OEM builds) returns the running-config
    as ``{"message": ["line1", "line2", ...]}`` — a list, not a single string.
    This helper converts both variants to a single newline-joined string.
    """
    if isinstance(msg, str):
        return msg
    if isinstance(msg, list):
        return '\n'.join(str(s) for s in msg if s is not None)
    return ''


def _config_from_json(data: dict) -> str:
    """Convert the JSON tree returned by GET /rci/show/running-config into
    the minimal CLI-text stanzas that ``parse_running_config()`` understands.

    The JSON structure varies slightly across NDMS versions; the parser is
    intentionally defensive — unknown shapes are silently skipped.
    """
    lines: list[str] = []

    # ── FQDN object groups ────────────────────────────────────────────────
    og = data.get('object-group') or {}
    fqdn_groups = og.get('fqdn', {}) if isinstance(og, dict) else {}
    if isinstance(fqdn_groups, dict):
        for name, grp in fqdn_groups.items():
            lines.append(f'object-group fqdn {name}')
            inc = (grp or {}).get('include') if isinstance(grp, dict) else None
            if isinstance(inc, dict):
                # NDMS 4.x: {'host': [{'name': 'domain'}, ...]}
                for h in (inc.get('host') or []):
                    host = (h.get('name') or h.get('host', '')) if isinstance(h, dict) else str(h)
                    if host:
                        lines.append(f' include {host}')
            elif isinstance(inc, list):
                # Alternative: [{'host': 'domain'}, ...] or ['domain', ...]
                for h in inc:
                    host = (h.get('host') or h.get('name', '')) if isinstance(h, dict) else str(h)
                    if host:
                        lines.append(f' include {host}')
            lines.append('!')

    # ── DNS-proxy routes ──────────────────────────────────────────────────
    dp = data.get('dns-proxy') or {}
    if isinstance(dp, dict):
        route = dp.get('route')
        if route is not None:
            lines.append('dns-proxy')
            routes = route if isinstance(route, list) else [route]
            for r in routes:
                if not isinstance(r, dict):
                    continue
                grp   = r.get('object-group', '')
                iface = r.get('interface', '')
                auto   = ' auto'   if (r.get('auto')   or 'auto'   in r) else ''
                reject = ' reject' if (r.get('reject') or 'reject' in r) else ''
                if grp and iface:
                    lines.append(f' route object-group {grp} {iface}{auto}{reject}')
            lines.append('!')

    # ── IP static routes ──────────────────────────────────────────────────
    ip_sec = data.get('ip') or {}
    if isinstance(ip_sec, dict):
        routes = ip_sec.get('route') or []
        if isinstance(routes, dict):
            routes = [routes]
        for r in routes:
            if not isinstance(r, dict):
                continue
            net    = r.get('address') or r.get('network', '')
            mask   = r.get('mask')    or r.get('netmask', '')
            iface  = r.get('interface') or r.get('gateway', '')
            auto   = ' auto'   if (r.get('auto')   or 'auto'   in r) else ''
            reject = ' reject' if (r.get('reject') or 'reject' in r) else ''
            if net and mask and iface:
                lines.append(f'ip route {net} {mask} {iface}{auto}{reject}')

    return '\n'.join(lines)


def _extract_parse_text(resp) -> str:
    """Pull CLI text out of a ``/rci/parse`` response.

    Handles two known response shapes:

    **NDMS 5.x (standard)**::

        {"parse": "show running-config", "prompt": "(config)>",
         "status": [{"message": "line 1", "code": 0}, ...]}

    **Netcraze / some OEM builds**::

        {"message": ["line 1", "line 2", ...], "prompt": "(config)"}

    Returns a single newline-joined string, or '' if nothing useful found.
    """
    if not isinstance(resp, dict):
        return ''

    # Shape A: top-level 'message' is a string or list of lines.
    top_msg = _join_message(resp.get('message'))
    if top_msg:
        return top_msg

    # Shape B: standard status[*].message list.
    chunks: list[str] = []
    for item in resp.get('status', []) or []:
        if isinstance(item, dict):
            msg = item.get('message') or item.get('text') or ''
            if msg:
                chunks.append(str(msg))
    if chunks:
        return '\n'.join(chunks)

    # Shape C: some firmware versions echo the command in 'parse'.
    parse_echo = resp.get('parse')
    if isinstance(parse_echo, str) and parse_echo.strip():
        return parse_echo

    return ''


def _looks_like_cli_text(text: str) -> bool:
    """Heuristic: does `text` look like a Keenetic CLI dump?

    A structured JSON blob (dict → JSON) would start with `{` or `[`;
    anything else — `!` comments, `interface …` stanzas, raw output —
    is treated as CLI text. Non-empty required.
    """
    if not text or not text.strip():
        return False
    head = text.strip()[:2]
    return not head.startswith(('{', '['))


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

    # ── CLI-through-HTTP: /rci/parse ────────────────────────────────────

    def parse(self, cli_command: str) -> dict:
        """Execute an arbitrary CLI command via POST /rci/parse.

        This is the universal write-path: every CLI command works here,
        including context-sensitive ones (object-group → include → exit).
        The router maintains a per-session CLI context just like Telnet.

        Returns the parsed JSON response, typically:
            {"parse": "<echoed command>", "prompt": "(config)>", "status": [...]}

        `status` is a list of result objects; an empty list or list of
        dicts without 'error' keys means success.
        """
        if not self._authed:
            self._do_auth_flow()
        # /rci/parse expects the command as a bare JSON string.
        data = json.dumps(cli_command).encode('utf-8')
        headers = {
            'User-Agent': f'{APP_NAME}/{APP_VERSION}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        req = urllib.request.Request(
            f'{self.base}/rci/parse', data=data, method='POST', headers=headers)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(MAX_HTTP_BYTES + 1)
                if len(raw) > MAX_HTTP_BYTES:
                    raise RCICommandError('parse response too large')
                return json.loads(raw.decode('utf-8', 'replace'))
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self._authed = False
                self._do_auth_flow()
                # Retry once after re-auth.
                with self._opener.open(req, timeout=self.timeout) as resp:
                    raw = resp.read(MAX_HTTP_BYTES + 1)
                    return json.loads(raw.decode('utf-8', 'replace'))
            raise RCICommandError(f'parse {cli_command!r}: HTTP {e.code}') from e

    def parse_batch(self, commands: list[str]) -> list[dict]:
        """Execute multiple CLI commands sequentially via /rci/parse.

        Returns a list of parse-responses, one per command. Maintains
        CLI context across the batch (so object-group → include → exit
        works as expected).
        """
        results: list[dict] = []
        for cmd in commands:
            results.append(self.parse(cmd))
        return results

    def batch(self, json_body: list[dict]) -> Any:
        """POST /rci/ with a JSON array (native batch).

        Each element maps to a CLI command tree. The router processes
        them top-to-bottom. Use this for well-documented operations
        (ip route, system config save, delete with "no": true).
        Falls back to parse() for operations with unknown JSON mapping.
        """
        return self.post('', json_body)

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
        """Running-config as CLI text (or synthetic equivalent).

        Three-stage strategy:
        1. GET /rci/show/running-config or /rci/show/configuration — fast
           path; works when firmware returns a plain-text blob.
        2. POST /rci/parse "show running-config" — CLI-through-HTTP; works
           on most NDMS 5.x builds that populate status[*].message.
        3. Convert the JSON tree from step 1 to synthetic CLI text — handles
           NDMS versions that only expose a structured JSON object.

        Returns '' only when all three stages fail (caller should treat this
        as "config temporarily unavailable" rather than a fatal error).
        """
        import logging
        _log = logging.getLogger(__name__)

        # 1. Try native GET endpoints — fast when they yield a text blob.
        _first_json: dict | None = None
        for path in ('show/running-config', 'show/configuration'):
            try:
                data = self.get(path)
            except Exception as exc:
                _log.debug('show_running_config GET %s failed: %s', path, exc)
                continue
            if data is None:
                _log.debug('show_running_config GET %s → 404', path)
                continue
            if isinstance(data, str) and _looks_like_cli_text(data):
                _log.debug('show_running_config GET %s → CLI text (%d chars)', path, len(data))
                return data
            if isinstance(data, dict):
                _log.debug('show_running_config GET %s → JSON dict, keys=%s',
                           path, list(data.keys())[:8])
                if _first_json is None:
                    _first_json = data
                msg = data.get('message')
                # message can be a plain string OR a list of CLI lines.
                text = _join_message(msg)
                if text and _looks_like_cli_text(text):
                    _log.debug('show_running_config GET %s → .message text (%d chars)',
                               path, len(text))
                    return text
            else:
                _log.debug('show_running_config GET %s → unexpected type %s',
                           path, type(data).__name__)

        # 2. POST /rci/parse — CLI-through-HTTP.
        try:
            resp = self.parse('show running-config')
            text = _extract_parse_text(resp)
            if text:
                _log.debug('show_running_config parse → %d chars', len(text))
                return text
            _log.debug('show_running_config parse → empty (resp keys=%s)',
                       list(resp.keys()) if isinstance(resp, dict) else type(resp).__name__)
        except Exception as exc:
            _log.debug('show_running_config parse failed: %s', exc)

        # 3. JSON-tree → synthetic CLI text.
        if _first_json:
            text = _config_from_json(_first_json)
            _log.debug('show_running_config JSON→CLI: %d chars, groups=%s',
                       len(text),
                       list((_first_json.get('object-group') or {}).get('fqdn', {}).keys()))
            return text

        _log.warning('show_running_config: all strategies failed, returning empty')
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
