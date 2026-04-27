"""RCI-based transport: drop-in replacement for KeeneticClient (Telnet).

Uses `/rci/parse` for write commands (1:1 CLI equivalent) and native
`/rci/show/*` GET endpoints for reads (faster, JSON-native). The public
API mirrors `KeeneticClient` exactly so `app.py` can swap transports
without changing any call sites.

Advantages over Telnet:
- Password never sent in plaintext (challenge-response auth).
- No "Telnet busy" — multiple concurrent sessions OK.
- `show running-config` is 5-10x faster.
- No ANSI escape parsing, no prompt detection.

Limitation:
- `show log` returns 404 via RCI (no mapping in NDMS). The syslog
  listener (`pppoe/syslog_listener.py`) is the recommended alternative.
  If `show log` is needed, keep a Telnet fallback.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .cli_safety import (IFACE_TYPES, parse_interfaces_text,
                          sanitize_cli_value as _sanitize_cli_value)
from .rci_client import RCIAuthError, RCIClient, RCICommandError
from .utils import (MAX_ENTRIES_PER_GROUP, is_error_output,
                    validate_fqdns, validate_group_name)


# Kept as a module-level alias for legacy code paths / tests that
# reference the old helper name by full qualified path.
_parse_interfaces_text = parse_interfaces_text


class KeeneticRCIClient:
    """RCI-based Keenetic client with the same public API as KeeneticClient.

    Usage:
        client = KeeneticRCIClient('192.168.32.1')
        client.login('admin', os.environ['ROUTER_PASS'])
        cfg = client.running_config()
        client.create_fqdn_group('telegram', ['t.me', 'telegram.org'])
        client.close()
    """

    # Class alias to the module-wide tuple — existing code still uses
    # `self.IFACE_TYPES`, and the tuple is defined once in cli_safety.
    IFACE_TYPES = IFACE_TYPES

    def __init__(self, host: str, port: int = 80, use_https: bool = False):
        self.host = host
        self.port = port
        self.connected = False
        self.router_info: dict = {}
        self._rci = RCIClient(host, port=port, use_https=use_https)

    # ── Auth + lifecycle ──────────────────────────────────────────────────

    def login(self, user: str, password: str, timeout: float = 8.0) -> None:
        """Authenticate via RCI challenge-response."""
        self._rci.timeout = timeout
        try:
            self._rci.login(user, password)
        except RCIAuthError as e:
            raise PermissionError(f'Login failed: {e}') from e
        self.connected = True
        # Populate router_info from show version.
        try:
            ver = self._rci.show_version()
            if ver:
                self.router_info['version'] = ver.get('release', '')
                self.router_info['vendor'] = ver.get('manufacturer', '')
                self.router_info['model'] = ver.get('model', '')
                self.router_info['hw_id'] = ver.get('hw_id', '')
                # Components: may be a list of dicts or a comma-separated string.
                comps = ver.get('components', [])
                if isinstance(comps, list):
                    names = set()
                    for c in comps:
                        if isinstance(c, dict):
                            names.add(c.get('name', ''))
                        elif isinstance(c, str):
                            names.add(c)
                    self.router_info['components'] = names
                elif isinstance(comps, str):
                    self.router_info['components'] = {
                        c.strip() for c in comps.split(',') if c.strip()}
        except Exception:
            pass

    def close(self) -> None:
        self._rci.close()
        self.connected = False

    # ── Low-level command execution ──────────────────────────────────────

    def run(self, cmd: str, timeout: float = 10.0) -> tuple[str, bool]:
        """Execute cmd via /rci/parse. Returns (output_text, prompt_seen).

        Maps the RCI parse-response to the same shape that
        ``KeeneticClient.run()`` returns (text, prompt_seen). `prompt_seen`
        is the RCI equivalent of "the CLI replied and we saw a prompt"
        — used by ``run_expect`` to distinguish "command executed" from
        "nothing happened".

        Error detection: if the response carries a ``status[*].error``
        marker (Netcraze OEM convention), that text is surfaced in the
        returned string so ``is_error_output`` catches it downstream.
        """
        old_timeout = self._rci.timeout
        self._rci.timeout = timeout
        try:
            resp = self._rci.parse(cmd)
            text = ''
            ok = False
            if isinstance(resp, dict):
                status_items = resp.get('status', []) or []
                # Collect text from status entries, including `error`
                # fields so the downstream is_error_output can fire.
                chunks: list[str] = []
                for s in status_items:
                    if isinstance(s, dict):
                        msg = (s.get('message') or s.get('text')
                               or s.get('error') or '')
                        if msg:
                            chunks.append(str(msg))
                text = '\n'.join(chunks)
                if not text:
                    text = resp.get('parse', '') or ''
                prompt = resp.get('prompt', '')
                # Success requires SOME evidence the command ran:
                # either a prompt echo, or a non-empty status list, or
                # any text payload. An all-empty reply is treated as
                # failure so callers don't mistake silent no-ops for OK.
                ok = bool(prompt or status_items or text)
                return text, ok
            return str(resp), True
        except (RCICommandError, RCIAuthError) as e:
            return str(e), False
        finally:
            self._rci.timeout = old_timeout

    def run_expect(self, cmd: str, timeout: float = 10.0,
                   retries: int = 2) -> str:
        """Execute cmd and raise on error. Same semantics as Telnet version.

        ``retries`` controls how many extra attempts are made when the call
        comes back without a prompt — i.e. the transport timeout. NDM under
        contention (e.g. our Bridge2 watcher reading a fat running-config)
        occasionally drops a single response; one or two retries with a
        short backoff turn that into a normal latency spike instead of a
        partial apply. Retries are skipped for ``is_error_output`` because
        those are deterministic command-syntax failures."""
        last_err: Optional[Exception] = None
        for attempt in range(retries + 1):
            text, ok = self.run(cmd, timeout=timeout)
            if ok:
                if is_error_output(text):
                    last = text.strip().splitlines()[-1] if text.strip() else ''
                    raise RuntimeError(f'command {cmd!r} failed: {last[:200]}')
                return text
            last_err = RuntimeError(f'no response after: {cmd}')
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))  # 0.5s, then 1.0s
        raise last_err  # type: ignore[misc]

    # ── Introspection ─────────────────────────────────────────────────────

    def list_interfaces(self) -> list[dict]:
        """List router interfaces as dicts (same shape as Telnet version).

        Prefers the native `/rci/show/interface` JSON (fast) but falls
        back to parsing `show interface` text output if the JSON shape
        is unexpected — this keeps behaviour identical to the Telnet
        path and avoids surprises on firmware versions that format the
        JSON differently.
        """
        data = self._rci.show_interfaces()
        result: list[dict] = []
        for iface in data:
            itype = iface.get('type', '')
            if itype not in self.IFACE_TYPES:
                continue
            result.append({
                'name': iface.get('name', '') or iface.get('interface-name', ''),
                'type': itype,
                'description': iface.get('description', ''),
                'link': iface.get('link', ''),
                'connected': iface.get('connected', ''),
            })
        if result:
            return result
        # Fallback: parse-based. Same parser as Telnet used.
        text, _ = self.run('show interface', timeout=15.0)
        return _parse_interfaces_text(text)

    def running_config(self) -> str:
        """Return running-config as CLI text, or '' if unavailable.

        Uses a 20 s timeout (matching the Telnet path) to give slower
        routers enough headroom.  Does NOT raise — an empty return means
        "config temporarily unavailable"; the caller should proceed with
        empty state and surface a warning to the user.
        """
        old_timeout = self._rci.timeout
        self._rci.timeout = 20.0
        try:
            return self._rci.show_running_config()
        except Exception:
            return ''
        finally:
            self._rci.timeout = old_timeout

    def get_components(self) -> set[str]:
        return self.router_info.get('components', set())

    def get_interface_status(self, name: str) -> dict:
        data = self._rci.show_interface(name)
        if data:
            return {
                'name': data.get('name', name),
                'type': data.get('type', ''),
                'description': data.get('description', ''),
                'link': data.get('link', ''),
                'connected': data.get('connected', ''),
            }
        return {}

    # ── FQDN object-group + dns-proxy route ───────────────────────────────
    # All FQDN group ops delegate to the transport-agnostic helper in
    # kn_gui._fqdn_group_ops so there's one place to evolve behaviour
    # (validation, auto-split, tagging). Previously each transport
    # duplicated ~70 lines of identical logic.

    def create_fqdn_group(self, name: str, entries: list[str],
                          description: str = '') -> tuple[list[str], list[str]]:
        from . import _fqdn_group_ops
        return _fqdn_group_ops.create_fqdn_group(
            name, entries, description,
            run_expect=self.run_expect, run=self.run)

    def bind_fqdn_route(self, group: str, interface: str, auto: bool = True,
                        reject: bool = False) -> str:
        parts = [f'dns-proxy route object-group {group} {interface}']
        if auto:
            parts.append('auto')
        if reject:
            parts.append('reject')
        return self.run_expect(' '.join(parts))

    def delete_fqdn_group(self, name: str) -> None:
        from . import _fqdn_group_ops
        _fqdn_group_ops.delete_fqdn_group(name, run=self.run)

    def add_ip_route(self, network: str, mask: str, interface: str,
                     auto: bool = True, reject: bool = False) -> str:
        parts = [f'ip route {network} {mask} {interface}']
        if auto:
            parts.append('auto')
        if reject:
            parts.append('reject')
        return self.run_expect(' '.join(parts))

    def delete_ip_route(self, network: str, mask: str, interface: str) -> None:
        self.run(f'no ip route {network} {mask} {interface}')

    def save_config(self) -> str:
        return self.run_expect('system configuration save', timeout=15.0)

    def list_managed_fqdn_groups(self) -> list[dict]:
        from . import _fqdn_group_ops
        return _fqdn_group_ops.list_managed_fqdn_groups(self.running_config)

    # ── SSTP interface provisioning ───────────────────────────────────────
    # Both methods delegate to kn_gui._sstp_ops so there's one place to
    # evolve the description-tagging / ip-global / auth flow. Parallel
    # to the _fqdn_group_ops split that happened in v3.4.1.

    def find_free_sstp_index(self, existing: list[str]) -> int:
        from . import _sstp_ops
        return _sstp_ops.find_free_sstp_index(existing)

    def create_sstp_interface(self, name: str, peer: str, user: str,
                               password: str, description: str = '',
                               auto_connect: bool = True) -> list[str]:
        from . import _sstp_ops
        return _sstp_ops.create_sstp_interface(
            name, peer, user, password, description, auto_connect,
            run_expect=self.run_expect, run=self.run)

    def delete_interface(self, name: str) -> None:
        self.run(f'no interface {name}')

    def list_managed_interfaces(self) -> list[dict]:
        """Return interfaces whose description starts with our tag.

        Used by the UI to let the user remove VPN interfaces this app
        created without touching ones they configured themselves.
        """
        from .constants import MANAGED_INTERFACE_TAG
        out: list[dict] = []
        for iface in self.list_interfaces():
            desc = (iface.get('description') or '')
            if MANAGED_INTERFACE_TAG in desc:
                out.append(iface)
        return out
