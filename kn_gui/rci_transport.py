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

    def run_expect(self, cmd: str, timeout: float = 10.0) -> str:
        """Execute cmd and raise on error. Same semantics as Telnet version."""
        text, ok = self.run(cmd, timeout=timeout)
        if not ok:
            raise RuntimeError(f'no response after: {cmd}')
        if is_error_output(text):
            last = text.strip().splitlines()[-1] if text.strip() else ''
            raise RuntimeError(f'command {cmd!r} failed: {last[:200]}')
        return text

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

    def create_fqdn_group(self, name: str, entries: list[str],
                          description: str = '') -> tuple[list[str], list[str]]:
        """Create FQDN group(s) via /rci/parse. Same API as Telnet version."""
        errs: list[str] = []
        created: list[str] = []

        name_err = validate_group_name(name)
        if name_err:
            errs.append(f'group name: {name_err}')
            return created, errs

        valid, warnings, invalid = validate_fqdns(entries)
        errs.extend(warnings)
        errs.extend(invalid)

        if not valid:
            errs.append('no valid entries to include')
            return created, errs

        # Split into chunks.
        chunks: list[tuple[str, list[str]]] = []
        if len(valid) <= MAX_ENTRIES_PER_GROUP:
            chunks.append((name, valid))
        else:
            for i in range(0, len(valid), MAX_ENTRIES_PER_GROUP):
                chunk = valid[i:i + MAX_ENTRIES_PER_GROUP]
                suffix = '' if i == 0 else f'_{i // MAX_ENTRIES_PER_GROUP + 1}'
                chunk_name = f'{name}{suffix}'
                if validate_group_name(chunk_name):
                    max_base = 32 - len(suffix)
                    chunk_name = f'{name[:max_base]}{suffix}'
                chunks.append((chunk_name, chunk))
            if len(chunks) > 1:
                errs.append(
                    f'split {len(valid)} entries into {len(chunks)} groups '
                    f'(Keenetic limit ~{MAX_ENTRIES_PER_GROUP}/group): '
                    + ', '.join(f'{n}({len(e)})' for n, e in chunks))

        for chunk_name, chunk_entries in chunks:
            try:
                self.run_expect(f'object-group fqdn {chunk_name}')
                if description:
                    safe = _sanitize_cli_value(description).replace('"', '').strip()
                    if safe:
                        try:
                            self.run_expect(f'description "{safe}"')
                        except RuntimeError as e:
                            errs.append(f'{chunk_name} description: {e}')
                for entry in chunk_entries:
                    try:
                        self.run_expect(f'include {entry}')
                    except RuntimeError as e:
                        errs.append(f'include {entry}: {e}')
                created.append(chunk_name)
            finally:
                self.run('exit')
        return created, errs

    def bind_fqdn_route(self, group: str, interface: str, auto: bool = True,
                        reject: bool = False) -> str:
        parts = [f'dns-proxy route object-group {group} {interface}']
        if auto:
            parts.append('auto')
        if reject:
            parts.append('reject')
        return self.run_expect(' '.join(parts))

    def delete_fqdn_group(self, name: str) -> None:
        """Delete group + speculatively remove auto-split siblings up to _50."""
        self.run(f'no dns-proxy route object-group {name}')
        self.run(f'no object-group fqdn {name}')
        for i in range(2, 51):
            sib = f'{name}_{i}'
            self.run(f'no dns-proxy route object-group {sib}')
            self.run(f'no object-group fqdn {sib}')

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

    # ── SSTP interface provisioning ───────────────────────────────────────

    def find_free_sstp_index(self, existing: list[str]) -> int:
        taken: set[int] = set()
        for name in existing:
            m = re.match(r'SSTP(\d+)$', name)
            if m:
                taken.add(int(m.group(1)))
        n = 1
        while n in taken:
            n += 1
        return n

    def create_sstp_interface(self, name: str, peer: str, user: str,
                               password: str, description: str = '',
                               auto_connect: bool = True) -> list[str]:
        from .constants import (MANAGED_INTERFACE_TAG,
                                 MANAGED_VPN_IP_GLOBAL_PRIORITY)

        errs: list[str] = []

        def try_(cmd: str, critical: bool = False):
            try:
                self.run_expect(cmd)
            except RuntimeError as e:
                if critical:
                    errs.append(str(e))

        # Prefix every managed interface description with a short tag so
        # we can tell apart interfaces we created from user-made ones.
        if description:
            tagged = f'{MANAGED_INTERFACE_TAG} {description}'.strip()
        else:
            tagged = MANAGED_INTERFACE_TAG

        try:
            self.run_expect(f'interface {name}')
            try_('no peer')
            try_('no authentication identity')
            try_('no authentication password')
            try_('no description')
            safe_desc = _sanitize_cli_value(tagged).replace('"', '').strip()
            if safe_desc:
                try_(f'description "{safe_desc}"', critical=True)
            try_(f'peer {_sanitize_cli_value(peer)}', critical=True)
            try_(f'authentication identity {_sanitize_cli_value(user)}', critical=True)
            try_(f'authentication password {_sanitize_cli_value(password)}', critical=True)
            try_('no ccp')
            try_('ip mtu 1400')
            try_('ip tcp adjust-mss pmtu')
            try_('security-level public')
            try_('ipcp default-route')
            try_('ipcp dns-routes')
            try_('ipcp address')
            # `ip global <N>` — Keenetic web-UI calls this checkbox
            # "Использовать для выхода в интернет". Without it the
            # interface exists but is not eligible for policy routing,
            # so dns-proxy rules pointing at this interface silently do
            # nothing. That was the "ничего не работает" symptom.
            try_(f'ip global {MANAGED_VPN_IP_GLOBAL_PRIORITY}')
            if auto_connect:
                try_('connect')
                try_('up')
        finally:
            self.run('exit')
        return errs

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
