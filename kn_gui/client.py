"""Telnet client for Keenetic / NDMS 5.x routers.

The run() method now returns (text, matched_prompt): if the config prompt
wasn't seen before the timeout, callers can detect a silent failure instead
of treating a partial buffer as successful output.

create_sstp_interface resets any previously-bound peer/auth fields so that
re-creating an existing interface slot doesn't inherit stale parameters."""
from __future__ import annotations

import re
import socket
import time
from typing import Optional

from .constants import DEFAULT_TELNET_PORT
from .utils import (MAX_ENTRIES_PER_GROUP, is_error_output, strip_ansi,
                    validate_fqdns, validate_group_name)


class KeeneticClient:
    IAC = 0xff
    WILL, WONT, DO, DONT, SB, SE = 0xfb, 0xfc, 0xfd, 0xfe, 0xfa, 0xf0
    CONFIG_PROMPT = r'\(config(-[a-z-]+)?\)>\s*$'

    def __init__(self, host: str, port: int = DEFAULT_TELNET_PORT):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.connected = False
        self.router_info: dict = {}

    # ── Low-level telnet ──────────────────────────────────────────────────
    def _negotiate(self, buf: bytes) -> bytes:
        out = bytearray()
        resp = bytearray()
        i = 0
        while i < len(buf):
            b = buf[i]
            if b == self.IAC and i + 1 < len(buf):
                cmd = buf[i + 1]
                if cmd in (self.WILL, self.WONT, self.DO, self.DONT) and i + 2 < len(buf):
                    opt = buf[i + 2]
                    rc = self.DONT if cmd == self.WILL else self.WONT if cmd == self.DO else None
                    if rc is not None:
                        resp += bytes([self.IAC, rc, opt])
                    i += 3
                    continue
                elif cmd == self.SB:
                    j = i + 2
                    while j < len(buf) - 1 and not (buf[j] == self.IAC and buf[j + 1] == self.SE):
                        j += 1
                    i = j + 2
                    continue
                else:
                    i += 2
                    continue
            out.append(b)
            i += 1
        if resp and self.sock is not None:
            self.sock.sendall(bytes(resp))
        return bytes(out)

    def _read_until_any(self, patterns: list[str], timeout: float = 8.0) -> tuple[str, int]:
        """Match regex against ANSI-stripped text.
        Returns (text_so_far, matched_index or -1)."""
        if self.sock is None:
            raise RuntimeError('KeeneticClient: socket is closed (call login() first)')
        self.sock.settimeout(0.3)
        buf = b''
        end = time.time() + timeout
        compiled = [re.compile(p) for p in patterns]

        def check() -> tuple[str, int]:
            txt = strip_ansi(buf.decode('utf-8', 'replace'))
            for i, rx in enumerate(compiled):
                if rx.search(txt):
                    return txt, i
            return txt, -1

        while time.time() < end:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buf += self._negotiate(chunk)
                txt, idx = check()
                if idx >= 0:
                    return txt, idx
            except socket.timeout:
                txt, idx = check()
                if idx >= 0:
                    return txt, idx
        return strip_ansi(buf.decode('utf-8', 'replace')), -1

    def _read_until(self, pattern: str, timeout: float = 8.0) -> str:
        text, _ = self._read_until_any([pattern], timeout)
        return text

    def _send(self, line: str) -> None:
        if self.sock is None:
            raise RuntimeError('KeeneticClient: socket is closed (call login() first)')
        self.sock.sendall((line + '\n').encode())

    # ── Auth + lifecycle ──────────────────────────────────────────────────
    def login(self, user: str, password: str, timeout: float = 8.0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect((self.host, self.port))
            banner1, idx = self._read_until_any([r'(?i)login\s*:'], timeout)
            if idx < 0:
                raise ConnectionError('Router did not send login prompt')
            self._send(user)
            _, idx = self._read_until_any([r'(?i)password\s*:'], timeout)
            if idx < 0:
                raise ConnectionError('Router did not ask for password')
            self._send(password)
            out, idx = self._read_until_any([
                self.CONFIG_PROMPT,                              # 0 success
                r'(?i)(fail|incorrect|invalid|locked|denied)',   # 1 auth error
                r'(?im)^\s*login\s*:\s*$',                       # 2 re-prompt
            ], timeout)
            if idx == 0:
                self.connected = True
                combined = (banner1 or '') + (out or '')
                m = re.search(r'NDMS version\s+(\S+?)[,\s]', combined)
                if m:
                    self.router_info['version'] = m.group(1)
                m = re.search(r'copyright.*?\d{4}\s+(.+?)\.', combined)
                if m:
                    self.router_info['vendor'] = m.group(1).strip()
            elif idx < 0:
                raise ConnectionError('Timeout waiting for login result')
            else:
                snippet = out.strip().splitlines()[-1] if out.strip() else ''
                raise PermissionError(f'Login failed: {snippet[:120] or "wrong credentials"}')
        except Exception:
            if self.sock is not None:
                try:
                    self.sock.close()
                except Exception:
                    pass
            self.sock = None
            self.connected = False
            raise

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.settimeout(2.0)
                self._send('exit')
                time.sleep(0.2)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self.connected = False

    # ── Commands ──────────────────────────────────────────────────────────
    def run(self, cmd: str, timeout: float = 10.0) -> tuple[str, bool]:
        """Execute cmd, return (output_text, prompt_seen).
        `prompt_seen` is False when the timeout elapsed without a prompt
        match — callers MUST treat the text as suspect in that case."""
        self._send(cmd)
        text, idx = self._read_until_any([self.CONFIG_PROMPT], timeout)
        return text, idx >= 0

    def run_expect(self, cmd: str, timeout: float = 10.0) -> str:
        """Execute cmd and raise if the prompt doesn't return or output
        contains an error marker. Used for interior operations where we
        truly can't tolerate silent failure."""
        text, ok = self.run(cmd, timeout=timeout)
        if not ok:
            raise RuntimeError(f'no prompt after: {cmd}')
        if is_error_output(text):
            last = text.strip().splitlines()[-1] if text.strip() else ''
            raise RuntimeError(f'command {cmd!r} failed: {last[:200]}')
        return text

    # ── Introspection ─────────────────────────────────────────────────────
    def list_interfaces(self) -> list[dict]:
        out, _ = self.run('show interface', timeout=15.0)
        ifaces: list[dict] = []
        current: dict = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('interface-name:'):
                if current.get('name'):
                    ifaces.append(current)
                current = {'name': line.split(':', 1)[1].strip()}
            elif line.startswith('type:'):
                current['type'] = line.split(':', 1)[1].strip()
            elif line.startswith('description:'):
                current['description'] = line.split(':', 1)[1].strip()
            elif line.startswith('link:'):
                current['link'] = line.split(':', 1)[1].strip()
            elif line.startswith('connected:'):
                current['connected'] = line.split(':', 1)[1].strip()
        if current.get('name'):
            ifaces.append(current)
        return [i for i in ifaces if i.get('type') in
                ('PPPoE', 'SSTP', 'L2TP', 'PPTP', 'Wireguard', 'OpenVPN',
                 'ZeroTier', 'GigabitEthernet', 'Vlan', 'Ipoe', 'Ipip', 'Gre')]

    def running_config(self) -> str:
        out, ok = self.run('show running-config', timeout=20.0)
        if not ok:
            raise RuntimeError('timeout reading running-config')
        return out

    def get_components(self) -> set[str]:
        """Parse `show version` to find installed firmware components.
        Result is a set of component names like {'sstp', 'wireguard', …}."""
        out, _ = self.run('show version', timeout=10.0)
        lines = out.splitlines()
        key_indent: Optional[int] = None
        parts: list[str] = []
        for ln in lines:
            if key_indent is None:
                m = re.match(r'^(\s*)components\s*:\s*(.*)$', ln)
                if m:
                    key_indent = len(m.group(1))
                    if m.group(2).strip():
                        parts.append(m.group(2))
                continue
            m2 = re.match(r'^(\s*)(\S.*)?$', ln)
            if not m2:
                break
            indent = len(m2.group(1))
            content = (m2.group(2) or '').strip()
            if not content:
                continue
            if indent > key_indent:
                parts.append(content)
            else:
                break
        raw = re.sub(r'\s+', '', ','.join(parts))
        return {c for c in raw.split(',') if c}

    def get_interface_status(self, name: str) -> dict:
        for iface in self.list_interfaces():
            if iface.get('name') == name:
                return iface
        return {}

    # ── FQDN object-group + dns-proxy route ───────────────────────────────
    def create_fqdn_group(self, name: str, entries: list[str],
                          description: str = '') -> list[str]:
        """Create (or update) an object-group fqdn and `include` each entry.

        Validation:
        - Group name is checked against Keenetic's 32-char regex.
        - Entries are normalized (wildcards stripped) and validated.
        - Invalid FQDNs are skipped (returned in errs).
        - If entries exceed MAX_ENTRIES_PER_GROUP (~300), the list is split
          into chunks and additional groups `<name>_2`, `<name>_3` are
          created automatically.

        Returns a list of warnings/errors (empty = all good).
        """
        errs: list[str] = []

        # ── Validate group name ────────────────────────────────────────
        name_err = validate_group_name(name)
        if name_err:
            errs.append(f'group name: {name_err}')
            return errs

        # ── Validate + normalize entries ───────────────────────────────
        valid, warnings, invalid = validate_fqdns(entries)
        errs.extend(warnings)
        errs.extend(invalid)

        if not valid:
            errs.append('no valid entries to include')
            return errs

        # ── Split into chunks ≤MAX_ENTRIES_PER_GROUP ───────────────────
        chunks: list[tuple[str, list[str]]] = []
        if len(valid) <= MAX_ENTRIES_PER_GROUP:
            chunks.append((name, valid))
        else:
            # name, name_2, name_3, ...
            for i in range(0, len(valid), MAX_ENTRIES_PER_GROUP):
                chunk = valid[i:i + MAX_ENTRIES_PER_GROUP]
                suffix = '' if i == 0 else f'_{i // MAX_ENTRIES_PER_GROUP + 1}'
                chunk_name = f'{name}{suffix}'
                # Validate derived name too (might exceed 32 chars)
                if validate_group_name(chunk_name):
                    # Name too long after suffix — truncate base
                    max_base = 32 - len(suffix)
                    chunk_name = f'{name[:max_base]}{suffix}'
                chunks.append((chunk_name, chunk))
            if len(chunks) > 1:
                errs.append(
                    f'split {len(valid)} entries into {len(chunks)} groups '
                    f'(Keenetic limit ~{MAX_ENTRIES_PER_GROUP}/group): '
                    + ', '.join(f'{n}({len(e)})' for n, e in chunks))

        # ── Push each chunk to the router ──────────────────────────────
        for chunk_name, chunk_entries in chunks:
            try:
                self.run_expect(f'object-group fqdn {chunk_name}')
                if description:
                    safe = description.replace('"', '').strip()
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
            finally:
                # Always leave the object-group context even on error.
                self.run('exit')
        return errs

    def bind_fqdn_route(self, group: str, interface: str, auto: bool = True,
                        reject: bool = False) -> str:
        parts = [f'dns-proxy route object-group {group} {interface}']
        if auto:   parts.append('auto')
        if reject: parts.append('reject')
        return self.run_expect(' '.join(parts))

    def delete_fqdn_group(self, name: str) -> None:
        # Removal of the route by the app is best-effort: deleting the group
        # itself will clean up the route regardless.
        self.run(f'no dns-proxy route object-group {name}')
        self.run(f'no object-group fqdn {name}')

    def add_ip_route(self, network: str, mask: str, interface: str,
                     auto: bool = True, reject: bool = False) -> str:
        parts = [f'ip route {network} {mask} {interface}']
        if auto:   parts.append('auto')
        if reject: parts.append('reject')
        return self.run_expect(' '.join(parts))

    def delete_ip_route(self, network: str, mask: str, interface: str) -> None:
        self.run(f'no ip route {network} {mask} {interface}')

    def save_config(self) -> str:
        return self.run_expect('system configuration save', timeout=15.0)

    # ── SSTP interface provisioning ───────────────────────────────────────
    def find_free_sstp_index(self, existing: list[str]) -> int:
        """Return the next unused N for SSTP<N>, starting at 1."""
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
        """Provision a fresh SSTP VPN-client interface. Idempotent: if a
        slot with the same name already exists, its peer/auth/flags get
        reset so we don't inherit stale params."""
        errs: list[str] = []

        def try_(cmd: str, critical: bool = False):
            try:
                self.run_expect(cmd)
            except RuntimeError as e:
                if critical:
                    errs.append(str(e))
                # Non-critical commands (`no ...` resets) can fail when the
                # field wasn't set in the first place; that's OK.

        try:
            self.run_expect(f'interface {name}')
            # Reset any prior state so re-creation doesn't inherit stale values
            try_('no peer')
            try_('no authentication identity')
            try_('no authentication password')
            try_('no description')
            if description:
                safe = description.replace('"', '').strip()
                if safe:
                    try_(f'description "{safe}"', critical=True)
            try_(f'peer {peer}',                           critical=True)
            try_(f'authentication identity {user}',        critical=True)
            try_(f'authentication password {password}',    critical=True)
            try_('no ccp')
            try_('ip mtu 1400')
            try_('ip tcp adjust-mss pmtu')
            try_('security-level public')
            try_('ipcp default-route')
            try_('ipcp dns-routes')
            try_('ipcp address')
            if auto_connect:
                try_('connect')
                try_('up')
        finally:
            self.run('exit')
        return errs

    def delete_interface(self, name: str) -> None:
        self.run(f'no interface {name}')
