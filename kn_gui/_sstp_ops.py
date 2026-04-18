"""Transport-agnostic SSTP interface provisioning.

Parallel to ``kn_gui._fqdn_group_ops``: one implementation, used by
both the Telnet (``client.KeeneticClient``) and RCI
(``rci_transport.KeeneticRCIClient``) transports.

Exposed helpers:

    create_sstp_interface(name, peer, user, password, description,
                           auto_connect, run_expect, run) -> list[str]
    find_free_sstp_index(existing) -> int

Both transports pass their bound ``run_expect`` / ``run`` method refs;
all CLI / description / ``ip global`` logic lives here.
"""
from __future__ import annotations

import re
from typing import Callable

from .constants import MANAGED_INTERFACE_TAG, MANAGED_VPN_IP_GLOBAL_PRIORITY


def _sanitize_cli_value(s: str) -> str:
    """Mirror of the transport-local helper: strip newlines/CR/NUL so a
    value can't smuggle a second CLI command through /rci/parse or
    Telnet."""
    return s.replace('\n', ' ').replace('\r', '').replace('\x00', '')


def find_free_sstp_index(existing: list[str]) -> int:
    """Return the next unused N for ``SSTP<N>``, starting at 1.

    Scans a list of already-present interface names for ``SSTP\\d+`` and
    returns the smallest positive integer not taken. Useful before
    ``create_sstp_interface`` so we don't clash with user-made SSTPs.
    """
    taken: set[int] = set()
    for name in existing:
        m = re.match(r'SSTP(\d+)$', name)
        if m:
            taken.add(int(m.group(1)))
    n = 1
    while n in taken:
        n += 1
    return n


def create_sstp_interface(name: str, peer: str, user: str, password: str,
                           description: str,
                           auto_connect: bool,
                           run_expect: Callable[..., str],
                           run: Callable[..., tuple[str, bool]],
                           ) -> list[str]:
    """Provision a fresh SSTP VPN-client interface. Idempotent: if a slot
    with the same name already exists, its peer/auth/flags get reset so
    we don't inherit stale params.

    The ``description`` is prefixed with ``MANAGED_INTERFACE_TAG`` so the
    app can later recognise which interfaces it owns (for "Delete
    managed VPN"), and ``ip global`` is set so the router will actually
    use this interface for policy routing — without it the interface
    exists but ``dns-proxy route`` rules pointing at it silently do
    nothing.

    Returns a list of error strings. Empty means everything went through;
    non-empty still means the interface may have been created partially
    — caller should display them to the user.
    """
    errs: list[str] = []

    def try_(cmd: str, critical: bool = False):
        try:
            run_expect(cmd)
        except RuntimeError as e:
            if critical:
                errs.append(str(e))
            # Non-critical commands (`no ...` resets) can fail when the
            # field wasn't set in the first place; that's fine.

    tagged = (f'{MANAGED_INTERFACE_TAG} {description}'.strip()
              if description else MANAGED_INTERFACE_TAG)

    try:
        run_expect(f'interface {name}')
        # Reset any prior state so re-creation doesn't inherit stale values.
        try_('no peer')
        try_('no authentication identity')
        try_('no authentication password')
        try_('no description')
        safe_desc = _sanitize_cli_value(tagged).replace('"', '').strip()
        if safe_desc:
            try_(f'description "{safe_desc}"', critical=True)
        try_(f'peer {_sanitize_cli_value(peer)}',                    critical=True)
        try_(f'authentication identity {_sanitize_cli_value(user)}', critical=True)
        try_(f'authentication password {_sanitize_cli_value(password)}',
             critical=True)
        try_('no ccp')
        try_('ip mtu 1400')
        try_('ip tcp adjust-mss pmtu')
        try_('security-level public')
        try_('ipcp default-route')
        try_('ipcp dns-routes')
        try_('ipcp address')
        # `ip global <N>` = the "Use for internet access" checkbox in the
        # web UI. Without it, dns-proxy rules silently route nothing.
        try_(f'ip global {MANAGED_VPN_IP_GLOBAL_PRIORITY}')
        if auto_connect:
            try_('connect')
            try_('up')
    finally:
        run('exit')
    return errs
