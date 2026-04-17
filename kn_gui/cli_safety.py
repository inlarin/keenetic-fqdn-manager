"""Helpers for safely passing user-controlled values into Keenetic CLI.

Consolidated from `client.py` and `rci_transport.py`, which each had a
private copy with identical semantics.  New callsites should import
from here.
"""
from __future__ import annotations


def sanitize_cli_value(s: str) -> str:
    """Strip characters that could break a CLI command on either
    transport (Telnet pipe or ``/rci/parse`` body).

    Newlines are the critical ones: a stray ``\\n`` in a description /
    peer / password field would split a single command in two, making
    the tail run as a separate CLI instruction — a classic injection
    vector when the data comes from an imported catalog URL.

    Null bytes (``\\x00``) would terminate a C string inside the router
    parser; carriage returns behave like newlines on some firmwares.
    """
    return s.replace('\n', ' ').replace('\r', '').replace('\x00', '')


# Interface types that the app is interested in managing / listing.
# Anything not in this set is filtered out in ``list_interfaces``.
# Shared between the Telnet (`client.py`) and RCI (`rci_transport.py`)
# transports so adding a new type is a one-line change.
IFACE_TYPES: tuple[str, ...] = (
    'PPPoE', 'SSTP', 'L2TP', 'PPTP', 'Wireguard', 'OpenVPN',
    'ZeroTier', 'GigabitEthernet', 'Vlan', 'Ipoe', 'Ipip', 'Gre',
)


def parse_interfaces_text(text: str,
                          allowed_types: tuple[str, ...] = IFACE_TYPES
                          ) -> list[dict]:
    """Parse ``show interface`` CLI output into a list of dicts.

    One parser for both transports — the Telnet client reads native CLI
    text, the RCI transport falls back to CLI text when the native JSON
    shape is unexpected (OEM firmware quirks).
    """
    ifaces: list[dict] = []
    current: dict = {}
    for line in text.splitlines():
        s = line.strip()
        if s.startswith('interface-name:'):
            if current.get('name'):
                ifaces.append(current)
            current = {'name': s.split(':', 1)[1].strip()}
        elif s.startswith('type:'):
            current['type'] = s.split(':', 1)[1].strip()
        elif s.startswith('description:'):
            current['description'] = s.split(':', 1)[1].strip()
        elif s.startswith('link:'):
            current['link'] = s.split(':', 1)[1].strip()
        elif s.startswith('connected:'):
            current['connected'] = s.split(':', 1)[1].strip()
    if current.get('name'):
        ifaces.append(current)
    return [i for i in ifaces if i.get('type') in allowed_types]
