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
    # VPN-style protocols — natural targets for selective FQDN routing.
    'PPPoE', 'SSTP', 'L2TP', 'PPTP', 'Wireguard', 'OpenVPN',
    # ZeroTier overlay net (zt0) — sometimes used as a route target.
    'ZeroTier',
    # `Bridge` covers NDM-managed bridge wrappers (e.g. Bridge2 plumbing an
    # Entware-side SoftEther TAP into NDM dns-proxy). Stock LAN bridges
    # (Bridge0=Home, Bridge1=Guest) will appear too — distinguished by
    # their description; the user picks the right one in the GUI.
    'Bridge',
    # `OpkgTun` — TUN device created by an Entware client (sing-box,
    # TrustTunnel, etc.) and registered into NDM via `interface OpkgTunN`
    # so it gets first-class fwmark-routing-table treatment, exactly
    # like SSTP/Wireguard interfaces. Without this entry the user can't
    # bind dns-proxy route groups to OpkgTun{0..N} from the GUI.
    'OpkgTun',
    # NOTE: `GigabitEthernet`, `Vlan`, `Ipoe`, `Ipip`, `Gre` were
    # intentionally removed. They are physical / L2 / transport-layer
    # interfaces that almost never make sense as a `dns-proxy route ...`
    # target (FQDN routing wants a *VPN-tunnel* iface, not eth0). Add
    # them back here if a specific deployment needs them.
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


# ── Interface dropdown formatting ───────────────────────────────────────────
#
# The GUI shows interfaces in a Combobox using "Name — description" so the
# user can spot e.g. our Bridge2 (description "SoftEther vpn_dallas via L2
# bridge") amid the stock ``Home`` and ``Guest`` LAN bridges. The helpers
# below are the round-trip between bare interface names (what NDM CLI
# expects) and the display strings (what the user picks).

_IFACE_DISPLAY_SEP = ' — '


def iface_display(iface: dict) -> str:
    """Format an interface dict as ``"Name — description"`` for the combobox.
    Falls back to the bare name when the interface has no description."""
    name = (iface.get('name') or '').strip()
    desc = (iface.get('description') or '').strip()
    return f'{name}{_IFACE_DISPLAY_SEP}{desc}' if desc else name


def iface_name_from_display(s: str) -> str:
    """Reverse of :func:`iface_display`: strip the description tail (if any)
    and return the bare interface name. Empty string in → empty string out
    (so it's safe to call on an unselected ComboBox)."""
    if not s:
        return ''
    return s.split(_IFACE_DISPLAY_SEP, 1)[0].strip()
