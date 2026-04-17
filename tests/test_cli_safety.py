"""Tests for cli_safety module (sanitizer + interface parser).

Moved out of client.py / rci_transport.py as a shared utility; these
tests lock in behaviour both transports rely on.
"""
from __future__ import annotations

import pytest

from kn_gui.cli_safety import (IFACE_TYPES, parse_interfaces_text,
                                sanitize_cli_value)


# ── sanitize_cli_value ─────────────────────────────────────────────────────

@pytest.mark.parametrize('raw, expected', [
    ('hello',              'hello'),
    ('line1\nline2',       'line1 line2'),
    ('line1\r\nline2',     'line1 line2'),
    ('has\x00null',        'hasnull'),
    ('\rline',             'line'),
    ('',                   ''),
    ('mixed\r\n\x00\n x',  'mixed   x'),
])
def test_sanitize_strips_breakers(raw, expected):
    assert sanitize_cli_value(raw) == expected


def test_sanitize_leaves_normal_strings():
    """Only the three dangerous bytes are stripped. Everything else —
    quotes, spaces, punctuation, CJK — passes through untouched."""
    for s in ('vpn.example.com',
              'user@domain',
              'password with spaces',
              'описание на кириллице',
              'quote" backtick`',
              'tab\tok'):
        assert sanitize_cli_value(s) == s


# ── parse_interfaces_text ──────────────────────────────────────────────────

def test_parse_interfaces_basic():
    text = '''
interface-name: PPPoE0
    type: PPPoE
    description: ISP
    link: up
    connected: yes
interface-name: SSTP0
    type: SSTP
    description: Dallas
    link: up
    connected: yes
'''
    result = parse_interfaces_text(text)
    assert len(result) == 2
    assert result[0]['name'] == 'PPPoE0'
    assert result[0]['type'] == 'PPPoE'
    assert result[0]['link'] == 'up'
    assert result[1]['name'] == 'SSTP0'


def test_parse_interfaces_filters_unknown_types():
    text = '''
interface-name: Loopback0
    type: Loopback
    link: up
interface-name: Bridge0
    type: Bridge
    link: up
interface-name: PPPoE0
    type: PPPoE
    link: up
'''
    result = parse_interfaces_text(text)
    # Only PPPoE is in IFACE_TYPES; Loopback and Bridge are filtered out.
    assert [i['name'] for i in result] == ['PPPoE0']


def test_parse_interfaces_empty():
    assert parse_interfaces_text('') == []
    assert parse_interfaces_text('garbage text') == []


def test_parse_interfaces_last_entry_kept():
    """The final interface has no trailing blank line / `!` separator
    in real CLI output either — the parser must still emit it."""
    text = 'interface-name: Wireguard1\n    type: Wireguard'
    result = parse_interfaces_text(text)
    assert len(result) == 1
    assert result[0]['name'] == 'Wireguard1'


def test_iface_types_includes_core_vpn():
    # Smoke-check: the VPN types we actually manage are present.
    for t in ('PPPoE', 'SSTP', 'Wireguard', 'OpenVPN', 'L2TP', 'PPTP'):
        assert t in IFACE_TYPES
