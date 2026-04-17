"""Tests for KeeneticRCIClient (RCI-based transport).

All network I/O is mocked — no real router needed. We verify that the
RCI transport exposes the same API as the Telnet KeeneticClient and
correctly translates CLI commands through /rci/parse.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from kn_gui.rci_client import RCIClient
from kn_gui.rci_transport import KeeneticRCIClient, _sanitize_cli_value


# ── _sanitize_cli_value ──────────────────────────────────────────────────

def test_sanitize_strips_newlines():
    assert _sanitize_cli_value('hello\nworld') == 'hello world'
    assert _sanitize_cli_value('a\r\nb\x00c') == 'a bc'


def test_sanitize_leaves_normal_strings():
    assert _sanitize_cli_value('vpn.example.com') == 'vpn.example.com'
    assert _sanitize_cli_value('') == ''


# ── KeeneticRCIClient basic API ──────────────────────────────────────────

@pytest.fixture
def mock_rci():
    """Return a KeeneticRCIClient with a mocked RCIClient inside."""
    client = KeeneticRCIClient.__new__(KeeneticRCIClient)
    client.host = '192.168.1.1'
    client.port = 80
    client.connected = True
    client.router_info = {'components': {'sstp'}, '_transport': 'RCI'}
    client._rci = MagicMock(spec=RCIClient)
    client._rci.timeout = 8.0
    return client


def test_run_delegates_to_parse(mock_rci):
    mock_rci._rci.parse.return_value = {
        'parse': 'show version',
        'prompt': '(config)>',
        'status': [{'message': 'NDMS 5.0'}],
    }
    text, ok = mock_rci.run('show version')
    assert ok is True
    assert 'NDMS 5.0' in text
    mock_rci._rci.parse.assert_called_once_with('show version')


def test_run_expect_raises_on_error_output(mock_rci):
    mock_rci._rci.parse.return_value = {
        'parse': 'bad command',
        'prompt': '(config)>',
        'status': [{'message': 'Error: unknown command'}],
    }
    with pytest.raises(RuntimeError, match='failed'):
        mock_rci.run_expect('bad command')


def test_run_expect_succeeds_on_clean_output(mock_rci):
    mock_rci._rci.parse.return_value = {
        'parse': 'system configuration save',
        'prompt': '(config)>',
        'status': [{'message': 'Configuration saved.'}],
    }
    text = mock_rci.run_expect('system configuration save')
    assert 'saved' in text.lower()


# ── create_fqdn_group (RCI version) ──────────────────────────────────────

def test_create_fqdn_group_returns_created_names(mock_rci):
    """Verify auto-split returns all chunk names for binding."""
    mock_rci._rci.parse.return_value = {
        'parse': '', 'prompt': '(config)>', 'status': [],
    }
    # 5 entries, well under the 300 limit — single group.
    created, errs = mock_rci.create_fqdn_group(
        'test', ['a.com', 'b.com', 'c.com', 'd.com', 'e.com'])
    assert created == ['test']
    # Verify object-group + include + exit commands were called.
    calls = [c.args[0] for c in mock_rci._rci.parse.call_args_list]
    assert 'object-group fqdn test' in calls
    assert 'include a.com' in calls
    assert 'exit' in calls


def test_create_fqdn_group_validates_name(mock_rci):
    created, errs = mock_rci.create_fqdn_group(
        '1invalid', ['a.com', 'b.com'])
    assert created == []
    assert any('group name' in e for e in errs)


def test_create_fqdn_group_normalizes_wildcards(mock_rci):
    mock_rci._rci.parse.return_value = {
        'parse': '', 'prompt': '(config)>', 'status': [],
    }
    created, errs = mock_rci.create_fqdn_group(
        'test', ['*.example.com', 'good.org'])
    assert created == ['test']
    # Wildcard should be stripped — include 'example.com' not '*.example.com'.
    calls = [c.args[0] for c in mock_rci._rci.parse.call_args_list]
    assert 'include example.com' in calls
    assert not any('*' in c for c in calls)
    # Should have a warning about wildcard.
    assert any('wildcard' in w for w in errs)


def test_create_fqdn_group_auto_splits(mock_rci):
    """Groups with >300 entries are split into name, name_2, etc."""
    mock_rci._rci.parse.return_value = {
        'parse': '', 'prompt': '(config)>', 'status': [],
    }
    # Generate 650 fake domains (→ 3 chunks: 300 + 300 + 50).
    domains = [f'd{i}.example.com' for i in range(650)]
    created, errs = mock_rci.create_fqdn_group('big', domains)
    assert len(created) == 3
    assert created[0] == 'big'
    assert created[1] == 'big_2'
    assert created[2] == 'big_3'
    assert any('split' in e for e in errs)


# ── delete_fqdn_group ────────────────────────────────────────────────────

def test_delete_fqdn_group_removes_siblings(mock_rci):
    mock_rci._rci.parse.return_value = {
        'parse': '', 'prompt': '(config)>', 'status': [],
    }
    mock_rci.delete_fqdn_group('test')
    calls = [c.args[0] for c in mock_rci._rci.parse.call_args_list]
    # Should delete main + _2.._9.
    assert 'no object-group fqdn test' in calls
    assert 'no dns-proxy route object-group test' in calls
    assert 'no object-group fqdn test_2' in calls
    assert 'no object-group fqdn test_9' in calls


# ── save_config ──────────────────────────────────────────────────────────

def test_save_config_calls_parse(mock_rci):
    mock_rci._rci.parse.return_value = {
        'parse': 'system configuration save',
        'prompt': '(config)>',
        'status': [{'message': 'Configuration saved.'}],
    }
    mock_rci.save_config()
    calls = [c.args[0] for c in mock_rci._rci.parse.call_args_list]
    assert 'system configuration save' in calls


# ── SSTP interface ────────────────────────────────────────────────────────

def test_create_sstp_sanitizes_inputs(mock_rci):
    mock_rci._rci.parse.return_value = {
        'parse': '', 'prompt': '(config)>', 'status': [],
    }
    mock_rci.create_sstp_interface(
        'SSTP1', peer='evil\npeer', user='vpn', password='vpn\nrm -rf /')
    calls = [c.args[0] for c in mock_rci._rci.parse.call_args_list]
    # Newlines must be stripped.
    assert not any('\n' in c for c in calls)
    assert 'peer evil peer' in calls
    assert 'authentication password vpn rm -rf /' in calls


def test_find_free_sstp_index():
    client = KeeneticRCIClient.__new__(KeeneticRCIClient)
    assert client.find_free_sstp_index([]) == 1
    assert client.find_free_sstp_index(['SSTP1', 'SSTP2']) == 3
    assert client.find_free_sstp_index(['SSTP1', 'SSTP3']) == 2


# ── Managed interface tagging + delete flow ──────────────────────────────

def test_create_sstp_tags_description(mock_rci):
    """Every interface we create must carry MANAGED_INTERFACE_TAG in
    its description so list_managed_interfaces() can pick it up later."""
    from kn_gui.constants import MANAGED_INTERFACE_TAG
    mock_rci._rci.parse.return_value = {
        'parse': '', 'prompt': '(config)>', 'status': [],
    }
    mock_rci.create_sstp_interface(
        'SSTP1', peer='203.0.113.5', user='vpn', password='vpn',
        description='VPN Gate JP tokyo-1')
    calls = [c.args[0] for c in mock_rci._rci.parse.call_args_list]
    # Must be exactly one description command, and it must carry the tag.
    desc_calls = [c for c in calls if c.startswith('description ')]
    assert len(desc_calls) == 1, f'expected 1 description, got {desc_calls}'
    assert MANAGED_INTERFACE_TAG in desc_calls[0]


def test_create_sstp_sets_ip_global(mock_rci):
    """Regression: without `ip global` the interface isn't eligible for
    policy routing, and dns-proxy rules silently don't fire."""
    mock_rci._rci.parse.return_value = {
        'parse': '', 'prompt': '(config)>', 'status': [],
    }
    mock_rci.create_sstp_interface(
        'SSTP1', peer='203.0.113.5', user='vpn', password='vpn')
    calls = [c.args[0] for c in mock_rci._rci.parse.call_args_list]
    assert any(c.startswith('ip global ') for c in calls), (
        'create_sstp_interface must emit `ip global <N>` '
        '(the "Use for internet" flag in the web UI)')


def test_list_managed_interfaces_filters_by_tag():
    """Mix of managed + user interfaces; we return only the managed ones."""
    from kn_gui.constants import MANAGED_INTERFACE_TAG
    client = KeeneticRCIClient.__new__(KeeneticRCIClient)
    client._rci = MagicMock(spec=RCIClient)
    # Stub list_interfaces() via a direct method patch.
    client.list_interfaces = MagicMock(return_value=[
        {'name': 'SSTP0', 'type': 'SSTP', 'description': 'manual config',
         'link': 'up', 'connected': 'yes'},
        {'name': 'SSTP1', 'type': 'SSTP',
         'description': f'{MANAGED_INTERFACE_TAG} VPN Gate JP',
         'link': 'up', 'connected': 'yes'},
        {'name': 'SSTP2', 'type': 'SSTP',
         'description': f'{MANAGED_INTERFACE_TAG} VPN Gate KR',
         'link': 'down', 'connected': 'no'},
        {'name': 'Wireguard0', 'type': 'Wireguard',
         'description': 'my wg',
         'link': 'up', 'connected': 'yes'},
    ])
    managed = client.list_managed_interfaces()
    names = [i['name'] for i in managed]
    assert names == ['SSTP1', 'SSTP2']


def test_list_managed_interfaces_empty_when_none_tagged():
    client = KeeneticRCIClient.__new__(KeeneticRCIClient)
    client._rci = MagicMock(spec=RCIClient)
    client.list_interfaces = MagicMock(return_value=[
        {'name': 'SSTP0', 'type': 'SSTP', 'description': 'manual',
         'link': 'up', 'connected': 'yes'},
    ])
    assert client.list_managed_interfaces() == []


def test_delete_interface_sends_no_interface(mock_rci):
    mock_rci._rci.parse.return_value = {
        'parse': '', 'prompt': '(config)>', 'status': [],
    }
    mock_rci.delete_interface('SSTP1')
    calls = [c.args[0] for c in mock_rci._rci.parse.call_args_list]
    assert 'no interface SSTP1' in calls
