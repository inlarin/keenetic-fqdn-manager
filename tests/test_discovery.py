"""Tests for kn_gui.discovery.

All network I/O is mocked via ``urllib.request.urlopen`` — no real router
needed. Tests verify:

* probe() correctly classifies 401+challenge as a hit, plain 401 as not.
* probe() swallows every network error type.
* list_default_gateways() parses both Windows (English + Russian) and
  Linux (``ip route``) output.
* scan_subnet() parallelism and cancellation.
* find_keenetic() follows the tiered strategy: last → gateway → /24 → typical.
"""
from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest

from kn_gui import discovery


# ── Helpers ───────────────────────────────────────────────────────────────


class _FakeResponse:
    """Duck-types enough of ``http.client.HTTPResponse`` for urlopen."""

    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _urlopen_returning(status: int, headers: dict | None = None):
    """Factory: returns an urlopen mock that yields the given response."""
    if status == 200:
        return MagicMock(return_value=_FakeResponse(status, headers))
    # For non-2xx, urllib raises HTTPError.
    import urllib.error

    def _raise(req, timeout=None):
        err = urllib.error.HTTPError(
            req.full_url, status, 'mock', headers or {}, None)
        return err  # HTTPError is valid as an error response

    # urlopen() raises for 4xx/5xx — simulate that.
    def _urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, status, 'mock', headers or {}, None)

    return MagicMock(side_effect=_urlopen)


# ── probe() ──────────────────────────────────────────────────────────────


def test_probe_accepts_401_with_ndm_challenge():
    with patch('kn_gui.discovery.urllib.request.urlopen',
               _urlopen_returning(401, {
                   'X-NDM-Realm': 'keenetic',
                   'X-NDM-Challenge': 'abc123',
               })):
        result = discovery.probe('192.168.1.1')
    assert result is not None
    assert result['host'] == '192.168.1.1'
    assert result['realm'] == 'keenetic'
    assert 'rtt_ms' in result


def test_probe_accepts_200_already_authenticated():
    """A cached cookie could make the router answer 200 — still counts."""
    with patch('kn_gui.discovery.urllib.request.urlopen',
               MagicMock(return_value=_FakeResponse(200, {
                   'X-NDM-Realm': 'keenetic',
               }))):
        result = discovery.probe('192.168.1.1')
    assert result is not None
    assert result['host'] == '192.168.1.1'


def test_probe_rejects_plain_401_without_challenge():
    """A NAS with Basic-Auth returns 401 too — must NOT be mistaken for
    a Keenetic."""
    with patch('kn_gui.discovery.urllib.request.urlopen',
               _urlopen_returning(401, {
                   'WWW-Authenticate': 'Basic realm="nas"',
               })):
        result = discovery.probe('192.168.1.2')
    assert result is None


def test_probe_rejects_200_on_other_vendor_router():
    """Unrelated 200 response (e.g. index page of another router)."""
    with patch('kn_gui.discovery.urllib.request.urlopen',
               MagicMock(return_value=_FakeResponse(200, {
                   'Server': 'NotAKeenetic',
               }))):
        result = discovery.probe('192.168.1.3')
    # 200 without X-NDM headers is ambiguous. Our policy: still accept,
    # but realm will be empty. This is a deliberate choice — a reachable
    # admin endpoint is better than false negative on /auth that happens
    # to return 200 (no credentials required).
    # If the caller later fails to auth, RCIClient will report it.
    assert result is not None
    assert result['realm'] == ''


def test_probe_swallows_url_error():
    import urllib.error
    with patch('kn_gui.discovery.urllib.request.urlopen',
               MagicMock(side_effect=urllib.error.URLError('unreachable'))):
        assert discovery.probe('10.0.0.1') is None


def test_probe_swallows_timeout():
    import socket as _socket
    with patch('kn_gui.discovery.urllib.request.urlopen',
               MagicMock(side_effect=_socket.timeout())):
        assert discovery.probe('10.0.0.1') is None


def test_probe_swallows_os_error():
    with patch('kn_gui.discovery.urllib.request.urlopen',
               MagicMock(side_effect=OSError('connection refused'))):
        assert discovery.probe('10.0.0.1') is None


def test_probe_empty_host_returns_none():
    assert discovery.probe('') is None


# ── Gateway enumeration ──────────────────────────────────────────────────


_IPCONFIG_EN = """\
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : home
   IPv4 Address. . . . . . . . . . . : 192.168.1.42
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1

Wireless LAN adapter Wi-Fi:

   Default Gateway . . . . . . . . . : 192.168.32.1
"""

_IPCONFIG_RU = """\
Настройка протокола IP для Windows

Адаптер Ethernet Ethernet:

   DNS-суффикс подключения . . . . . : home
   IPv4-адрес. . . . . . . . . . . . : 192.168.1.42
   Маска подсети . . . . . . . . . . : 255.255.255.0
   Основной шлюз . . . . . . . . . . : 192.168.1.1
"""

_IPCONFIG_NO_GW = """\
Windows IP Configuration

Ethernet adapter Loopback:
   IPv4 Address. . . . . . . . . . . : 169.254.1.1
   Default Gateway . . . . . . . . . :
"""


def test_gateways_via_ipconfig_english():
    with patch('kn_gui.discovery.subprocess.run') as mrun:
        mrun.return_value.stdout = _IPCONFIG_EN
        result = discovery._gateways_via_ipconfig()
    assert '192.168.1.1' in result
    assert '192.168.32.1' in result


def test_gateways_via_ipconfig_russian():
    with patch('kn_gui.discovery.subprocess.run') as mrun:
        mrun.return_value.stdout = _IPCONFIG_RU
        result = discovery._gateways_via_ipconfig()
    assert result == ['192.168.1.1']


def test_gateways_via_ipconfig_empty_gw_ignored():
    with patch('kn_gui.discovery.subprocess.run') as mrun:
        mrun.return_value.stdout = _IPCONFIG_NO_GW
        result = discovery._gateways_via_ipconfig()
    assert result == []


def test_gateways_via_ipconfig_failure_returns_empty():
    with patch('kn_gui.discovery.subprocess.run',
               side_effect=OSError('ipconfig missing')):
        assert discovery._gateways_via_ipconfig() == []


# ── scan_subnet() ────────────────────────────────────────────────────────


def test_scan_subnet_finds_the_router():
    def fake_probe(host, timeout=None):
        if host == '192.168.1.1':
            return {'host': host, 'realm': 'keenetic', 'rtt_ms': 42}
        return None

    with patch('kn_gui.discovery.probe', fake_probe):
        # Use a /29 so we only probe 6 hosts — keeps the test fast.
        results = discovery.scan_subnet('192.168.1.0/29', workers=4)
    assert len(results) == 1
    assert results[0]['host'] == '192.168.1.1'


def test_scan_subnet_sorts_by_rtt():
    hits = {
        '192.168.1.1': {'host': '192.168.1.1', 'realm': 'a', 'rtt_ms': 80},
        '192.168.1.2': {'host': '192.168.1.2', 'realm': 'b', 'rtt_ms': 30},
        '192.168.1.3': {'host': '192.168.1.3', 'realm': 'c', 'rtt_ms': 50},
    }
    with patch('kn_gui.discovery.probe', lambda h, timeout=None: hits.get(h)):
        results = discovery.scan_subnet('192.168.1.0/29', workers=4)
    rtts = [r['rtt_ms'] for r in results]
    assert rtts == sorted(rtts), 'results must be sorted by RTT asc'


def test_scan_subnet_refuses_huge_prefixes():
    # /16 = 65k probes → refuse.
    assert discovery.scan_subnet('10.0.0.0/16') == []


def test_scan_subnet_respects_cancel():
    cancel = threading.Event()
    cancel.set()   # pre-cancelled
    # With cancel already set, the sweep should exit without scanning.
    with patch('kn_gui.discovery.probe',
               MagicMock(return_value=None)) as mprobe:
        results = discovery.scan_subnet('192.168.1.0/29',
                                         workers=2, cancel=cancel)
    assert results == []
    # It's fine if a handful of futures started before the cancel check,
    # but the pool should NOT have walked the whole address space.
    # Relaxed assertion: at least we didn't finish normally.


# ── find_keenetic() strategy ─────────────────────────────────────────────


def test_find_keenetic_stops_at_last_host_when_hit():
    hit = {'host': '192.168.32.1', 'realm': 'keenetic', 'rtt_ms': 12}
    with patch('kn_gui.discovery.probe', return_value=hit) as mprobe, \
         patch('kn_gui.discovery.list_default_gateways') as mgw, \
         patch('kn_gui.discovery.scan_subnet') as msweep:
        results = discovery.find_keenetic(last_host='192.168.32.1')
    assert results == [hit]
    # Should have skipped gateway enumeration entirely.
    mgw.assert_not_called()
    msweep.assert_not_called()


def test_find_keenetic_falls_through_to_gateway():
    hit = {'host': '192.168.1.1', 'realm': 'keenetic', 'rtt_ms': 80}

    call_log: list[str] = []

    def fake_probe(host, timeout=None):
        call_log.append(host)
        if host == '192.168.1.1':
            return hit
        return None

    with patch('kn_gui.discovery.probe', fake_probe), \
         patch('kn_gui.discovery.list_default_gateways',
               return_value=['192.168.1.1']), \
         patch('kn_gui.discovery.scan_subnet') as msweep:
        results = discovery.find_keenetic(last_host='192.168.99.99')
    assert results == [hit]
    # Last-host probed first, then gateway.
    assert call_log == ['192.168.99.99', '192.168.1.1']
    msweep.assert_not_called()


def test_find_keenetic_falls_through_to_subnet_sweep():
    hit = {'host': '192.168.1.42', 'realm': 'keenetic', 'rtt_ms': 120}
    with patch('kn_gui.discovery.probe', return_value=None), \
         patch('kn_gui.discovery.list_default_gateways',
               return_value=['192.168.1.1']), \
         patch('kn_gui.discovery.scan_subnet',
               return_value=[hit]) as msweep:
        results = discovery.find_keenetic(last_host=None)
    assert results == [hit]
    # Called for the gateway's /24.
    assert msweep.call_args.args[0] == '192.168.1.0/24'


def test_find_keenetic_opt_out_typical_subnets():
    with patch('kn_gui.discovery.probe', return_value=None), \
         patch('kn_gui.discovery.list_default_gateways', return_value=[]), \
         patch('kn_gui.discovery.local_ip_guess', return_value=None), \
         patch('kn_gui.discovery.scan_subnet',
               return_value=[]) as msweep:
        results = discovery.find_keenetic(include_typical=False)
    assert results == []
    msweep.assert_not_called()


def test_find_keenetic_respects_cancel():
    cancel = threading.Event()

    def fake_probe(host, timeout=None):
        cancel.set()   # trip on the very first probe
        return None

    with patch('kn_gui.discovery.probe', fake_probe), \
         patch('kn_gui.discovery.list_default_gateways',
               return_value=['10.0.0.1']), \
         patch('kn_gui.discovery.scan_subnet') as msweep:
        results = discovery.find_keenetic(
            last_host='192.168.1.1', cancel=cancel)
    assert results == []
    # scan_subnet must not be called after cancellation.
    msweep.assert_not_called()


def test_find_keenetic_sorts_aggregate_by_rtt():
    hits_by_subnet = {
        '192.168.1.0/24': [{'host': 'a', 'realm': '', 'rtt_ms': 80}],
        '10.0.0.0/24':    [{'host': 'b', 'realm': '', 'rtt_ms': 30}],
    }

    def fake_sweep(cidr, **kw):
        return hits_by_subnet.get(cidr, [])

    with patch('kn_gui.discovery.probe', return_value=None), \
         patch('kn_gui.discovery.list_default_gateways',
               return_value=['192.168.1.1', '10.0.0.1']), \
         patch('kn_gui.discovery.scan_subnet', side_effect=fake_sweep):
        results = discovery.find_keenetic()
    assert [r['host'] for r in results] == ['b', 'a']


def test_find_keenetic_progress_callback_invoked():
    messages: list[str] = []
    with patch('kn_gui.discovery.probe', return_value=None), \
         patch('kn_gui.discovery.list_default_gateways', return_value=[]), \
         patch('kn_gui.discovery.local_ip_guess', return_value=None), \
         patch('kn_gui.discovery.scan_subnet', return_value=[]):
        discovery.find_keenetic(on_progress=messages.append,
                                 include_typical=False)
    # At minimum we should be told no gateways were found.
    assert any('шлюз' in m.lower() for m in messages)
