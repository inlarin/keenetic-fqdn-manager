from kn_gui import vpngate
from kn_gui.cache import CACHE


def test_bootstrap_loaded_from_bundled_json():
    """The shipped bootstrap_servers.json must load as a non-trivial list."""
    servers = vpngate.load_bootstrap_servers()
    assert len(servers) >= 10
    for s in servers:
        assert 'host' in s and 'ip' in s and 'country' in s


def test_fetch_vpngate_parses_csv(monkeypatch):
    """Synthesize a minimal VPN-Gate-style CSV and run it through the parser."""
    CACHE.clear()
    csv = (
        '*vpn_servers\n'
        '#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,'
        'NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,'
        'Message,OpenVPN_ConfigData_Base64\n'
        'public-vpn-1,1.2.3.4,100,10,1000000,Japan,JP,5,86400000,100,'
        '12345,2weeks,Tsukuba,msg,SGVsbG8=\n'
        'public-vpn-2,5.6.7.8,50,20,2000000,Korea,KR,3,172800000,50,'
        '6789,2weeks,Volunteer,msg,SGVsbG8=\n'
        '*\n'
    )
    monkeypatch.setattr(vpngate, '_http_get', lambda url, timeout=30.0: csv)
    out = vpngate.fetch_vpngate(force=True)
    assert len(out) == 2
    s = out[0]
    assert s['HostName'] == 'public-vpn-1'
    assert s['IP'] == '1.2.3.4'
    # Numeric fields coerced
    assert s['Ping'] == 10
    assert s['SpeedMbps'] == 1.0
    assert s['UptimeDays'] == 1.0
    # Big base64 config blob must be stripped (cache bloat mitigation)
    assert 'OpenVPN_ConfigData_Base64' not in s
    CACHE.clear()


def test_fetch_vpngate_skips_terminator(monkeypatch):
    CACHE.clear()
    csv = (
        '#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,'
        'NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,'
        'Message,OpenVPN_ConfigData_Base64\n'
        'only-row,9.9.9.9,1,1,1,X,X,1,1,1,1,l,o,m,c\n'
        '* terminator should not be parsed as row\n'
    )
    monkeypatch.setattr(vpngate, '_http_get', lambda url, timeout=30.0: csv)
    out = vpngate.fetch_vpngate(force=True)
    assert [s['HostName'] for s in out] == ['only-row']
    CACHE.clear()
