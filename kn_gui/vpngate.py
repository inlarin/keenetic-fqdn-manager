"""VPN Gate fetch + bootstrap server list loader."""
from __future__ import annotations

import json

from .constants import TTL_VPNGATE, VPNGATE_URL
from .net import _http_get, cached
from .paths import data_path


def fetch_vpngate(force: bool = False) -> list[dict]:
    """Fetch and parse the VPN Gate academic CSV.
    Returns list of server dicts with numeric fields parsed."""
    def produce():
        text = _http_get(VPNGATE_URL, timeout=30.0)
        lines = text.splitlines()
        header_idx = 0
        for i, ln in enumerate(lines):
            if ln.startswith('#HostName') or ln.startswith('HostName'):
                header_idx = i
                break
        header = [h.strip().lstrip('#') for h in lines[header_idx].split(',')]
        servers: list[dict] = []
        for ln in lines[header_idx + 1:]:
            if not ln or ln.startswith('*'):
                continue
            parts = ln.split(',')
            if len(parts) < len(header):
                continue
            row = dict(zip(header, parts))
            for k in ('Score', 'Ping', 'Speed', 'NumVpnSessions',
                      'Uptime', 'TotalUsers', 'TotalTraffic'):
                try:
                    row[k] = int(row.get(k, 0) or 0)
                except (ValueError, TypeError):
                    row[k] = 0
            row['SpeedMbps'] = round(row['Speed'] / 1_000_000, 1) if row['Speed'] else 0.0
            row['UptimeDays'] = round(row['Uptime'] / 86_400_000, 1) if row['Uptime'] else 0.0
            # Drop the huge base64 OpenVPN config blob — not used, just bloats cache.
            row.pop('OpenVPN_ConfigData_Base64', None)
            servers.append(row)
        return servers
    return cached('vpngate', TTL_VPNGATE, produce, force)


def load_bootstrap_servers() -> list[dict]:
    """Load the hand-picked bootstrap list shipped alongside the app.
    Used when vpngate.net itself is unreachable — lets users spin up an
    initial SSTP tunnel that then makes vpngate.net routable."""
    try:
        with open(data_path('bootstrap_servers.json'), 'r', encoding='utf-8') as f:
            doc = json.load(f)
        return list(doc.get('servers', []))
    except Exception:
        return []
