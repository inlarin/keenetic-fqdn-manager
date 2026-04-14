"""
Keenetic FQDN Router Manager
A GUI tool to manage FQDN object-groups and dns-proxy routes on Keenetic
(and OEM forks like Netcraze) routers via telnet CLI.

Single-file app. Bundle with:
    pyinstaller --onefile --windowed --add-data "services.json;." kn_router_gui.py
"""
from __future__ import annotations

import json
import os
import queue
import re
import socket
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import urllib.request
from enum import Enum
from pathlib import Path
from tkinter import ttk, messagebox, filedialog, scrolledtext
from typing import Callable, Optional

APP_NAME = 'Keenetic FQDN Manager'
APP_VERSION = '0.8.0'
DEFAULT_ROUTER = '192.168.32.1'
DEFAULT_USER = 'admin'
DEFAULT_TELNET_PORT = 23
GROUP_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]{0,31}$')

CONFIG_DIR = Path(os.environ.get('APPDATA', os.path.expanduser('~'))) / 'KeeneticFqdnManager'
CONFIG_FILE = CONFIG_DIR / 'ui.json'


def _cache_dir() -> Path:
    """Prefer folder next to the .exe / .py. Fall back to %APPDATA% if the
    exe folder is read-only (e.g. installed under Program Files)."""
    if getattr(sys, 'frozen', False) or hasattr(sys, '_MEIPASS'):
        base = Path(os.path.dirname(sys.executable))
    else:
        base = Path(os.path.dirname(os.path.abspath(__file__)))
    candidate = base / 'cache'
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        test = candidate / '.wtest'
        test.write_text('')
        test.unlink()
        return candidate
    except Exception:
        fb = CONFIG_DIR / 'cache'
        fb.mkdir(parents=True, exist_ok=True)
        return fb


CACHE_DIR = _cache_dir()
CACHE_FILE = CACHE_DIR / 'cache.json'


class DiskCache:
    """Single-file JSON cache with per-entry TTL. Thread-safe for our use
    (one writer from the worker thread at a time)."""
    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {'version': 1, 'entries': {}}
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        try:
            self.data = json.loads(self.path.read_text(encoding='utf-8'))
            if 'entries' not in self.data:
                self.data['entries'] = {}
        except Exception:
            self.data = {'version': 1, 'entries': {}}

    def _save(self):
        try:
            self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2),
                                 encoding='utf-8')
        except Exception:
            pass

    def get(self, key: str, max_age: float) -> Optional[object]:
        with self._lock:
            entry = self.data['entries'].get(key)
            if not entry:
                return None
            age = time.time() - entry.get('fetched_at', 0)
            if age > max_age:
                return None
            return entry.get('value')

    def age(self, key: str) -> Optional[float]:
        with self._lock:
            entry = self.data['entries'].get(key)
            if not entry:
                return None
            return time.time() - entry.get('fetched_at', 0)

    def set(self, key: str, value) -> None:
        with self._lock:
            self.data['entries'][key] = {
                'fetched_at': time.time(),
                'value': value,
            }
            self._save()

    def clear(self) -> None:
        with self._lock:
            self.data = {'version': 1, 'entries': {}}
            self._save()

    def size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except Exception:
            return 0

    def num_entries(self) -> int:
        return len(self.data.get('entries', {}))


CACHE = DiskCache(CACHE_FILE)

# TTL defaults per source class (seconds)
TTL_VPNGATE      = 5 * 60
TTL_V2FLY        = 6 * 60 * 60
TTL_IP_PROVIDER  = 24 * 60 * 60
TTL_ASN          = 24 * 60 * 60

CATEGORY_ICON = {
    'AI': '🤖', 'Video': '📺', 'Music': '🎵', 'Messaging': '💬',
    'Social': '👥', 'Dev': '⚙', 'Productivity': '📝', 'Content': '📰',
    'Other': '📦',
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def resource_path(relative_path: str) -> str:
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


def cidr_to_mask(cidr: str) -> tuple[str, str]:
    net, prefix_s = cidr.split('/')
    prefix = int(prefix_s)
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    mask = '.'.join(str((mask_int >> (24 - 8 * i)) & 0xFF) for i in range(4))
    return net, mask


def strip_ansi(s: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', s)


# ─────────────────────────────────────────────────────────────────────────────
# Upstream fetchers — pull FQDN lists and IPv4 CIDRs from public sources
# ─────────────────────────────────────────────────────────────────────────────

_FETCH_HEADERS = {'User-Agent': f'{APP_NAME}/{APP_VERSION}'}


def _http_get(url: str, timeout: float = 20.0) -> str:
    req = urllib.request.Request(url, headers=_FETCH_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='replace')


def _cached(key: str, ttl: float, producer: Callable, force: bool = False):
    """Return cached value for key if fresh, else produce, cache, return."""
    if not force:
        hit = CACHE.get(key, ttl)
        if hit is not None:
            return hit
    value = producer()
    CACHE.set(key, value)
    return value


def fetch_v2fly(url: str, force: bool = False) -> list[str]:
    """Parse v2fly domain-list-community format.
    We accept `domain:X` and `full:X`; drop `keyword:`, `regexp:`, `include:`
    and comment-only / empty lines."""
    def produce():
        text = _http_get(url)
        out: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '#' in line:
                line = line.split('#', 1)[0].strip()
            if not line:
                continue
            if ':' in line:
                prefix, rest = line.split(':', 1)
                prefix = prefix.lower().strip()
                rest = rest.strip().split()[0] if rest.strip() else ''
                if prefix in ('domain', 'full') and rest:
                    out.add(rest.lower())
            else:
                if ' ' not in line:
                    out.add(line.lower())
        return sorted(out)
    return _cached(f'v2fly:{url}', TTL_V2FLY, produce, force)


def fetch_plain_text(url: str, force: bool = False) -> list[str]:
    """Generic: one domain per line; # for comments."""
    def produce():
        text = _http_get(url)
        out: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '#' in line:
                line = line.split('#', 1)[0].strip()
            if line and ' ' not in line and '/' not in line:
                out.add(line.lower())
        return sorted(out)
    return _cached(f'plain:{url}', TTL_V2FLY, produce, force)


def fetch_cloudflare_v4(force: bool = False) -> list[str]:
    def produce():
        text = _http_get('https://www.cloudflare.com/ips-v4')
        return sorted({ln.strip() for ln in text.splitlines() if ln.strip() and '/' in ln})
    return _cached('cloudflare', TTL_IP_PROVIDER, produce, force)


def fetch_github_meta(force: bool = False) -> list[str]:
    def produce():
        data = json.loads(_http_get('https://api.github.com/meta'))
        ips: set[str] = set()
        for key in ('web', 'api', 'git', 'packages', 'hooks'):
            for entry in data.get(key, []):
                if ':' not in entry and '/' in entry:
                    ips.add(entry)
        return sorted(ips)
    return _cached('github_meta', TTL_IP_PROVIDER, produce, force)


def fetch_fastly(force: bool = False) -> list[str]:
    def produce():
        data = json.loads(_http_get('https://api.fastly.com/public-ip-list'))
        return sorted({a for a in data.get('addresses', []) if '/' in a})
    return _cached('fastly', TTL_IP_PROVIDER, produce, force)


def fetch_aws_service(service_tag: str, force: bool = False) -> list[str]:
    def produce():
        data = json.loads(_http_get('https://ip-ranges.amazonaws.com/ip-ranges.json'))
        return sorted({
            p['ip_prefix'] for p in data.get('prefixes', [])
            if p.get('service') == service_tag and 'ip_prefix' in p
        })
    return _cached(f'aws:{service_tag}', TTL_IP_PROVIDER, produce, force)


def fetch_google_ipranges(name: str = 'goog', force: bool = False) -> list[str]:
    """name is 'goog' (all Google) or 'cloud' (GCP)."""
    def produce():
        data = json.loads(_http_get(f'https://www.gstatic.com/ipranges/{name}.json'))
        return sorted({
            p['ipv4Prefix'] for p in data.get('prefixes', []) if 'ipv4Prefix' in p
        })
    return _cached(f'google:{name}', TTL_IP_PROVIDER, produce, force)


def fetch_oracle_ranges(service: str = '', force: bool = False) -> list[str]:
    def produce():
        data = json.loads(_http_get('https://docs.oracle.com/iaas/tools/public_ip_ranges.json'))
        out: set[str] = set()
        for region in data.get('regions', []):
            for cidr in region.get('cidrs', []):
                if service and service not in cidr.get('tags', []):
                    continue
                if '/' in cidr.get('cidr', ''):
                    out.add(cidr['cidr'])
        return sorted(out)
    return _cached(f'oracle:{service}', TTL_IP_PROVIDER, produce, force)


def fetch_asn_prefixes(asn: int, force: bool = False) -> list[str]:
    """RIPEstat: IPv4 prefixes announced by an ASN."""
    def produce():
        url = f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}'
        data = json.loads(_http_get(url, timeout=30.0))
        out: set[str] = set()
        for entry in data.get('data', {}).get('prefixes', []):
            pfx = entry.get('prefix', '')
            if ':' not in pfx and '/' in pfx:
                out.add(pfx)
        return sorted(out)
    return _cached(f'asn:{asn}', TTL_ASN, produce, force)


# ─────────────────────────────────────────────────────────────────────────────
# SoftEther VPN Gate
# ─────────────────────────────────────────────────────────────────────────────

VPNGATE_URL = 'http://www.vpngate.net/api/iphone/'

# Offline bootstrap: 40 servers picked at release time from the live CSV,
# weighted by uptime * sqrt(speed) / ping. Diversified to at most 2 per /24
# subnet so one DPI-blocked network doesn't kill the whole list. Purpose:
# let a user with NO existing VPN route spin up an initial SSTP tunnel to
# reach vpngate.net and refresh the full live list.
BOOTSTRAP_VPNGATE_SERVERS: list[dict] = [
    {"host": "public-vpn-58", "ip": "219.100.37.49", "country": "JP", "country_long": "Japan", "speed_mbps": 1356.3, "uptime_days": 65.4, "log_policy": "2weeks", "operator": "Daiyuu Nobori_ Japan. Academic Use Only."},
    {"host": "public-vpn-187", "ip": "219.100.37.179", "country": "JP", "country_long": "Japan", "speed_mbps": 741.2, "uptime_days": 65.4, "log_policy": "2weeks", "operator": "Daiyuu Nobori_ Japan. Academic Use Only."},
    {"host": "vpn547433109", "ip": "60.94.156.193", "country": "JP", "country_long": "Japan", "speed_mbps": 112.4, "uptime_days": 89.5, "log_policy": "2weeks", "operator": "DESKTOP-0AHT9E7's owner"},
    {"host": "vpn402044879", "ip": "211.185.142.92", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 233.9, "uptime_days": 42.5, "log_policy": "2weeks", "operator": "LAPTOP-5PPSLTA4's owner"},
    {"host": "vpn174859392", "ip": "153.182.10.87", "country": "JP", "country_long": "Japan", "speed_mbps": 31.5, "uptime_days": 70.3, "log_policy": "2weeks", "operator": "DESKTOP-O54US4T's owner"},
    {"host": "vpn555964923", "ip": "115.91.77.92", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 788.7, "uptime_days": 31.3, "log_policy": "2weeks", "operator": "DESKTOP-8P3DAB8's owner"},
    {"host": "vpn267555532", "ip": "133.149.208.5", "country": "JP", "country_long": "Japan", "speed_mbps": 200.9, "uptime_days": 30.4, "log_policy": "2weeks", "operator": "Unknown346's owner"},
    {"host": "vpn483922824", "ip": "125.51.134.78", "country": "JP", "country_long": "Japan", "speed_mbps": 951.4, "uptime_days": 15.4, "log_policy": "2weeks", "operator": "Necmon's owner"},
    {"host": "vpn243876497", "ip": "14.35.204.212", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 777.6, "uptime_days": 13.3, "log_policy": "2weeks", "operator": "DESKTOP-TLA53CI's owner"},
    {"host": "n26", "ip": "103.152.178.62", "country": "JP", "country_long": "Japan", "speed_mbps": 31.0, "uptime_days": 31.1, "log_policy": "2weeks", "operator": "DNCServers"},
    {"host": "vpn257766783", "ip": "133.155.185.191", "country": "JP", "country_long": "Japan", "speed_mbps": 37.0, "uptime_days": 25.4, "log_policy": "2weeks", "operator": "WIN-MMRJCODCAVO's owner"},
    {"host": "vpn734393325", "ip": "220.125.33.97", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 95.8, "uptime_days": 16.6, "log_policy": "2weeks", "operator": "DESKTOP-LPP12CE's owner"},
    {"host": "vpn699442602", "ip": "118.240.66.7", "country": "JP", "country_long": "Japan", "speed_mbps": 838.8, "uptime_days": 8.3, "log_policy": "2weeks", "operator": "DESKTOP-N3018PM's owner"},
    {"host": "vpn172194090", "ip": "126.88.128.168", "country": "JP", "country_long": "Japan", "speed_mbps": 695.4, "uptime_days": 7.2, "log_policy": "2weeks", "operator": "DESKTOP-3OQEUC5's owner"},
    {"host": "2i6", "ip": "1.66.33.164", "country": "JP", "country_long": "Japan", "speed_mbps": 101.4, "uptime_days": 12.4, "log_policy": "2weeks", "operator": "DNC"},
    {"host": "vpn892785171", "ip": "110.67.13.220", "country": "JP", "country_long": "Japan", "speed_mbps": 178.6, "uptime_days": 10.2, "log_policy": "2weeks", "operator": "mariko's owner"},
    {"host": "vpn801552750", "ip": "113.22.172.28", "country": "VN", "country_long": "Viet Nam", "speed_mbps": 532.8, "uptime_days": 6.2, "log_policy": "2weeks", "operator": "DESKTOP-P0F2MAS's owner"},
    {"host": "vpn655909591", "ip": "106.158.139.230", "country": "JP", "country_long": "Japan", "speed_mbps": 701.3, "uptime_days": 4.3, "log_policy": "2weeks", "operator": "eater's owner"},
    {"host": "vpn953960224", "ip": "114.16.18.46", "country": "JP", "country_long": "Japan", "speed_mbps": 545.9, "uptime_days": 3.4, "log_policy": "2weeks", "operator": "T-Kname's owner"},
    {"host": "vpn855551265", "ip": "122.36.8.16", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 88.6, "uptime_days": 7.2, "log_policy": "2weeks", "operator": "DESKTOP-F0AB0IT's owner"},
    {"host": "vpn211969447", "ip": "118.41.236.148", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 83.7, "uptime_days": 5.1, "log_policy": "2weeks", "operator": "DESKTOP-KHCJQM0's owner"},
    {"host": "vpn987180915", "ip": "106.168.253.245", "country": "JP", "country_long": "Japan", "speed_mbps": 67.8, "uptime_days": 5.1, "log_policy": "2weeks", "operator": "DESKTOP-TDBEP88's owner"},
    {"host": "vpn237166644", "ip": "121.156.29.29", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 117.9, "uptime_days": 4.3, "log_policy": "2weeks", "operator": "DESKTOP-DUN3CS5's owner"},
    {"host": "vpn415748184", "ip": "125.202.166.110", "country": "JP", "country_long": "Japan", "speed_mbps": 327.2, "uptime_days": 2.4, "log_policy": "2weeks", "operator": "GALLERIA-RL5C-R35T's owner"},
    {"host": "vpn888165520", "ip": "14.133.60.67", "country": "JP", "country_long": "Japan", "speed_mbps": 90.9, "uptime_days": 3.4, "log_policy": "2weeks", "operator": "idea-PC's owner"},
    {"host": "vpn705026594", "ip": "58.98.175.87", "country": "JP", "country_long": "Japan", "speed_mbps": 197.9, "uptime_days": 2.6, "log_policy": "2weeks", "operator": "DESKTOP-RAKN0HV's owner"},
    {"host": "vpn473206366", "ip": "60.119.199.206", "country": "JP", "country_long": "Japan", "speed_mbps": 265.4, "uptime_days": 2.3, "log_policy": "2weeks", "operator": "DESKTOP-HUUFSTU's owner"},
    {"host": "vpn559430764", "ip": "126.219.117.54", "country": "JP", "country_long": "Japan", "speed_mbps": 214.1, "uptime_days": 2.3, "log_policy": "2weeks", "operator": "tukune33333's owner"},
    {"host": "vpn517286755", "ip": "1.53.96.73", "country": "VN", "country_long": "Viet Nam", "speed_mbps": 66.4, "uptime_days": 4.3, "log_policy": "2weeks", "operator": "CAM-PC's owner"},
    {"host": "vpn148293641", "ip": "175.208.46.223", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 232.8, "uptime_days": 2.1, "log_policy": "2weeks", "operator": "DESKTOP-6MGC1KD's owner"},
    {"host": "vpn946999877", "ip": "58.183.127.232", "country": "JP", "country_long": "Japan", "speed_mbps": 212.3, "uptime_days": 2.1, "log_policy": "2weeks", "operator": "トムとジェリーの配下's owner"},
    {"host": "vpn809753260", "ip": "124.246.174.153", "country": "JP", "country_long": "Japan", "speed_mbps": 963.1, "uptime_days": 1.3, "log_policy": "2weeks", "operator": "DESKTOP-4OL02EV's owner"},
    {"host": "vpn160593065", "ip": "211.230.99.159", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 98.4, "uptime_days": 2.3, "log_policy": "2weeks", "operator": "DESKTOP-83AFFI0's owner"},
    {"host": "vpn966533712", "ip": "59.6.114.192", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 320.5, "uptime_days": 1.2, "log_policy": "2weeks", "operator": "PC's owner"},
    {"host": "vpn829299859", "ip": "153.176.147.247", "country": "JP", "country_long": "Japan", "speed_mbps": 92.9, "uptime_days": 1.2, "log_policy": "2weeks", "operator": "WIN-T2NQ1SDSOFK's owner"},
    {"host": "vpn666075659", "ip": "118.36.15.104", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 85.9, "uptime_days": 1.3, "log_policy": "2weeks", "operator": "DESKTOP-2KJUIB4's owner"},
    {"host": "vpn759533362", "ip": "183.103.84.180", "country": "KR", "country_long": "Korea Republic of", "speed_mbps": 55.2, "uptime_days": 1.2, "log_policy": "2weeks", "operator": "DESKTOP-1A8DDC1's owner"},
    {"host": "vpn221487938", "ip": "126.125.49.30", "country": "JP", "country_long": "Japan", "speed_mbps": 30.7, "uptime_days": 1.3, "log_policy": "2weeks", "operator": "user's owner"},
    {"host": "vpn25252525", "ip": "180.144.222.102", "country": "JP", "country_long": "Japan", "speed_mbps": 7.7, "uptime_days": 2.1, "log_policy": "2weeks", "operator": "Matsushin-PC's owner"},
    {"host": "vpn193189456", "ip": "184.22.34.95", "country": "TH", "country_long": "Thailand", "speed_mbps": 353.5, "uptime_days": 0.3, "log_policy": "2weeks", "operator": "B's owner"},
]


def check_tcp_reachable(host: str, port: int = 443, timeout: float = 3.0) -> tuple[bool, float]:
    """Try a TCP connect. Returns (reachable, rtt_ms). rtt_ms is -1 on failure."""
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.time() - t0) * 1000
    except Exception:
        return False, -1


def fetch_vpngate(force: bool = False) -> list[dict]:
    """Fetch and parse the VPN Gate academic CSV.
    Returns list of server dicts with numeric fields parsed."""
    def produce():
        text = _http_get(VPNGATE_URL, timeout=30.0)
        lines = text.splitlines()
        # Find header row (starts with '#HostName' or first CSV line)
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
            # We intentionally drop the huge base64 OpenVPN config from cache
            row.pop('OpenVPN_ConfigData_Base64', None)
            servers.append(row)
        return servers
    return _cached('vpngate', TTL_VPNGATE, produce, force)


def resolve_ipv4_provider(spec: str) -> tuple[list[str], str]:
    """Dispatch `ipv4_providers` entries. Returns (cidrs, human_label)."""
    spec = spec.strip()
    if ':' in spec:
        kind, arg = spec.split(':', 1)
        kind = kind.lower()
        if kind == 'aws':
            return fetch_aws_service(arg.upper()), f'aws:{arg.upper()}'
        if kind == 'google':
            return fetch_google_ipranges(arg.lower()), f'google:{arg.lower()}'
        if kind == 'oracle':
            return fetch_oracle_ranges(arg.upper()), f'oracle:{arg.upper()}'
        if kind == 'asn':
            return fetch_asn_prefixes(int(arg)), f'AS{arg}'
        raise ValueError(f'Unknown provider kind: {kind}')
    key = spec.lower()
    if key == 'cloudflare':
        return fetch_cloudflare_v4(), 'cloudflare'
    if key == 'github':
        return fetch_github_meta(), 'github'
    if key == 'fastly':
        return fetch_fastly(), 'fastly'
    raise ValueError(f'Unknown provider: {spec}')


def refresh_service(svc: dict, merge: bool = True) -> tuple[dict, list[str], list[str]]:
    """Pull upstream/ipv4_providers/asn data into the service.

    Returns (updated_svc, info_lines, errors).
    When merge=True, upstream data is union-merged with catalog lists.
    When merge=False, upstream data replaces them."""
    info: list[str] = []
    errors: list[str] = []
    new_fqdn: set[str] = set(svc.get('fqdn', [])) if merge else set()
    new_ipv4: set[str] = set(svc.get('ipv4_cidr', [])) if merge else set()

    for spec in svc.get('upstream', []) or []:
        t = (spec.get('type') or '').lower()
        url = spec.get('url', '')
        try:
            if t == 'v2fly':
                pulled = fetch_v2fly(url)
            elif t in ('text', 'plain', 'podkop'):
                pulled = fetch_plain_text(url)
            else:
                errors.append(f'unknown upstream type: {t}')
                continue
            before = len(new_fqdn)
            new_fqdn.update(pulled)
            info.append(f'{t}: {url.rsplit("/", 1)[-1]} — {len(pulled)} items, +{len(new_fqdn) - before} new FQDN')
        except Exception as e:
            errors.append(f'{url}: {e}')

    for spec in svc.get('ipv4_providers', []) or []:
        try:
            cidrs, label = resolve_ipv4_provider(spec)
            before = len(new_ipv4)
            new_ipv4.update(cidrs)
            info.append(f'{label}: {len(cidrs)} CIDR, +{len(new_ipv4) - before} new IPv4')
        except Exception as e:
            errors.append(f'{spec}: {e}')

    for asn in svc.get('asn', []) or []:
        try:
            cidrs = fetch_asn_prefixes(int(asn))
            before = len(new_ipv4)
            new_ipv4.update(cidrs)
            info.append(f'AS{asn}: {len(cidrs)} prefixes, +{len(new_ipv4) - before} new IPv4')
        except Exception as e:
            errors.append(f'AS{asn}: {e}')

    out_svc = dict(svc)
    out_svc['fqdn'] = sorted(new_fqdn)
    out_svc['ipv4_cidr'] = sorted(new_ipv4)
    return out_svc, info, errors


def load_ui_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
    except Exception:
        return {}


def save_ui_config(data: dict) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding='utf-8')
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Connection state
# ─────────────────────────────────────────────────────────────────────────────

class ConnState(Enum):
    DISCONNECTED = 'disconnected'
    CONNECTING = 'connecting'
    CONNECTED = 'connected'
    ERROR = 'error'


STATE_COLOR = {
    ConnState.DISCONNECTED: '#888',
    ConnState.CONNECTING:   '#e6a500',
    ConnState.CONNECTED:    '#2c9f2c',
    ConnState.ERROR:        '#c33',
}

STATE_LABEL = {
    ConnState.DISCONNECTED: 'Disconnected',
    ConnState.CONNECTING:   'Connecting…',
    ConnState.CONNECTED:    'Connected',
    ConnState.ERROR:        'Error',
}


# ─────────────────────────────────────────────────────────────────────────────
# Router connection (telnet)
# ─────────────────────────────────────────────────────────────────────────────

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
        """Wait for any of the regexes (against ANSI-stripped text).
        Returns (text_so_far, matched_index or -1).
        The Keenetic CLI emits ANSI erase sequences (\\x1b[K) right after the
        prompt, so we must strip ANSI before regex matching or '$' anchors
        never match."""
        assert self.sock is not None
        self.sock.settimeout(0.3)
        buf = b''
        end = time.time() + timeout
        compiled = [re.compile(p) for p in patterns]
        def _check() -> tuple[str, int]:
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
                txt, idx = _check()
                if idx >= 0:
                    return txt, idx
            except socket.timeout:
                txt, idx = _check()
                if idx >= 0:
                    return txt, idx
        return strip_ansi(buf.decode('utf-8', 'replace')), -1

    def _read_until(self, pattern: str, timeout: float = 8.0) -> str:
        text, _ = self._read_until_any([pattern], timeout)
        return text

    def _send(self, line: str) -> None:
        assert self.sock is not None
        self.sock.sendall((line + '\n').encode())

    def login(self, user: str, password: str, timeout: float = 8.0) -> None:
        """Connect + authenticate. Fails fast on wrong password via multi-pattern wait."""
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
            # Wait for EITHER success, explicit failure message, or re-prompt
            out, idx = self._read_until_any([
                self.CONFIG_PROMPT,                              # 0 = success
                r'(?i)(fail|incorrect|invalid|locked|denied)',   # 1 = auth error msg
                r'(?im)^\s*login\s*:\s*$',                       # 2 = re-prompt = failed
            ], timeout)
            if idx == 0:
                self.connected = True
                combined = (banner1 or '') + (out or '')
                m = re.search(r'NDMS version\s+(\S+)', combined)
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
            try:
                if self.sock is not None:
                    self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.connected = False
            raise

    def close(self) -> None:
        if self.sock is not None:
            try:
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

    def run(self, cmd: str, timeout: float = 10.0) -> str:
        self._send(cmd)
        return self._read_until(self.CONFIG_PROMPT, timeout)

    def list_interfaces(self) -> list[dict]:
        out = self.run('show interface', timeout=15.0)
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
        return self.run('show running-config', timeout=20.0)

    def get_components(self) -> set[str]:
        """Parse `show version` to find installed firmware components.
        Result is a set of component names like {'sstp', 'wireguard', ...}.

        The 'components:' YAML-ish field spans multiple lines where each
        continuation line is indented more than the `components:` key line.
        We collect until indent drops back (next field) or EOF."""
        out = self.run('show version', timeout=10.0)
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
            # continuation?
            m2 = re.match(r'^(\s*)(\S.*)?$', ln)
            if not m2:
                break
            indent = len(m2.group(1))
            content = (m2.group(2) or '').strip()
            if content and indent > key_indent:
                parts.append(content)
            elif content:
                break  # next YAML field
        raw = re.sub(r'\s+', '', ','.join(parts))
        return {c for c in raw.split(',') if c}

    def get_interface_status(self, name: str) -> dict:
        """Return current status of an interface: type, link, connected."""
        for iface in self.list_interfaces():
            if iface.get('name') == name:
                return iface
        return {}

    def create_fqdn_group(self, name: str, entries: list[str],
                          description: str = '') -> list[str]:
        """Create/enter an object-group and include both FQDNs and IP/CIDR entries.
        Keenetic's object-group fqdn accepts all three as `include <x>` lines."""
        errs: list[str] = []
        self.run(f'object-group fqdn {name}')
        if description:
            # Keenetic requires descriptions with spaces/special chars to be
            # double-quoted. Strip any embedded quotes to avoid breaking the
            # parser, then always quote for safety.
            safe = description.replace('"', '').strip()
            if safe:
                out = self.run(f'description "{safe}"')
                if 'rror' in out or 'nvalid' in out.lower():
                    errs.append(f'description: {out.strip().splitlines()[-1] if out.strip() else "error"}')
        for entry in entries:
            out = self.run(f'include {entry}')
            if 'rror' in out or 'nvalid' in out.lower():
                errs.append(f'include {entry}: {out.strip().splitlines()[-1] if out.strip() else "error"}')
        self.run('exit')
        return errs

    def bind_fqdn_route(self, group: str, interface: str, auto: bool = True,
                        reject: bool = False) -> str:
        parts = [f'dns-proxy route object-group {group} {interface}']
        if auto:   parts.append('auto')
        if reject: parts.append('reject')
        return self.run(' '.join(parts))

    def delete_fqdn_group(self, name: str) -> str:
        self.run(f'no dns-proxy route object-group {name}')
        return self.run(f'no object-group fqdn {name}')

    def add_ip_route(self, network: str, mask: str, interface: str, auto: bool = True,
                     reject: bool = False) -> str:
        parts = [f'ip route {network} {mask} {interface}']
        if auto:   parts.append('auto')
        if reject: parts.append('reject')
        return self.run(' '.join(parts))

    def delete_ip_route(self, network: str, mask: str, interface: str) -> str:
        return self.run(f'no ip route {network} {mask} {interface}')

    def save_config(self) -> str:
        return self.run('system configuration save', timeout=15.0)

    # ── SSTP interface provisioning (VPN Gate and similar) ──────────────
    def find_free_sstp_index(self, existing: list[str]) -> int:
        """Return the next unused integer N for interface SSTP<N>, skipping
        existing interface names. Starts at 1 (0 is usually the user's
        primary, keep it alone)."""
        taken: set[int] = set()
        for name in existing:
            m = re.match(r'SSTP(\d+)$', name)
            if m:
                taken.add(int(m.group(1)))
        n = 1
        while n in taken:
            n += 1
        return n

    def create_sstp_interface(self, name: str, peer: str, user: str, password: str,
                               description: str = '', auto_connect: bool = True,
                               via_interface: str = '') -> list[str]:
        """Provision a new SSTP VPN-client interface on the router.
        name: e.g. 'SSTP1' (caller picks free slot)
        peer: hostname or IP of the SSTP server
        user/password: cleartext credentials (VPN Gate uses 'vpn'/'vpn')
        """
        errs: list[str] = []

        def check(out: str, step: str):
            if 'rror' in out and 'enewed' not in out:
                errs.append(f'{step}: {out.strip().splitlines()[-1] if out.strip() else "error"}')

        check(self.run(f'interface {name}'), f'interface {name}')
        if description:
            safe = description.replace('"', '').strip()
            if safe:
                check(self.run(f'description "{safe}"'), 'description')
        check(self.run(f'peer {peer}'),                                       'peer')
        check(self.run(f'authentication identity {user}'),                    'auth identity')
        check(self.run(f'authentication password {password}'),                'auth password')
        self.run('no ccp')
        self.run('ip mtu 1400')
        self.run('ip tcp adjust-mss pmtu')
        self.run('security-level public')
        self.run('ipcp default-route')
        self.run('ipcp dns-routes')
        self.run('ipcp address')
        if via_interface:
            self.run(f'connect via {via_interface}')
        if auto_connect:
            self.run('connect')
            self.run('up')
        self.run('exit')
        return errs

    def delete_interface(self, name: str) -> str:
        return self.run(f'no interface {name}')


# ─────────────────────────────────────────────────────────────────────────────
# Catalog
# ─────────────────────────────────────────────────────────────────────────────

class Catalog:
    def __init__(self, data: dict):
        self.data = data

    @property
    def version(self) -> str: return self.data.get('catalog_version', '?')
    @property
    def name(self) -> str:    return self.data.get('catalog_name', 'Unnamed catalog')
    @property
    def services(self) -> list[dict]: return self.data.get('services', [])

    def service(self, sid: str) -> Optional[dict]:
        for s in self.services:
            if s.get('id') == sid:
                return s
        return None

    @classmethod
    def load_default(cls) -> 'Catalog':
        path = resource_path('services.json')
        with open(path, 'r', encoding='utf-8') as f:
            return cls(json.load(f))

    @classmethod
    def load_url(cls, url: str, timeout: float = 10.0) -> 'Catalog':
        req = urllib.request.Request(url, headers={'User-Agent': f'{APP_NAME}/{APP_VERSION}'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        if data.get('schema_version') != 1:
            raise ValueError(f'Unsupported schema_version: {data.get("schema_version")}')
        return cls(data)


# ─────────────────────────────────────────────────────────────────────────────
# Running-config parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_running_config(cfg: str) -> dict:
    groups: dict[str, list[str]] = {}
    current_group: Optional[str] = None
    dns_routes: list[dict] = []
    ip_routes: list[dict] = []
    in_dns_proxy = False

    for raw in cfg.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if stripped == '!':
            current_group = None
            in_dns_proxy = False
            continue
        m = re.match(r'object-group fqdn (\S+)', stripped)
        if m:
            current_group = m.group(1)
            groups[current_group] = []
            continue
        if current_group and stripped.startswith('include '):
            groups[current_group].append(stripped.split(' ', 1)[1])
            continue
        if stripped == 'dns-proxy':
            in_dns_proxy = True
            continue
        if in_dns_proxy:
            m = re.match(r'route object-group (\S+) (\S+)(?:\s+(auto))?(?:\s+(reject))?', stripped)
            if m:
                dns_routes.append({'group': m.group(1), 'interface': m.group(2),
                                   'auto': m.group(3) == 'auto',
                                   'reject': m.group(4) == 'reject'})
                continue
        m = re.match(r'ip route (\S+) (\S+) (\S+)(?:\s+(auto))?(?:\s+(reject))?', stripped)
        if m:
            ip_routes.append({'network': m.group(1), 'mask': m.group(2),
                              'interface': m.group(3), 'auto': m.group(4) == 'auto',
                              'reject': m.group(5) == 'reject'})
    return {'groups': groups, 'dns_routes': dns_routes, 'ip_routes': ip_routes}


# ─────────────────────────────────────────────────────────────────────────────
# Background worker
# ─────────────────────────────────────────────────────────────────────────────

class Worker:
    def __init__(self, ui_queue: queue.Queue):
        self.ui_queue = ui_queue
        self.thread: Optional[threading.Thread] = None

    def busy(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def run(self, fn: Callable, *args, on_done: Optional[Callable] = None):
        if self.busy():
            self.ui_queue.put(('log', ('warn', 'Busy — another operation is in progress.')))
            return

        def target():
            try:
                result = fn(*args)
                self.ui_queue.put(('done', (on_done, result, None)))
            except Exception as e:
                self.ui_queue.put(('done', (on_done, None, e)))

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()


# ─────────────────────────────────────────────────────────────────────────────
# Application
# ─────────────────────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f'{APP_NAME} v{APP_VERSION}')
        self.minsize(960, 640)

        self.ui_cfg = load_ui_config()
        self.geometry(self.ui_cfg.get('geometry', '1180x760+100+80'))

        self.client: Optional[KeeneticClient] = None
        self.catalog: Catalog = Catalog.load_default()
        self.ui_queue: queue.Queue = queue.Queue()
        self.worker = Worker(self.ui_queue)
        self.interfaces: list[dict] = []
        self.state: dict = {'groups': {}, 'dns_routes': [], 'ip_routes': []}
        self.conn_state: ConnState = ConnState.DISCONNECTED

        self.svc_checked: dict[str, bool] = {}
        self.exclusive_var = tk.BooleanVar(value=bool(self.ui_cfg.get('exclusive', True)))

        self._init_style()
        self._build_ui()
        self._bind_hotkeys()
        self._set_state(ConnState.DISCONNECTED)
        self.protocol('WM_DELETE_WINDOW', self._on_close)
        self._drain_queue()

    # ── Styling ─────────────────────────────────────────────────────────────
    def _init_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use('vista' if sys.platform == 'win32' else 'clam')
        except Exception:
            pass
        # Emoji-capable font for tree (Segoe UI Emoji ships with Windows 10+)
        self._tree_font = tkfont.Font(family='Segoe UI', size=10)
        self._tree_font_bold = tkfont.Font(family='Segoe UI', size=10, weight='bold')
        self._label_font = tkfont.Font(family='Segoe UI', size=9)
        self._mono_font = tkfont.Font(family='Consolas', size=9)
        # Accent button style for primary Apply button
        style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('Status.TLabel', font=('Segoe UI', 9))

    # ── Layout ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        main_pane = ttk.PanedWindow(self, orient='vertical')
        main_pane.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self._main_pane = main_pane

        nb_holder = ttk.Frame(main_pane)
        main_pane.add(nb_holder, weight=4)

        nb = ttk.Notebook(nb_holder)
        nb.pack(fill='both', expand=True)
        self.nb = nb
        self.tab_services = ttk.Frame(nb)
        self.tab_state    = ttk.Frame(nb)
        self.tab_vpngate  = ttk.Frame(nb)
        self.tab_catalog  = ttk.Frame(nb)
        nb.add(self.tab_services, text='  Services  ')
        nb.add(self.tab_state,    text='  Current state  ')
        nb.add(self.tab_vpngate,  text='  VPN Gate  ')
        nb.add(self.tab_catalog,  text='  Catalog  ')
        self._build_services_tab()
        self._build_state_tab()
        self._build_vpngate_tab()
        self._build_catalog_tab()

        log_frame = ttk.LabelFrame(main_pane, text=' Log ')
        main_pane.add(log_frame, weight=1)
        # Log toolbar
        log_top = ttk.Frame(log_frame)
        log_top.pack(fill='x', padx=4, pady=(4, 0))
        ttk.Button(log_top, text='Copy all',
                   command=self._log_copy_all).pack(side='left')
        ttk.Button(log_top, text='Copy selection',
                   command=self._log_copy_selection).pack(side='left', padx=4)
        ttk.Button(log_top, text='Clear',
                   command=self._log_clear).pack(side='left', padx=4)
        ttk.Label(log_top, text='(Ctrl+A select all · Ctrl+C copy · right-click for menu)',
                  foreground='#888', style='Status.TLabel').pack(side='left', padx=12)
        self.log_box = scrolledtext.ScrolledText(
            log_frame, height=6,
            font=self._mono_font, wrap='word', relief='flat', borderwidth=0)
        self.log_box.pack(fill='both', expand=True, padx=4, pady=4)
        # Read-only but still selectable / copyable:
        def _log_block_keys(e):
            if e.state & 0x4:          # Ctrl held → let Ctrl+C/A/Insert through
                return
            if e.keysym in ('Left', 'Right', 'Up', 'Down', 'Home', 'End',
                            'Prior', 'Next', 'Shift_L', 'Shift_R',
                            'Control_L', 'Control_R', 'Tab'):
                return
            return 'break'
        self.log_box.bind('<Key>', _log_block_keys)
        self.log_box.bind('<Button-2>', lambda e: 'break')  # block middle-click paste
        self.log_box.bind('<Control-a>', lambda e: self._log_select_all())
        self.log_box.bind('<Control-A>', lambda e: self._log_select_all())
        self.log_box.bind('<Button-3>', self._log_context_menu)
        # Color tags for log levels
        self.log_box.tag_configure('info',  foreground='#333')
        self.log_box.tag_configure('ok',    foreground='#1e7e1e')
        self.log_box.tag_configure('warn',  foreground='#a05c00')
        self.log_box.tag_configure('err',   foreground='#a51818')
        self.log_box.tag_configure('ts',    foreground='#888')
        # Context menu
        self._log_menu = tk.Menu(self, tearoff=0)
        self._log_menu.add_command(label='Copy selection', command=self._log_copy_selection)
        self._log_menu.add_command(label='Copy all',       command=self._log_copy_all)
        self._log_menu.add_separator()
        self._log_menu.add_command(label='Select all',     command=self._log_select_all)
        self._log_menu.add_command(label='Clear',          command=self._log_clear)

    def _build_header(self):
        wrap = ttk.Frame(self, padding=(8, 8, 8, 4))
        wrap.pack(fill='x')

        # Status dot (colored ●) + label
        self.status_dot = tk.Label(wrap, text='●', fg=STATE_COLOR[ConnState.DISCONNECTED],
                                    bg=self.cget('background'), font=('Segoe UI', 14))
        self.status_dot.grid(row=0, column=0, rowspan=2, padx=(0, 6))
        self.status_label = ttk.Label(wrap, text=STATE_LABEL[ConnState.DISCONNECTED],
                                       style='Status.TLabel')
        self.status_label.grid(row=0, column=1, sticky='w', padx=(0, 12))

        ttk.Label(wrap, text='Host:').grid(row=0, column=2, sticky='e', padx=(8, 4))
        self.host_var = tk.StringVar(value=self.ui_cfg.get('last_host', DEFAULT_ROUTER))
        self.host_entry = ttk.Entry(wrap, textvariable=self.host_var, width=18)
        self.host_entry.grid(row=0, column=3, sticky='w')

        ttk.Label(wrap, text='User:').grid(row=0, column=4, sticky='e', padx=(12, 4))
        self.user_var = tk.StringVar(value=self.ui_cfg.get('last_user', DEFAULT_USER))
        self.user_entry = ttk.Entry(wrap, textvariable=self.user_var, width=12)
        self.user_entry.grid(row=0, column=5, sticky='w')

        ttk.Label(wrap, text='Password:').grid(row=0, column=6, sticky='e', padx=(12, 4))
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(wrap, textvariable=self.pass_var, show='•', width=18)
        self.pass_entry.grid(row=0, column=7, sticky='w')

        self.btn_connect = ttk.Button(wrap, text='Connect', command=self._on_connect_click,
                                       width=12)
        self.btn_connect.grid(row=0, column=8, padx=10)

        # Row 2: interface + info
        ttk.Label(wrap, text='Interface:').grid(row=1, column=2, sticky='e', padx=(8, 4), pady=(4, 0))
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(wrap, textvariable=self.iface_var, state='disabled',
                                         width=22)
        self.iface_combo.grid(row=1, column=3, columnspan=2, sticky='w', pady=(4, 0))

        self.info_var = tk.StringVar(value='')
        ttk.Label(wrap, textvariable=self.info_var, foreground='#555',
                  style='Status.TLabel').grid(row=1, column=5, columnspan=4,
                                              sticky='w', padx=(12, 0), pady=(4, 0))

        # Warning banner — sits between the header and the notebook.
        self.warn_frame = ttk.Frame(self, padding=(8, 4))
        self.warn_frame.pack(fill='x', padx=8, pady=(0, 4))
        self.warn_frame.pack_forget()  # hidden until there's something to show
        self.warn_label = tk.Label(self.warn_frame, text='', bg='#fff3cd',
                                    fg='#664d03', font=('Segoe UI', 9),
                                    anchor='w', padx=10, pady=6, justify='left',
                                    wraplength=1000)
        self.warn_label.pack(fill='x')

    # ── Services tab ────────────────────────────────────────────────────────
    def _build_services_tab(self):
        f = self.tab_services

        top = ttk.Frame(f, padding=(0, 4))
        top.pack(fill='x', padx=4, pady=(4, 0))

        ttk.Button(top, text='Select all', width=10,
                   command=lambda: self._toggle_all_services(True)).pack(side='left', padx=(0, 4))
        ttk.Button(top, text='Clear',      width=8,
                   command=lambda: self._toggle_all_services(False)).pack(side='left', padx=2)
        ttk.Button(top, text='Select applied', width=14,
                   command=self._select_applied).pack(side='left', padx=2)

        ttk.Label(top, text='Show:').pack(side='left', padx=(12, 2))
        self.svc_filter_var = tk.StringVar(value='All')
        flt = ttk.Combobox(top, textvariable=self.svc_filter_var,
                            values=('All', 'Applied', 'Drifted', 'Not applied', 'Ticked'),
                            state='readonly', width=12)
        flt.pack(side='left')
        flt.bind('<<ComboboxSelected>>', lambda e: self._populate_services())

        self.svc_summary_var = tk.StringVar(value='')
        ttk.Label(top, textvariable=self.svc_summary_var, foreground='#555',
                  style='Status.TLabel').pack(side='left', padx=12)

        self.btn_apply = ttk.Button(top, text='▶  Apply  (Ctrl+Enter)',
                                     command=self._on_apply_services,
                                     style='Accent.TButton')
        self.btn_apply.pack(side='right', padx=(8, 0))
        ttk.Checkbutton(top, text='Exclusive / Kill switch',
                        variable=self.exclusive_var).pack(side='right', padx=10)

        svc_pane = ttk.PanedWindow(f, orient='horizontal')
        svc_pane.pack(fill='both', expand=True, padx=4, pady=4)

        # Left: tree with checkbox column
        tree_frame = ttk.Frame(svc_pane)
        svc_pane.add(tree_frame, weight=3)

        self.svc_tree = ttk.Treeview(
            tree_frame,
            columns=('check', 'fqdn', 'ipv4', 'applied'),
            show='tree headings', selectmode='browse', height=20)
        self.svc_tree.heading('#0',      text='Category / Service')
        self.svc_tree.heading('check',   text='✓')
        self.svc_tree.heading('fqdn',    text='FQDN')
        self.svc_tree.heading('ipv4',    text='IPv4')
        self.svc_tree.heading('applied', text='State')
        self.svc_tree.column('#0',      width=300, anchor='w')
        self.svc_tree.column('check',   width=36,  stretch=False, anchor='center')
        self.svc_tree.column('fqdn',    width=55,  stretch=False, anchor='e')
        self.svc_tree.column('ipv4',    width=55,  stretch=False, anchor='e')
        self.svc_tree.column('applied', width=110, stretch=False, anchor='center')

        self.svc_tree.tag_configure('category',  font=self._tree_font_bold, background='#eef2f7')
        self.svc_tree.tag_configure('applied',   foreground='#0a6b0a', background='#dff5df')
        self.svc_tree.tag_configure('drifted',   foreground='#8a4500', background='#ffeccc')
        self.svc_tree.tag_configure('stripe',    background='#fafafa')

        self.svc_tree.pack(side='left', fill='both', expand=True)
        yscroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.svc_tree.yview)
        yscroll.pack(side='right', fill='y')
        self.svc_tree.configure(yscrollcommand=yscroll.set)

        self.svc_tree.bind('<Button-1>',       self._on_svc_click)
        self.svc_tree.bind('<<TreeviewSelect>>', self._on_svc_select)

        # Right: details panel
        right = ttk.LabelFrame(svc_pane, text=' Details ')
        svc_pane.add(right, weight=2)
        self.svc_details = scrolledtext.ScrolledText(
            right, state='disabled', font=self._label_font, wrap='word',
            relief='flat', padx=8, pady=8)
        self.svc_details.pack(fill='both', expand=True)
        self.svc_details.tag_configure('h1', font=('Segoe UI', 12, 'bold'), spacing3=6)
        self.svc_details.tag_configure('h2', font=('Segoe UI', 9, 'bold'), spacing1=8, spacing3=2)
        self.svc_details.tag_configure('mono', font=self._mono_font)
        self.svc_details.tag_configure('muted', foreground='#888')
        self.svc_details.tag_configure('ok',    foreground='#1e7e1e')
        self.svc_details.tag_configure('warn',  foreground='#a05c00')

        self._populate_services()
        self._set_details_placeholder()

    def _populate_services(self):
        self.svc_tree.delete(*self.svc_tree.get_children())
        flt = getattr(self, 'svc_filter_var', None)
        filter_mode = flt.get() if flt else 'All'

        # Global counters (not filtered) for the summary line
        all_applied = all_drifted = 0
        for s in self.catalog.services:
            st, _ = self._svc_state(s)
            if st == 'applied': all_applied += 1
            elif st == 'drifted': all_drifted += 1

        by_cat: dict[str, list[dict]] = {}
        for svc in self.catalog.services:
            by_cat.setdefault(svc.get('category', 'Other'), []).append(svc)

        shown = 0
        stripe = False
        for cat in sorted(by_cat.keys()):
            # Decide which services in this category to show
            visible = []
            for svc in by_cat[cat]:
                state, _ = self._svc_state(svc)
                checked = self.svc_checked.get(svc['id'], False)
                if filter_mode == 'Applied' and state != 'applied':
                    continue
                if filter_mode == 'Drifted' and state != 'drifted':
                    continue
                if filter_mode == 'Not applied' and state in ('applied', 'drifted'):
                    continue
                if filter_mode == 'Ticked' and not checked:
                    continue
                visible.append((svc, state, checked))
            if not visible:
                continue

            icon = CATEGORY_ICON.get(cat, '📦')
            cat_id = f'cat::{cat}'
            self.svc_tree.insert('', 'end', iid=cat_id,
                                  text=f'  {icon}  {cat}  ({len(visible)})',
                                  values=('', '', '', ''),
                                  tags=('category',),
                                  open=True)
            for svc, state, checked in visible:
                tags: tuple = ('stripe',) if stripe else ()
                if state == 'applied':
                    tags = tags + ('applied',)
                elif state == 'drifted':
                    tags = tags + ('drifted',)
                status_icon = {'applied': '✓ ', 'drifted': '⚠ ', '': '◯ '}[state]
                _, label = self._svc_state(svc)
                self.svc_tree.insert(cat_id, 'end', iid=f'svc::{svc["id"]}',
                                      text=f'    {status_icon} {svc["name"]}',
                                      values=('☑' if checked else '☐',
                                              len(svc.get('fqdn', [])),
                                              len(svc.get('ipv4_cidr', [])),
                                              label),
                                      tags=tags)
                stripe = not stripe
                shown += 1

        total = len(self.catalog.services)
        not_applied = total - all_applied - all_drifted
        parts = [f'✓ {all_applied} applied', f'⚠ {all_drifted} drifted',
                 f'◯ {not_applied} not applied',
                 f'total {total}']
        if filter_mode != 'All':
            parts.append(f'showing {shown}')
        self.svc_summary_var.set('  ·  '.join(parts))

    def _svc_state(self, svc: dict) -> tuple[str, str]:
        """Return (state, label) where state is 'applied'|'drifted'|''."""
        sid = svc['id']
        if sid not in self.state.get('groups', {}):
            return '', ''
        route = next((r for r in self.state.get('dns_routes', []) if r['group'] == sid), None)
        if not route:
            return 'drifted', '● orphaned group'
        cat_inc = self._svc_includes(svc)
        rtr_inc = set(self.state['groups'].get(sid, []))
        has_legacy = bool(self._svc_legacy_routes(svc))
        flags = []
        if route.get('reject'):
            flags.append('kill')
        label_suffix = f' ({",".join(flags)})' if flags else ''
        if cat_inc == rtr_inc and not has_legacy:
            return 'applied', f'● {route["interface"]}{label_suffix}'
        return 'drifted', f'⚠ {route["interface"]}{label_suffix} · drift'

    def _select_applied(self):
        """Tick all services that are currently present on the router."""
        for svc in self.catalog.services:
            state, _ = self._svc_state(svc)
            self.svc_checked[svc['id']] = state in ('applied', 'drifted')
        self._populate_services()

    def _on_svc_click(self, event):
        region = self.svc_tree.identify('region', event.x, event.y)
        col = self.svc_tree.identify_column(event.x)
        iid = self.svc_tree.identify_row(event.y)
        if not iid or not iid.startswith('svc::'):
            return
        # Only toggle on clicks in the 'check' column (column #1) OR the name column.
        if col in ('#1',):  # check column
            sid = iid.split('::', 1)[1]
            self.svc_checked[sid] = not self.svc_checked.get(sid, False)
            vals = list(self.svc_tree.item(iid, 'values'))
            vals[0] = '☑' if self.svc_checked[sid] else '☐'
            self.svc_tree.item(iid, values=vals)

    def _on_svc_select(self, event=None):
        sel = self.svc_tree.selection()
        if not sel:
            return
        iid = sel[0]
        if iid.startswith('svc::'):
            sid = iid.split('::', 1)[1]
            svc = self.catalog.service(sid)
            if svc is not None:
                self._show_service_details(svc)
        elif iid.startswith('cat::'):
            self._set_details_placeholder()

    def _show_service_details(self, svc: dict):
        t = self.svc_details
        t.configure(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', f'{svc["name"]}\n', 'h1')
        t.insert('end', f'{svc.get("category", "Other")} · id = {svc["id"]}\n', 'muted')
        if svc.get('description'):
            t.insert('end', f'\n{svc["description"]}\n')
        sources = []
        for u in svc.get('upstream', []) or []:
            sources.append(f'{u.get("type", "?")}:{u.get("url", "").rsplit("/", 1)[-1]}')
        for p in svc.get('ipv4_providers', []) or []:
            sources.append(p)
        for a in svc.get('asn', []) or []:
            sources.append(f'AS{a}')
        if sources:
            t.insert('end', '\nUpstream sources: ', 'h2')
            t.insert('end', ', '.join(sources) + '\n', 'mono')
            btn = ttk.Button(t, text='⟳ Refresh this service from upstream',
                              command=lambda s=svc: self._on_refresh_upstream_one(s))
            t.window_create('end', window=btn)
            t.insert('end', '\n')
        state, label = self._svc_state(svc)
        if state == 'applied':
            t.insert('end', '\nApplied on router: ', 'h2')
            t.insert('end', label + '\n', 'ok')
        elif state == 'drifted':
            t.insert('end', '\nApplied with drift: ', 'h2')
            t.insert('end', label + '\n', 'warn')
            cat_inc = self._svc_includes(svc)
            rtr_inc = set(self.state['groups'].get(svc['id'], []))
            missing = cat_inc - rtr_inc
            extra   = rtr_inc - cat_inc
            if missing:
                t.insert('end', f'  missing on router: {", ".join(sorted(missing))}\n', 'mono')
            if extra:
                t.insert('end', f'  extra on router:   {", ".join(sorted(extra))}\n', 'mono')
            legacy = self._svc_legacy_routes(svc)
            if legacy:
                t.insert('end',
                         f'  legacy ip routes to migrate: '
                         f'{", ".join(f"{r["network"]}/{r["mask"]} via {r["interface"]}" for r in legacy)}\n',
                         'mono')
        else:
            t.insert('end', '\nNot applied on router.\n', 'muted')
        t.insert('end', f'\nFQDN ({len(svc.get("fqdn", []))}):\n', 'h2')
        for d in svc.get('fqdn', []):
            t.insert('end', f'  {d}\n', 'mono')
        if svc.get('ipv4_cidr'):
            t.insert('end', f'\nIPv4 ({len(svc["ipv4_cidr"])}):\n', 'h2')
            for c in svc['ipv4_cidr']:
                t.insert('end', f'  {c}\n', 'mono')
        t.configure(state='disabled')

    def _set_details_placeholder(self):
        t = self.svc_details
        t.configure(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', 'Pick a service on the left to see details.\n', 'muted')
        t.configure(state='disabled')

    def _toggle_all_services(self, on: bool):
        for svc in self.catalog.services:
            self.svc_checked[svc['id']] = on
        self._populate_services()

    # ── Current state tab ──────────────────────────────────────────────────
    def _build_state_tab(self):
        f = self.tab_state
        top = ttk.Frame(f, padding=(0, 4))
        top.pack(fill='x', padx=4, pady=(4, 0))
        ttk.Button(top, text='Refresh (F5)',   command=self._on_refresh_state).pack(side='left', padx=2)
        ttk.Button(top, text='Delete selected', command=self._on_delete_selected).pack(side='left', padx=2)
        ttk.Button(top, text='Save config',    command=self._on_save_config).pack(side='left', padx=12)
        self.state_summary_var = tk.StringVar(value='')
        ttk.Label(top, textvariable=self.state_summary_var, foreground='#555',
                  style='Status.TLabel').pack(side='right', padx=4)

        tree_frame = ttk.Frame(f)
        tree_frame.pack(fill='both', expand=True, padx=4, pady=4)
        self.state_tree = ttk.Treeview(
            tree_frame, columns=('details',), show='tree headings', height=20)
        self.state_tree.heading('#0',      text='Item')
        self.state_tree.heading('details', text='Details')
        self.state_tree.column('#0',      width=340, anchor='w')
        self.state_tree.column('details', width=560, anchor='w')
        self.state_tree.tag_configure('section', font=self._tree_font_bold,
                                       background='#eef2f7')
        self.state_tree.tag_configure('exclusive', foreground='#1e7e1e')
        self.state_tree.tag_configure('unprotected', foreground='#a05c00')
        self.state_tree.pack(side='left', fill='both', expand=True)
        yscroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.state_tree.yview)
        yscroll.pack(side='right', fill='y')
        self.state_tree.configure(yscrollcommand=yscroll.set)

    def _refresh_state_view(self):
        self.state_tree.delete(*self.state_tree.get_children())
        groups = self.state['groups']
        dns_routes = self.state['dns_routes']
        ip_routes = self.state['ip_routes']

        g_root = self.state_tree.insert('', 'end', iid='sect::fqdn',
                                         text=f'  📁  FQDN groups ({len(groups)})',
                                         values=('',), open=True, tags=('section',))
        for g, domains in sorted(groups.items()):
            route = next((r for r in dns_routes if r['group'] == g), None)
            if route:
                flags = []
                if route.get('auto'):   flags.append('auto')
                if route.get('reject'): flags.append('exclusive (kill switch)')
                details = f'→ {route["interface"]}  [{", ".join(flags) if flags else "—"}]'
                tag = ('exclusive',) if route.get('reject') else ('unprotected',)
            else:
                details = 'not bound to any route'
                tag = ('unprotected',)
            node = self.state_tree.insert(g_root, 'end', iid=f'group::{g}',
                                           text=f'      {g}  ·  {len(domains)} domains',
                                           values=(details,), tags=tag)
            for d in domains:
                self.state_tree.insert(node, 'end', text=f'            {d}', values=('',))

        r_root = self.state_tree.insert('', 'end', iid='sect::ip',
                                         text=f'  🌐  IP routes ({len(ip_routes)})',
                                         values=('',), open=True, tags=('section',))
        for i, r in enumerate(ip_routes):
            flags = []
            if r.get('auto'):   flags.append('auto')
            if r.get('reject'): flags.append('exclusive (kill switch)')
            tag = ('exclusive',) if r.get('reject') else ('unprotected',)
            self.state_tree.insert(r_root, 'end', iid=f'iproute::{i}',
                                    text=f'      {r["network"]}/{r["mask"]}',
                                    values=(f'→ {r["interface"]}  [{", ".join(flags) if flags else "—"}]',),
                                    tags=tag)

        # Summary
        exc_groups = sum(1 for r in dns_routes if r.get('reject'))
        exc_ips    = sum(1 for r in ip_routes if r.get('reject'))
        self.state_summary_var.set(
            f'{len(groups)} FQDN groups ({exc_groups} exclusive) · '
            f'{len(ip_routes)} IP routes ({exc_ips} exclusive)')

    # ── VPN Gate tab (split into Bootstrap / Live sub-tabs for laptops) ───
    def _build_vpngate_tab(self):
        f = self.tab_vpngate
        inner = ttk.Notebook(f)
        inner.pack(fill='both', expand=True)
        self.tab_vpngate_bootstrap = ttk.Frame(inner)
        self.tab_vpngate_live      = ttk.Frame(inner)
        inner.add(self.tab_vpngate_bootstrap, text='  Bootstrap servers  ')
        inner.add(self.tab_vpngate_live,      text='  Live list  ')
        self._build_vpngate_bootstrap_tab()
        self._build_vpngate_live_tab()

    def _build_vpngate_bootstrap_tab(self):
        f = self.tab_vpngate_bootstrap
        subnets = len({'.'.join(s['ip'].split('.')[:3]) for s in BOOTSTRAP_VPNGATE_SERVERS})
        ttk.Label(f,
                  text=f'{len(BOOTSTRAP_VPNGATE_SERVERS)} built-in servers across {subnets} distinct /24 subnets. '
                       'Use these to bootstrap an SSTP tunnel when vpngate.net is blocked on your ISP. '
                       'Credentials are the VPN Gate defaults: vpn / vpn.',
                  foreground='#555', wraplength=1100, justify='left'
                  ).pack(anchor='w', padx=6, pady=(6, 4))

        toolbar = ttk.Frame(f)
        toolbar.pack(fill='x', padx=4, pady=(0, 4))
        ttk.Button(toolbar, text='🔍 Test reachability',
                   command=self._bootstrap_test_all).pack(side='left')
        ttk.Button(toolbar, text='▶ Create SSTP interface from selected',
                   command=self._bootstrap_create_interface,
                   style='Accent.TButton').pack(side='left', padx=(6, 0))
        self.bootstrap_status_var = tk.StringVar(value='Not tested yet')
        ttk.Label(toolbar, textvariable=self.bootstrap_status_var, foreground='#555',
                  style='Status.TLabel').pack(side='left', padx=10)

        tf = ttk.Frame(f)
        tf.pack(fill='both', expand=True, padx=4, pady=4)
        cols = ('reach', 'country', 'host', 'ip', 'mbps', 'uptime', 'op')
        self.bootstrap_tree = ttk.Treeview(tf, columns=cols, show='headings',
                                             selectmode='browse')
        headings = {'reach': 'Reach', 'country': 'Country', 'host': 'Host',
                    'ip': 'IP', 'mbps': 'Mbps', 'uptime': 'Up d', 'op': 'Operator'}
        widths = {'reach': 80, 'country': 70, 'host': 150, 'ip': 120,
                  'mbps': 65, 'uptime': 55, 'op': 280}
        for c in cols:
            self.bootstrap_tree.heading(c, text=headings[c],
                command=lambda col=c: self._bootstrap_sort(col))
            self.bootstrap_tree.column(c, width=widths[c],
                anchor='e' if c in ('mbps', 'uptime') else 'w')
        self.bootstrap_tree.tag_configure('reach_ok', background='#dff5df')
        self.bootstrap_tree.tag_configure('reach_bad', background='#ffe0e0')
        self.bootstrap_tree.pack(side='left', fill='both', expand=True)
        ysc = ttk.Scrollbar(tf, orient='vertical', command=self.bootstrap_tree.yview)
        ysc.pack(side='right', fill='y')
        self.bootstrap_tree.configure(yscrollcommand=ysc.set)
        self.bootstrap_reach_results: dict = {}
        self.bootstrap_sort_col = 'uptime'
        self.bootstrap_sort_rev = True
        self._bootstrap_populate()

    def _build_vpngate_live_tab(self):
        f = self.tab_vpngate_live
        ttk.Label(f,
                  text='Live list from vpngate.net. Requires vpngate.net to be routable — '
                       'if blocked, use a Bootstrap server first, tick the "VPN Gate (vpngate.net)" '
                       'service and Apply, then come back here.',
                  foreground='#555', wraplength=1100, justify='left'
                  ).pack(anchor='w', padx=6, pady=(6, 4))

        toolbar = ttk.Frame(f)
        toolbar.pack(fill='x', padx=4, pady=(0, 4))
        ttk.Button(toolbar, text='⟳ Refresh',
                   command=self._on_vpngate_refresh,
                   style='Accent.TButton').pack(side='left')
        self.vpngate_status_var = tk.StringVar(value='Not loaded yet')
        ttk.Label(toolbar, textvariable=self.vpngate_status_var, foreground='#555',
                  style='Status.TLabel').pack(side='left', padx=10)

        filt = ttk.Frame(f)
        filt.pack(fill='x', padx=4, pady=(0, 4))
        ttk.Label(filt, text='Country:').pack(side='left')
        self.vpngate_country_var = tk.StringVar(value='Any')
        self.vpngate_country_combo = ttk.Combobox(filt, textvariable=self.vpngate_country_var,
                                                   state='readonly', width=18)
        self.vpngate_country_combo.pack(side='left', padx=(4, 8))
        self.vpngate_country_combo.bind('<<ComboboxSelected>>', lambda e: self._vpngate_repaint())
        ttk.Label(filt, text='Max ping:').pack(side='left')
        self.vpngate_ping_var = tk.StringVar(value='1000')
        ttk.Entry(filt, textvariable=self.vpngate_ping_var, width=6).pack(side='left', padx=(4, 8))
        ttk.Label(filt, text='Min Mbps:').pack(side='left')
        self.vpngate_speed_var = tk.StringVar(value='5')
        ttk.Entry(filt, textvariable=self.vpngate_speed_var, width=6).pack(side='left', padx=(4, 8))
        self.vpngate_nolog_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(filt, text='No-logs only',
                        variable=self.vpngate_nolog_var,
                        command=self._vpngate_repaint).pack(side='left', padx=(0, 8))
        ttk.Button(filt, text='Apply',
                   command=self._vpngate_repaint).pack(side='left')

        tf = ttk.Frame(f)
        tf.pack(fill='both', expand=True, padx=4, pady=4)
        cols = ('country', 'host', 'ip', 'ping', 'mbps', 'uptime', 'sessions', 'log', 'op')
        self.vpngate_tree = ttk.Treeview(tf, columns=cols,
                                           show='headings', selectmode='browse')
        headings = {'country': 'Country', 'host': 'Hostname', 'ip': 'IP',
                    'ping': 'Ping', 'mbps': 'Mbps', 'uptime': 'Up d',
                    'sessions': 'Users', 'log': 'Log policy', 'op': 'Operator'}
        widths = {'country': 75, 'host': 180, 'ip': 120, 'ping': 55, 'mbps': 65,
                  'uptime': 55, 'sessions': 55, 'log': 80, 'op': 210}
        for c in cols:
            self.vpngate_tree.heading(c, text=headings[c],
                                       command=lambda col=c: self._vpngate_sort(col))
            self.vpngate_tree.column(c, width=widths[c],
                anchor='w' if c in ('country', 'host', 'ip', 'op', 'log') else 'e')
        self.vpngate_tree.pack(side='left', fill='both', expand=True)
        ysc = ttk.Scrollbar(tf, orient='vertical', command=self.vpngate_tree.yview)
        ysc.pack(side='right', fill='y')
        self.vpngate_tree.configure(yscrollcommand=ysc.set)
        self.vpngate_tree.bind('<<TreeviewSelect>>', lambda e: self._vpngate_on_select())

        act = ttk.Frame(f)
        act.pack(fill='x', padx=4, pady=(0, 4))
        ttk.Button(act, text='Copy host:port',
                   command=self._vpngate_copy_host).pack(side='left')
        ttk.Button(act, text='Copy creds (vpn/vpn)',
                   command=self._vpngate_copy_creds).pack(side='left', padx=(4, 0))
        self.btn_vpngate_create = ttk.Button(
            act, text='▶ Create SSTP interface on router',
            command=self._vpngate_create_interface,
            style='Accent.TButton')
        self.btn_vpngate_create.pack(side='right')

        self.vpngate_all: list[dict] = []
        self.vpngate_shown: list[dict] = []
        self.vpngate_sort_col = 'mbps'
        self.vpngate_sort_rev = True
        cached = CACHE.get('vpngate', TTL_VPNGATE * 6)
        if cached:
            self.vpngate_all = cached
            self._vpngate_populate_country_filter()
            self._vpngate_repaint()
            age = CACHE.age('vpngate') or 0
            self.vpngate_status_var.set(f'{len(cached)} servers (cached, {int(age/60)} min old)')

    # ── Bootstrap helpers ─────────────────────────────────────────────────
    def _bootstrap_populate(self, results: Optional[dict] = None):
        """Render the bootstrap table. results: {host: (reachable, rtt_ms)}."""
        if results is not None:
            self.bootstrap_reach_results = results
        self.bootstrap_tree.delete(*self.bootstrap_tree.get_children())

        # Sort copy of the bootstrap list for display
        sort_col = getattr(self, 'bootstrap_sort_col', 'uptime')
        rev = getattr(self, 'bootstrap_sort_rev', True)
        key_map = {'reach': lambda s: (1 if self.bootstrap_reach_results.get(s['host'], (False, -1))[0] else 0,
                                        -(self.bootstrap_reach_results.get(s['host'], (False, 99999))[1] or 99999)),
                   'country': lambda s: s['country'],
                   'host':    lambda s: s['host'],
                   'ip':      lambda s: tuple(int(o) for o in s['ip'].split('.')),
                   'mbps':    lambda s: s.get('speed_mbps', 0),
                   'uptime':  lambda s: s.get('uptime_days', 0),
                   'op':      lambda s: s.get('operator', '')}
        key = key_map.get(sort_col, key_map['uptime'])
        rows = sorted(BOOTSTRAP_VPNGATE_SERVERS, key=key, reverse=rev)

        for s in rows:
            if not self.bootstrap_reach_results:
                reach = '—'
                tag: tuple = ()
            else:
                ok, rtt = self.bootstrap_reach_results.get(s['host'], (False, -1))
                if ok:
                    reach = f'✓ {int(rtt)} ms'
                    tag = ('reach_ok',)
                else:
                    reach = '✗ blocked'
                    tag = ('reach_bad',)
            self.bootstrap_tree.insert('', 'end', iid=f'boot::{s["host"]}',
                values=(reach,
                        f'{s["country"]} {s["country_long"]}',
                        s['host'], s['ip'], s['speed_mbps'],
                        s['uptime_days'], s.get('operator', '')),
                tags=tag)

    def _bootstrap_sort(self, col: str):
        if self.bootstrap_sort_col == col:
            self.bootstrap_sort_rev = not self.bootstrap_sort_rev
        else:
            self.bootstrap_sort_col = col
            self.bootstrap_sort_rev = col in ('mbps', 'uptime', 'reach')
        self._bootstrap_populate()

    def _bootstrap_test_all(self):
        self.bootstrap_status_var.set('Testing TCP reachability on port 443…')
        # Clear previous results so rows show as "—" during the run
        self.bootstrap_reach_results = {}
        self._bootstrap_populate()

        def do():
            results: dict[str, tuple[bool, float]] = {}
            for s in BOOTSTRAP_VPNGATE_SERVERS:
                target = s.get('ip') or s['host']
                results[s['host']] = check_tcp_reachable(target, 443, timeout=3.0)
            return results

        def done(result, err):
            if err is not None:
                self.log(f'Reachability test failed: {err}', 'err')
                return
            self._bootstrap_populate(result)
            ok_count = sum(1 for v in result.values() if v[0])
            self.bootstrap_status_var.set(
                f'{ok_count}/{len(result)} reachable from this PC')
            self.log(f'Bootstrap reachability: {ok_count}/{len(result)} servers up.',
                     'ok' if ok_count else 'warn')
            # When results arrive, sort by reach so reachable ones bubble to top
            self.bootstrap_sort_col = 'reach'
            self.bootstrap_sort_rev = True
            self._bootstrap_populate()

        self.worker.run(do, on_done=done)

    def _bootstrap_create_interface(self):
        if not self._ensure_connected():
            return
        comps = self.client.router_info.get('components') or set()
        if comps and 'sstp' not in comps:
            messagebox.showerror(
                APP_NAME,
                'SSTP client component is not installed on the router. '
                'Install it via the web UI (Components page), reboot, then retry.')
            return
        sel = self.bootstrap_tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME,
                'Select a bootstrap server in the table first.\n\n'
                'Tip: click "Test reachability" to see which ones are reachable.')
            return
        host_id = sel[0].split('::', 1)[1]
        server = next((s for s in BOOTSTRAP_VPNGATE_SERVERS if s['host'] == host_id), None)
        if not server:
            return
        existing_names = [i['name'] for i in self.interfaces]
        idx = self.client.find_free_sstp_index(existing_names)
        new_name = f'SSTP{idx}'
        # Use the IP directly — bootstrap hosts are chosen with stable IPs to
        # avoid relying on the user's DNS resolving an external hostname.
        peer = server.get('ip') or server['host']
        desc = f'VPN Gate bootstrap {server["country"]} {server["host"]}'
        if not messagebox.askyesno(
                APP_NAME,
                f'Create SSTP interface "{new_name}" using bootstrap server?\n\n'
                f'Peer:     {peer}\n'
                f'Country:  {server["country_long"]}\n'
                f'Speed:    {server["speed_mbps"]} Mbps\n'
                f'Uptime:   {server["uptime_days"]} days\n'
                f'Creds:    vpn / vpn\n\n'
                'The interface will connect immediately.'):
            return
        self.log(f'Creating {new_name} from bootstrap server {host_id} ({peer})…')

        def do():
            errs = self.client.create_sstp_interface(
                new_name, peer=peer, user='vpn', password='vpn',
                description=desc, auto_connect=True)
            self.client.save_config()
            ifaces = self.client.list_interfaces()
            return new_name, ifaces, errs

        def done(result, err):
            if err is not None:
                self.log(f'Create interface failed: {err}', 'err')
                messagebox.showerror(APP_NAME, str(err))
                return
            new_name, ifaces, errs = result
            self.interfaces = ifaces
            names = [i['name'] for i in ifaces]
            self.iface_combo.configure(values=names, state='readonly')
            if new_name in names:
                self.iface_var.set(new_name)
            for e in errs:
                self.log(f'  {new_name}: {e}', 'warn')
            self.log(f'✓ Created {new_name}. Selected as current interface.', 'ok')
            self._update_warnings()
            messagebox.showinfo(
                APP_NAME,
                f'Interface {new_name} created.\n\n'
                'Next steps:\n'
                '1) Tick the "VPN Gate (vpngate.net)" service on Services tab and Apply — '
                'this will make vpngate.net reachable through this new tunnel.\n'
                '2) Then the Live list on this tab can be refreshed from the real API.')

        self.worker.run(do, on_done=done)

    def _on_vpngate_refresh(self):
        self.vpngate_status_var.set('Fetching…')

        def do():
            return fetch_vpngate(force=True)

        def done(result, err):
            if err is not None:
                self.vpngate_status_var.set(f'Fetch failed: {err}')
                self.log(f'VPN Gate fetch failed: {err}', 'err')
                return
            self.vpngate_all = result
            self._vpngate_populate_country_filter()
            self._vpngate_repaint()
            self.vpngate_status_var.set(f'{len(result)} servers (fresh)')
            self.log(f'VPN Gate: {len(result)} servers loaded.', 'ok')

        self.worker.run(do, on_done=done)

    def _vpngate_populate_country_filter(self):
        countries = sorted({s.get('CountryLong', '') for s in self.vpngate_all if s.get('CountryLong')})
        self.vpngate_country_combo.configure(values=['Any'] + countries)

    def _vpngate_repaint(self):
        self.vpngate_tree.delete(*self.vpngate_tree.get_children())
        try: max_ping = int(self.vpngate_ping_var.get() or '99999')
        except ValueError: max_ping = 99999
        try: min_mbps = float(self.vpngate_speed_var.get() or '0')
        except ValueError: min_mbps = 0
        country = self.vpngate_country_var.get().strip()
        nolog = self.vpngate_nolog_var.get()
        out = []
        for s in self.vpngate_all:
            if country and country != 'Any' and s.get('CountryLong') != country:
                continue
            if s.get('Ping', 0) > max_ping:
                continue
            if s.get('SpeedMbps', 0) < min_mbps:
                continue
            if nolog and 'no logs' not in (s.get('LogType', '') or '').lower():
                continue
            out.append(s)
        # Sort
        key_map = {'country': 'CountryShort', 'host': 'HostName', 'ip': 'IP',
                   'ping': 'Ping', 'mbps': 'SpeedMbps', 'uptime': 'UptimeDays',
                   'sessions': 'NumVpnSessions', 'log': 'LogType', 'op': 'Operator'}
        key = key_map.get(self.vpngate_sort_col, 'SpeedMbps')
        out.sort(key=lambda r: (r.get(key, 0) if isinstance(r.get(key), (int, float)) else str(r.get(key, ''))),
                 reverse=self.vpngate_sort_rev)
        self.vpngate_shown = out
        for s in out:
            self.vpngate_tree.insert('', 'end', iid=s['HostName'],
                values=(
                    f'{s.get("CountryShort","")} {s.get("CountryLong","")}',
                    s.get('HostName', ''),
                    s.get('IP', ''),
                    s.get('Ping', 0),
                    s.get('SpeedMbps', 0),
                    s.get('UptimeDays', 0),
                    s.get('NumVpnSessions', 0),
                    (s.get('LogType', '') or '')[:30],
                    (s.get('Operator', '') or '')[:40],
                ))

    def _vpngate_sort(self, col: str):
        if self.vpngate_sort_col == col:
            self.vpngate_sort_rev = not self.vpngate_sort_rev
        else:
            self.vpngate_sort_col = col
            self.vpngate_sort_rev = col in ('mbps', 'uptime', 'sessions')
        self._vpngate_repaint()

    def _vpngate_selected(self) -> Optional[dict]:
        sel = self.vpngate_tree.selection()
        if not sel:
            return None
        hn = sel[0]
        for s in self.vpngate_shown:
            if s.get('HostName') == hn:
                return s
        return None

    def _vpngate_on_select(self):
        pass  # reserved for future details

    def _vpngate_copy_host(self):
        s = self._vpngate_selected()
        if not s:
            messagebox.showinfo(APP_NAME, 'Select a server in the table.')
            return
        text = f'{s.get("HostName")}:443'
        self.clipboard_clear(); self.clipboard_append(text)
        self.log(f'Copied: {text}', 'ok')

    def _vpngate_copy_creds(self):
        self.clipboard_clear(); self.clipboard_append('vpn')
        messagebox.showinfo(APP_NAME,
                             'Copied "vpn" as username. Click OK, then copy again for the password.')
        self.clipboard_clear(); self.clipboard_append('vpn')
        self.log('Copied VPN Gate creds (vpn/vpn)', 'ok')

    def _vpngate_create_interface(self):
        if not self._ensure_connected():
            return
        s = self._vpngate_selected()
        if not s:
            messagebox.showinfo(APP_NAME, 'Select a server in the table.')
            return
        host = s.get('HostName', '')
        country = s.get('CountryShort', '?')
        existing_names = [i['name'] for i in self.interfaces]
        idx = self.client.find_free_sstp_index(existing_names)
        new_name = f'SSTP{idx}'
        if not messagebox.askyesno(
                APP_NAME,
                f'Create SSTP interface "{new_name}" on the router?\n\n'
                f'Peer:      {host}\n'
                f'Country:   {country}\n'
                f'User/Pass: vpn / vpn\n\n'
                'The interface will attempt to connect immediately. '
                'After creation it will appear in the main "Interface" dropdown '
                'and can be used as a routing target for services.'):
            return
        self.log(f'Creating {new_name} via VPN Gate ({host})…')

        def do():
            desc = f'VPN Gate {country} {host}'
            errs = self.client.create_sstp_interface(
                new_name, peer=host, user='vpn', password='vpn',
                description=desc, auto_connect=True)
            self.client.save_config()
            ifaces = self.client.list_interfaces()
            return new_name, ifaces, errs

        def done(result, err):
            if err is not None:
                self.log(f'Create interface failed: {err}', 'err')
                messagebox.showerror(APP_NAME, str(err))
                return
            new_name, ifaces, errs = result
            self.interfaces = ifaces
            names = [i['name'] for i in ifaces]
            self.iface_combo.configure(values=names, state='readonly')
            if new_name in names:
                self.iface_var.set(new_name)
            for e in errs:
                self.log(f'  {new_name}: {e}', 'warn')
            self.log(f'✓ Created {new_name}. Selected as current interface.', 'ok')
            messagebox.showinfo(APP_NAME,
                                 f'Interface {new_name} created and set as current. '
                                 'You can now tick services and Apply to route them through it.')

        self.worker.run(do, on_done=done)

    # ── Catalog tab ────────────────────────────────────────────────────────
    def _build_catalog_tab(self):
        f = self.tab_catalog
        for w in f.winfo_children():
            w.destroy()

        header = ttk.Frame(f, padding=(8, 12, 8, 4))
        header.pack(fill='x')
        ttk.Label(header, text=self.catalog.name,
                  font=('Segoe UI', 11, 'bold')).pack(anchor='w')
        by_cat: dict[str, int] = {}
        for svc in self.catalog.services:
            by_cat[svc.get('category', 'Other')] = by_cat.get(svc.get('category', 'Other'), 0) + 1
        stats = ' · '.join(f'{CATEGORY_ICON.get(c, "📦")} {c}: {n}' for c, n in sorted(by_cat.items()))
        ttk.Label(header,
                  text=f'Version {self.catalog.version} · {len(self.catalog.services)} services',
                  foreground='#555').pack(anchor='w')
        ttk.Label(header, text=stats, foreground='#555').pack(anchor='w', pady=(2, 0))

        # Upstream refresh: how many services declare upstream/providers/asn
        n_upstream = sum(1 for s in self.catalog.services
                         if s.get('upstream') or s.get('ipv4_providers') or s.get('asn'))
        refresh_box = ttk.LabelFrame(f, text=' Upstream refresh ', padding=8)
        refresh_box.pack(fill='x', padx=8, pady=(10, 6))
        ttk.Label(refresh_box,
                  text=f'{n_upstream} of {len(self.catalog.services)} services declare an upstream '
                       'source (v2fly, Cloudflare, AWS, RIPEstat, etc.)').pack(anchor='w')
        ttk.Label(refresh_box,
                  text='Pull fresh FQDN / IPv4 CIDR lists from upstream and merge into the '
                       'in-memory catalog. Re-Apply after to push changes to the router.',
                  foreground='#555', wraplength=700, justify='left').pack(anchor='w', pady=(2, 6))
        row = ttk.Frame(refresh_box)
        row.pack(anchor='w')
        ttk.Button(row, text='⟳  Refresh all upstream',
                   command=self._on_refresh_upstream_all,
                   style='Accent.TButton').pack(side='left')
        ttk.Button(row, text='Export current catalog to file…',
                   command=self._on_export_catalog).pack(side='left', padx=(8, 0))

        # Cache box
        cache_box = ttk.LabelFrame(f, text=' Disk cache ', padding=8)
        cache_box.pack(fill='x', padx=8, pady=6)
        size_kb = CACHE.size_bytes() / 1024.0
        ttk.Label(cache_box,
                  text=f'{CACHE.num_entries()} entries, {size_kb:.1f} KB at '
                       f'{str(CACHE_FILE)}').pack(anchor='w')
        ttk.Label(cache_box,
                  text='TTL: v2fly/plain-text 6h, IP providers 24h, RIPEstat 24h, VPN Gate 5 min. '
                       'Refresh buttons ignore the cache and re-fetch.',
                  foreground='#555', wraplength=700, justify='left').pack(anchor='w', pady=(2, 6))
        ttk.Button(cache_box, text='Clear cache',
                   command=self._on_cache_clear).pack(anchor='w')

        url_box = ttk.LabelFrame(f, text=' Import from URL ', padding=8)
        url_box.pack(fill='x', padx=8, pady=6)
        self.url_var = tk.StringVar()
        ttk.Label(url_box, text='URL to services.json (schema_version=1):').pack(anchor='w')
        row = ttk.Frame(url_box)
        row.pack(fill='x', pady=(4, 0))
        ttk.Entry(row, textvariable=self.url_var).pack(side='left', fill='x', expand=True)
        ttk.Button(row, text='Import', command=self._on_import_url).pack(side='left', padx=(6, 0))

        file_box = ttk.LabelFrame(f, text=' Import from file ', padding=8)
        file_box.pack(fill='x', padx=8, pady=4)
        ttk.Button(file_box, text='Load JSON file…', command=self._on_import_file).pack(anchor='w')

        schema_box = ttk.LabelFrame(f, text=' Schema reference ', padding=8)
        schema_box.pack(fill='both', expand=True, padx=8, pady=(6, 8))
        schema_txt = (
            '{\n'
            '  "schema_version": 1,\n'
            '  "catalog_version": "x.y.z",\n'
            '  "catalog_name": "My list",\n'
            '  "services": [\n'
            '    {\n'
            '      "id": "foo",\n'
            '      "name": "Foo Service",\n'
            '      "category": "AI | Video | Messaging | Social | Music | Dev | ...",\n'
            '      "description": "...",\n'
            '      "fqdn": ["example.com", "api.example.com"],\n'
            '      "ipv4_cidr": ["1.2.3.0/24"]\n'
            '    }\n'
            '  ]\n'
            '}\n')
        txt = scrolledtext.ScrolledText(schema_box, height=12, font=self._mono_font,
                                         wrap='none', relief='flat', borderwidth=0)
        txt.pack(fill='both', expand=True)
        txt.insert('1.0', schema_txt)
        txt.configure(state='disabled')

    # ── Hotkeys ────────────────────────────────────────────────────────────
    def _bind_hotkeys(self):
        self.bind('<Control-Return>', lambda e: self._on_apply_services())
        self.bind('<F5>',              lambda e: self._on_refresh_state())
        self.bind('<Escape>',          lambda e: self._on_disconnect() if self.conn_state == ConnState.CONNECTED else None)
        self.pass_entry.bind('<Return>', lambda e: self._on_connect_click())
        self.host_entry.bind('<Return>', lambda e: self.pass_entry.focus_set())
        self.user_entry.bind('<Return>', lambda e: self.pass_entry.focus_set())

    # ── State management ───────────────────────────────────────────────────
    def _set_state(self, s: ConnState, extra: str = ''):
        self.conn_state = s
        self.status_dot.configure(fg=STATE_COLOR[s])
        label = STATE_LABEL[s]
        if extra:
            label += f' — {extra}'
        self.status_label.configure(text=label)
        # Enable/disable inputs
        entry_state = 'normal' if s in (ConnState.DISCONNECTED, ConnState.ERROR) else 'disabled'
        self.host_entry.configure(state=entry_state)
        self.user_entry.configure(state=entry_state)
        self.pass_entry.configure(state=entry_state)
        if s == ConnState.CONNECTED:
            self.btn_connect.configure(text='Disconnect', state='normal')
        elif s == ConnState.CONNECTING:
            self.btn_connect.configure(text='Connecting…', state='disabled')
        else:
            self.btn_connect.configure(text='Connect', state='normal')
        if s != ConnState.CONNECTED:
            self.iface_combo.configure(state='disabled')

    # ── Log ────────────────────────────────────────────────────────────────
    def log(self, msg: str, level: str = 'info'):
        ts = time.strftime('%H:%M:%S')
        self.log_box.insert('end', f'[{ts}] ', 'ts')
        self.log_box.insert('end', f'{msg}\n', level)
        self.log_box.see('end')

    def _log_select_all(self):
        self.log_box.tag_add('sel', '1.0', 'end-1c')
        return 'break'

    def _log_copy_selection(self):
        try:
            text = self.log_box.selection_get()
        except tk.TclError:
            return
        self.clipboard_clear()
        self.clipboard_append(text)

    def _log_copy_all(self):
        text = self.log_box.get('1.0', 'end-1c')
        self.clipboard_clear()
        self.clipboard_append(text)

    def _log_clear(self):
        self.log_box.delete('1.0', 'end')

    def _log_context_menu(self, event):
        try:
            self._log_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._log_menu.grab_release()

    # ── Queue drain ────────────────────────────────────────────────────────
    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == 'log':
                    if isinstance(payload, tuple) and len(payload) == 2:
                        level, msg = payload
                        self.log(msg, level)
                    else:
                        self.log(str(payload))
                elif kind == 'done':
                    cb, result, err = payload
                    if cb is not None:
                        cb(result, err)
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    # ── Connection handlers ────────────────────────────────────────────────
    def _on_connect_click(self):
        if self.conn_state == ConnState.CONNECTED:
            self._on_disconnect()
        else:
            self._on_connect()

    def _on_connect(self):
        host = self.host_var.get().strip()
        user = self.user_var.get().strip()
        password = self.pass_var.get()
        if not host or not user or not password:
            messagebox.showwarning(APP_NAME, 'Enter host, user and password.')
            return
        self._set_state(ConnState.CONNECTING)
        self.log(f'Connecting to {host} as {user}…')

        def connect_and_probe():
            if self.client is not None:
                try: self.client.close()
                except Exception: pass
            c = KeeneticClient(host)
            c.login(user, password)
            ifaces = c.list_interfaces()
            cfg = c.running_config()
            try:
                components = c.get_components()
            except Exception:
                components = set()
            c.router_info['components'] = components
            return c, ifaces, cfg

        def done(result, err):
            self.pass_var.set('')  # clear from memory ASAP
            if err is not None:
                self._set_state(ConnState.ERROR)
                self._handle_connect_error(err)
                return
            self.client, self.interfaces, cfg = result
            self.state = parse_running_config(cfg)
            names = [i['name'] for i in self.interfaces]
            self.iface_combo.configure(values=names, state='readonly')
            saved_iface = self.ui_cfg.get('last_interface', '')
            if saved_iface in names:
                self.iface_var.set(saved_iface)
            else:
                preferred = next((i for i in self.interfaces
                                  if i.get('type') in ('SSTP', 'Wireguard', 'OpenVPN', 'L2TP', 'PPTP')
                                  and i.get('connected') == 'yes'), None)
                if preferred:
                    self.iface_var.set(preferred['name'])
                elif names:
                    self.iface_var.set(names[0])
            v = self.client.router_info.get('version', '?')
            vendor = self.client.router_info.get('vendor', '')
            self.info_var.set(
                f'{vendor} NDMS {v} · {len(self.interfaces)} interfaces · '
                f'{len(self.state["groups"])} FQDN groups · '
                f'{len(self.state["ip_routes"])} IP routes')
            self._set_state(ConnState.CONNECTED, f'{self.iface_var.get() or "no iface"}')
            self.log(f'Connected. Interface: {self.iface_var.get()}', 'ok')
            self._populate_services()    # to mark applied
            self._refresh_state_view()
            self._update_warnings()
            # Persist
            self.ui_cfg['last_host'] = host
            self.ui_cfg['last_user'] = user
            save_ui_config(self.ui_cfg)

        self.worker.run(connect_and_probe, on_done=done)

    def _on_disconnect(self):
        if self.client is not None:
            try: self.client.close()
            except Exception: pass
        self.client = None
        self.interfaces = []
        self.state = {'groups': {}, 'dns_routes': [], 'ip_routes': []}
        self.info_var.set('')
        self.iface_combo.configure(values=[], state='disabled')
        self.iface_var.set('')
        self._set_state(ConnState.DISCONNECTED)
        self._populate_services()
        self._refresh_state_view()
        self.warn_frame.pack_forget()
        self.log('Disconnected.', 'info')

    def _update_warnings(self):
        """Build the warning banner based on router state: missing SSTP
        component, VPN interface that is down, etc."""
        warns: list[str] = []
        if self.client:
            comps = self.client.router_info.get('components') or set()
            if comps and 'sstp' not in comps:
                warns.append(
                    '⚠  SSTP client component is NOT installed on the router. '
                    'You will not be able to create/use SSTP interfaces until it is installed. '
                    'Open the router web UI → System settings → Components → enable "SSTP client", apply and reboot.')
            iface_name = self.iface_var.get().strip()
            if iface_name:
                st = next((i for i in self.interfaces if i.get('name') == iface_name), {})
                connected = st.get('connected', '') == 'yes'
                link_up = st.get('link', '') == 'up'
                if not (connected and link_up):
                    status_bits = []
                    if st.get('link'):      status_bits.append(f'link={st["link"]}')
                    if st.get('connected'): status_bits.append(f'connected={st["connected"]}')
                    warns.append(
                        f'⚠  Selected interface "{iface_name}" is DOWN '
                        f'({", ".join(status_bits) or "no status"}). With kill switch '
                        'enabled, traffic to protected services will be dropped until the '
                        'interface comes back up.')
        # For newcomers with no services applied and no VPN interfaces at all
        if self.client and not any(i.get('type') in
                                   ('SSTP', 'L2TP', 'OpenVPN', 'Wireguard', 'PPTP')
                                   for i in self.interfaces):
            warns.append(
                'ℹ  No VPN-client interfaces found on the router. To get started with '
                'zero-config routing, open the "VPN Gate" tab and use a bootstrap server.')
        if warns:
            self.warn_label.configure(text='\n\n'.join(warns))
            self.warn_frame.pack(fill='x', padx=8, pady=(0, 4),
                                  before=self._main_pane)
        else:
            self.warn_frame.pack_forget()

    def _handle_connect_error(self, err: Exception):
        cls = type(err).__name__
        msg = str(err)
        if isinstance(err, PermissionError):
            human = f'Login failed — check user/password.\n\n{msg}'
        elif isinstance(err, socket.timeout) or 'timed out' in msg.lower():
            human = f'Timed out connecting to router. Is it reachable on the network?'
        elif isinstance(err, ConnectionRefusedError):
            human = 'Connection refused. Is telnet (port 23) enabled on the router?'
        elif isinstance(err, socket.gaierror):
            human = f'Cannot resolve host "{self.host_var.get()}".'
        elif isinstance(err, ConnectionError):
            human = f'Protocol error: {msg}'
        else:
            human = f'{cls}: {msg}'
        self.log(f'Connect failed: {human}', 'err')
        messagebox.showerror(APP_NAME, human)

    def _ensure_connected(self) -> bool:
        if self.client is None or self.conn_state != ConnState.CONNECTED:
            messagebox.showwarning(APP_NAME, 'Connect to the router first.')
            return False
        return True

    # ── Apply ─────────────────────────────────────────────────────────────
    def _svc_legacy_routes(self, svc: dict) -> list[dict]:
        """Legacy `ip route` entries whose subnet matches this service's
        ipv4_cidr — left over from the pre-v0.4 model and now redundant
        (the subnet is included directly in the object-group)."""
        legacy = []
        for cidr in svc.get('ipv4_cidr', []):
            net, mask = cidr_to_mask(cidr)
            for r in self.state.get('ip_routes', []):
                if r['network'] == net and r['mask'] == mask:
                    legacy.append(r)
        return legacy

    @staticmethod
    def _svc_includes(svc: dict) -> set[str]:
        """Combined set of includes (FQDN + IP/CIDR) for the unified object-group."""
        return set(svc.get('fqdn', [])) | set(svc.get('ipv4_cidr', []))

    def _compute_apply_plan(self, selected: list[dict], iface: str, exclusive: bool) -> dict:
        """Classify each service as create / update / skip."""
        plan: dict = {'create': [], 'update': [], 'skip': []}
        for svc in selected:
            sid = svc['id']
            cat_inc = self._svc_includes(svc)
            rtr_inc = set(self.state['groups'].get(sid, []))
            route = next((r for r in self.state['dns_routes'] if r['group'] == sid), None)
            legacy = self._svc_legacy_routes(svc)

            if not rtr_inc and not route:
                reasons = ['new']
                if legacy:
                    reasons.append(f'migrate {len(legacy)} legacy ip route(s)')
                plan['create'].append({'svc': svc, 'reasons': reasons})
                continue

            reasons = []
            if rtr_inc != cat_inc:
                add_n = len(cat_inc - rtr_inc)
                rm_n  = len(rtr_inc - cat_inc)
                if add_n or rm_n:
                    reasons.append(f'entries ({add_n}+ / {rm_n}-)')
            if route is None and cat_inc:
                reasons.append('dns-proxy route missing')
            elif route is not None:
                if route['interface'] != iface:
                    reasons.append(f'iface {route["interface"]}→{iface}')
                if bool(route.get('reject')) != exclusive:
                    reasons.append(f'kill-switch {route.get("reject", False)}→{exclusive}')
            if legacy:
                reasons.append(f'migrate {len(legacy)} legacy ip route(s)')

            if reasons:
                plan['update'].append({'svc': svc, 'reasons': reasons})
            else:
                plan['skip'].append({'svc': svc, 'reasons': ['identical']})
        return plan

    def _on_apply_services(self):
        if not self._ensure_connected():
            return
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showwarning(APP_NAME, 'Pick an interface.')
            return
        selected = [s for s in self.catalog.services if self.svc_checked.get(s['id'])]
        if not selected:
            messagebox.showinfo(APP_NAME, 'Tick at least one service.')
            return
        exclusive = self.exclusive_var.get()
        plan = self._compute_apply_plan(selected, iface, exclusive)

        # Build confirmation text
        def fmt(items: list, verb: str) -> str:
            if not items:
                return ''
            lines = [f'  • {verb}:']
            for it in items[:8]:
                rsn = ', '.join(it['reasons'][:3])
                lines.append(f'      {it["svc"]["name"]} ({rsn})')
            if len(items) > 8:
                lines.append(f'      … and {len(items) - 8} more')
            return '\n'.join(lines) + '\n'

        if not plan['create'] and not plan['update']:
            messagebox.showinfo(APP_NAME,
                f'All {len(plan["skip"])} selected service(s) are already up-to-date. '
                'Nothing to apply.')
            return

        summary = [
            f'Apply plan via {iface}',
            f'Kill switch: {"ON" if exclusive else "off"}',
            '',
            fmt(plan['create'], f'CREATE  ({len(plan["create"])})'),
            fmt(plan['update'], f'UPDATE  ({len(plan["update"])})'),
            fmt(plan['skip'],   f'SKIP    ({len(plan["skip"])} already up-to-date)'),
            'Proceed?'
        ]
        if not messagebox.askyesno(APP_NAME, '\n'.join(x for x in summary if x)):
            return

        to_do = plan['create'] + plan['update']

        def do_apply():
            c = self.client
            assert c is not None
            total_inc = touched = migrated = 0
            for entry in to_do:
                svc = entry['svc']
                group = svc['id']
                if not GROUP_NAME_RE.match(group):
                    self.ui_queue.put(('log', ('warn', f'SKIP {svc["name"]}: invalid group id "{group}"')))
                    continue
                includes = list(svc.get('fqdn', [])) + list(svc.get('ipv4_cidr', []))
                c.delete_fqdn_group(group)
                errs = c.create_fqdn_group(group, includes, description=svc.get('name', ''))
                for e in errs:
                    self.ui_queue.put(('log', ('warn', f'  {group}: {e}')))
                c.bind_fqdn_route(group, iface, auto=True, reject=exclusive)
                total_inc += len(includes)
                suffix = ' [kill switch]' if exclusive else ''
                self.ui_queue.put(('log', ('ok',
                    f'✓ {svc["name"]}  →  {iface}{suffix}  '
                    f'({len(svc.get("fqdn", []))} FQDN + {len(svc.get("ipv4_cidr", []))} IPv4)')))

                # Migrate: remove legacy `ip route` entries whose subnet is now
                # inside the object-group — keeping both would be redundant.
                for legacy in self._svc_legacy_routes(svc):
                    c.delete_ip_route(legacy['network'], legacy['mask'], legacy['interface'])
                    self.ui_queue.put(('log', ('warn',
                        f'  ↳ migrated: removed legacy ip route '
                        f'{legacy["network"]}/{legacy["mask"]} via {legacy["interface"]}')))
                    migrated += 1
                touched += 1

            for entry in plan['skip']:
                self.ui_queue.put(('log', ('info',
                    f'= {entry["svc"]["name"]} already up-to-date, skipped')))

            c.save_config()
            cfg = c.running_config()
            return touched, total_inc, migrated, cfg

        def done(result, err):
            if err is not None:
                self.log(f'Apply failed: {err}', 'err')
                messagebox.showerror(APP_NAME, str(err))
                return
            touched, total_inc, migrated, cfg = result
            self.state = parse_running_config(cfg)
            self._refresh_state_view()
            self._populate_services()
            extra = f', {migrated} legacy ip route(s) migrated' if migrated else ''
            self.log(
                f'Applied {touched} service(s): {total_inc} includes (FQDN+IPv4){extra}. '
                'Config saved.', 'ok')

        self.worker.run(do_apply, on_done=done)

    # ── State / Delete / Save ─────────────────────────────────────────────
    def _on_refresh_state(self):
        if not self._ensure_connected():
            return

        def do(): return self.client.running_config()
        def done(result, err):
            if err is not None:
                self.log(f'Refresh failed: {err}', 'err')
                return
            self.state = parse_running_config(result)
            self._refresh_state_view()
            self._populate_services()
            self.log('State refreshed.', 'ok')

        self.worker.run(do, on_done=done)

    def _on_delete_selected(self):
        if not self._ensure_connected():
            return
        sel = self.state_tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, 'Select an item to delete.')
            return
        iid = sel[0]
        if iid.startswith('group::'):
            name = iid.split('::', 1)[1]
            if not messagebox.askyesno(APP_NAME, f'Delete FQDN group "{name}" and its dns-proxy route?'):
                return

            def do():
                self.client.delete_fqdn_group(name)
                self.client.save_config()
                return self.client.running_config()

            def done(result, err):
                if err is not None:
                    self.log(f'Delete failed: {err}', 'err'); return
                self.state = parse_running_config(result)
                self._refresh_state_view()
                self._populate_services()
                self.log(f'Deleted group {name}.', 'ok')

            self.worker.run(do, on_done=done)

        elif iid.startswith('iproute::'):
            idx = int(iid.split('::', 1)[1])
            r = self.state['ip_routes'][idx]
            if not messagebox.askyesno(APP_NAME,
                    f'Delete IP route {r["network"]}/{r["mask"]} via {r["interface"]}?'):
                return

            def do():
                self.client.delete_ip_route(r['network'], r['mask'], r['interface'])
                self.client.save_config()
                return self.client.running_config()

            def done(result, err):
                if err is not None:
                    self.log(f'Delete failed: {err}', 'err'); return
                self.state = parse_running_config(result)
                self._refresh_state_view()
                self._populate_services()
                self.log(f'Deleted IP route {r["network"]}/{r["mask"]}.', 'ok')

            self.worker.run(do, on_done=done)

    def _on_save_config(self):
        if not self._ensure_connected():
            return

        def do(): return self.client.save_config()
        def done(result, err):
            if err is None:
                self.log('Configuration saved.', 'ok')
            else:
                self.log(f'Save failed: {err}', 'err')

        self.worker.run(do, on_done=done)

    # ── Catalog import ────────────────────────────────────────────────────
    def _on_import_url(self):
        url = self.url_var.get().strip()
        if not url:
            return

        def do(): return Catalog.load_url(url)
        def done(result, err):
            if err is not None:
                self.log(f'Import failed: {err}', 'err')
                messagebox.showerror(APP_NAME, f'Import failed:\n\n{err}')
                return
            self.catalog = result
            self.svc_checked.clear()
            self._populate_services()
            self._build_catalog_tab()
            self.log(f'Loaded "{self.catalog.name}" v{self.catalog.version} '
                     f'({len(self.catalog.services)} services).', 'ok')

        self.worker.run(do, on_done=done)

    def _on_import_file(self):
        path = filedialog.askopenfilename(filetypes=[('JSON', '*.json'), ('All', '*.*')])
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get('schema_version') != 1:
                raise ValueError(f'Unsupported schema_version: {data.get("schema_version")}')
            self.catalog = Catalog(data)
            self.svc_checked.clear()
            self._populate_services()
            self._build_catalog_tab()
            self.log(f'Loaded local "{self.catalog.name}" '
                     f'({len(self.catalog.services)} services).', 'ok')
        except Exception as e:
            messagebox.showerror(APP_NAME, f'Failed to load: {e}')

    # ── Upstream refresh ──────────────────────────────────────────────────
    def _on_refresh_upstream_all(self):
        targets = [s for s in self.catalog.services
                   if s.get('upstream') or s.get('ipv4_providers') or s.get('asn')]
        if not targets:
            messagebox.showinfo(APP_NAME, 'No services in the catalog declare an upstream.')
            return
        if not messagebox.askyesno(
                APP_NAME,
                f'Fetch upstream lists for {len(targets)} service(s)?\n\n'
                'Domains / CIDRs from v2fly, Cloudflare, AWS, RIPEstat etc. will be '
                'merged into the in-memory catalog.\n\nThis does NOT push to the router — '
                'run Apply after to propagate.'):
            return
        self.log(f'Refreshing upstream for {len(targets)} service(s)…')

        def do():
            results = []
            for svc in targets:
                before_f = len(svc.get('fqdn', []))
                before_i = len(svc.get('ipv4_cidr', []))
                new_svc, info, errs = refresh_service(svc, merge=True)
                after_f = len(new_svc.get('fqdn', []))
                after_i = len(new_svc.get('ipv4_cidr', []))
                results.append((svc['id'], new_svc, info, errs, before_f, after_f, before_i, after_i))
            return results

        def done(result, err):
            if err is not None:
                self.log(f'Refresh failed: {err}', 'err')
                messagebox.showerror(APP_NAME, str(err))
                return
            # Apply results: replace service dict in catalog.data.services
            updated = 0
            for sid, new_svc, info_lines, errs, bf, af, bi, ai in result:
                for idx, s in enumerate(self.catalog.data.get('services', [])):
                    if s.get('id') == sid:
                        self.catalog.data['services'][idx] = new_svc
                        break
                delta_f = af - bf
                delta_i = ai - bi
                if errs:
                    for e in errs:
                        self.log(f'  {sid}: {e}', 'warn')
                if delta_f or delta_i:
                    self.log(f'↻ {sid}: FQDN {bf}→{af} (+{delta_f}), IPv4 {bi}→{ai} (+{delta_i})', 'ok')
                    updated += 1
                else:
                    self.log(f'= {sid}: no changes', 'info')
            self._populate_services()
            self._set_details_placeholder()
            self.log(f'Upstream refresh done: {updated} service(s) updated.', 'ok')
            messagebox.showinfo(APP_NAME, f'Refreshed {updated} service(s) out of {len(result)}.')

        self.worker.run(do, on_done=done)

    def _on_refresh_upstream_one(self, svc: dict):
        self.log(f'Refreshing upstream for {svc["id"]}…')

        def do():
            return refresh_service(svc, merge=True)

        def done(result, err):
            if err is not None:
                self.log(f'Refresh failed: {err}', 'err')
                messagebox.showerror(APP_NAME, str(err))
                return
            new_svc, info_lines, errs = result
            for idx, s in enumerate(self.catalog.data.get('services', [])):
                if s.get('id') == svc['id']:
                    self.catalog.data['services'][idx] = new_svc
                    break
            for ln in info_lines:
                self.log(f'  {svc["id"]}: {ln}', 'info')
            for e in errs:
                self.log(f'  {svc["id"]}: {e}', 'warn')
            self.log(f'↻ {svc["id"]}: FQDN→{len(new_svc["fqdn"])}, IPv4→{len(new_svc["ipv4_cidr"])}', 'ok')
            self._populate_services()
            self._show_service_details(new_svc)

        self.worker.run(do, on_done=done)

    def _on_cache_clear(self):
        if not messagebox.askyesno(APP_NAME,
                'Clear the on-disk cache? Next refresh will re-fetch everything from origin.'):
            return
        CACHE.clear()
        self.log('Disk cache cleared.', 'ok')
        self._build_catalog_tab()  # refresh the Disk cache stats label

    def _on_export_catalog(self):
        path = filedialog.asksaveasfilename(
            defaultextension='.json', filetypes=[('JSON', '*.json')],
            initialfile='services.json')
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.catalog.data, f, ensure_ascii=False, indent=2)
            self.log(f'Catalog exported to {path}', 'ok')
        except Exception as e:
            messagebox.showerror(APP_NAME, f'Export failed: {e}')

    # ── Close ──────────────────────────────────────────────────────────────
    def _on_close(self):
        try:
            self.ui_cfg['geometry'] = self.geometry()
            self.ui_cfg['last_interface'] = self.iface_var.get()
            self.ui_cfg['exclusive'] = bool(self.exclusive_var.get())
            save_ui_config(self.ui_cfg)
        except Exception:
            pass
        if self.client is not None:
            try: self.client.close()
            except Exception: pass
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    try:
        app = App()
        app.mainloop()
    except Exception as e:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, str(e), APP_NAME, 0x10)
        except Exception:
            print(f'FATAL: {e}', file=sys.stderr)
        raise


if __name__ == '__main__':
    main()
