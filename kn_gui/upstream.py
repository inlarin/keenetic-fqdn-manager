"""Upstream fetchers — pull FQDN lists and IPv4 CIDRs from public sources.
All results pass through the shared DiskCache with per-source TTL."""
from __future__ import annotations

import json
from typing import Callable

from .constants import TTL_ASN, TTL_IP_PROVIDER, TTL_V2FLY
from .net import _http_get, cached


# jsDelivr mirror for v2fly — auto-tried when raw.githubusercontent.com
# is blocked (common in RU). Same content, different CDN.
_V2FLY_RAW = 'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/'
_V2FLY_CDN = 'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/'


def _v2fly_parse(text: str) -> list[str]:
    """Parse v2fly domain-list-community format. Accepts `domain:X` and
    `full:X`; drops keyword: / regexp: / include: and blank/comment lines."""
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


def fetch_v2fly(url: str, force: bool = False) -> list[str]:
    """Fetch and parse a v2fly domain-list. Automatically tries the jsDelivr
    CDN mirror when the primary (raw.githubusercontent.com) fails — which
    happens regularly in Russia."""
    def produce():
        # Try primary URL first.
        try:
            return _v2fly_parse(_http_get(url))
        except Exception:
            pass
        # Fallback: swap GitHub raw → jsDelivr CDN.
        if _V2FLY_RAW in url:
            cdn_url = url.replace(_V2FLY_RAW, _V2FLY_CDN)
            return _v2fly_parse(_http_get(cdn_url))
        raise  # re-raise the original error if no fallback applies

    return cached(f'v2fly:{url}', TTL_V2FLY, produce, force)


def fetch_plain_text(url: str, force: bool = False) -> list[str]:
    """Generic one-domain-per-line list with # comments."""
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
    return cached(f'plain:{url}', TTL_V2FLY, produce, force)


def fetch_cloudflare_v4(force: bool = False) -> list[str]:
    def produce():
        text = _http_get('https://www.cloudflare.com/ips-v4')
        return sorted({ln.strip() for ln in text.splitlines()
                       if ln.strip() and '/' in ln})
    return cached('cloudflare', TTL_IP_PROVIDER, produce, force)


def fetch_github_meta(force: bool = False) -> list[str]:
    def produce():
        data = json.loads(_http_get('https://api.github.com/meta'))
        ips: set[str] = set()
        for key in ('web', 'api', 'git', 'packages', 'hooks'):
            for entry in data.get(key, []):
                if ':' not in entry and '/' in entry:
                    ips.add(entry)
        return sorted(ips)
    return cached('github_meta', TTL_IP_PROVIDER, produce, force)


def fetch_fastly(force: bool = False) -> list[str]:
    def produce():
        data = json.loads(_http_get('https://api.fastly.com/public-ip-list'))
        return sorted({a for a in data.get('addresses', []) if '/' in a})
    return cached('fastly', TTL_IP_PROVIDER, produce, force)


def fetch_telegram(force: bool = False) -> list[str]:
    """Telegram publishes its IPv4 subnets at /resources/cidr.txt.

    Format: one CIDR per line, blank lines and `#` comments allowed.
    Historically this endpoint is sometimes filtered from certain regions;
    when the fetch fails the caller just doesn't get a refresh and keeps
    using the last cached value. There is no secondary mirror that's
    authoritative, so don't add a fallback here.
    """
    def produce():
        text = _http_get('https://core.telegram.org/resources/cidr.txt')
        out: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # tolerate trailing comments on a data line
            if '#' in line:
                line = line.split('#', 1)[0].strip()
            # IPv4 CIDRs only (IPv6 entries contain ':')
            if '/' in line and ':' not in line:
                out.add(line)
        return sorted(out)
    return cached('telegram', TTL_IP_PROVIDER, produce, force)


def fetch_aws_service(service_tag: str, force: bool = False) -> list[str]:
    def produce():
        data = json.loads(_http_get('https://ip-ranges.amazonaws.com/ip-ranges.json'))
        return sorted({
            p['ip_prefix'] for p in data.get('prefixes', [])
            if p.get('service') == service_tag and 'ip_prefix' in p
        })
    return cached(f'aws:{service_tag}', TTL_IP_PROVIDER, produce, force)


def fetch_google_ipranges(name: str = 'goog', force: bool = False) -> list[str]:
    def produce():
        data = json.loads(_http_get(f'https://www.gstatic.com/ipranges/{name}.json'))
        return sorted({p['ipv4Prefix'] for p in data.get('prefixes', [])
                       if 'ipv4Prefix' in p})
    return cached(f'google:{name}', TTL_IP_PROVIDER, produce, force)


def fetch_oracle_ranges(service: str = '', force: bool = False) -> list[str]:
    def produce():
        data = json.loads(_http_get(
            'https://docs.oracle.com/iaas/tools/public_ip_ranges.json'))
        out: set[str] = set()
        for region in data.get('regions', []):
            for cidr in region.get('cidrs', []):
                if service and service not in cidr.get('tags', []):
                    continue
                if '/' in cidr.get('cidr', ''):
                    out.add(cidr['cidr'])
        return sorted(out)
    return cached(f'oracle:{service}', TTL_IP_PROVIDER, produce, force)


def fetch_asn_prefixes(asn: int, force: bool = False) -> list[str]:
    def produce():
        url = f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}'
        data = json.loads(_http_get(url, timeout=30.0))
        out: set[str] = set()
        for entry in data.get('data', {}).get('prefixes', []):
            pfx = entry.get('prefix', '')
            if ':' not in pfx and '/' in pfx:
                out.add(pfx)
        return sorted(out)
    return cached(f'asn:{asn}', TTL_ASN, produce, force)


def resolve_ipv4_provider(spec: str) -> tuple[list[str], str]:
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


def refresh_service(svc: dict, merge: bool = True
                    ) -> tuple[dict, list[str], list[str]]:
    """Pull all upstream/ipv4_providers/asn data into the service.
    Returns (updated_svc, info_lines, errors)."""
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
            info.append(f'{t}: {url.rsplit("/", 1)[-1]} — '
                        f'{len(pulled)} items, +{len(new_fqdn) - before} new FQDN')
        except Exception as e:
            errors.append(f'{url}: {e}')

    for spec in svc.get('ipv4_providers', []) or []:
        try:
            cidrs, label = resolve_ipv4_provider(spec)
            before = len(new_ipv4)
            new_ipv4.update(cidrs)
            info.append(f'{label}: {len(cidrs)} CIDR, '
                        f'+{len(new_ipv4) - before} new IPv4')
        except Exception as e:
            errors.append(f'{spec}: {e}')

    for asn in svc.get('asn', []) or []:
        try:
            cidrs = fetch_asn_prefixes(int(asn))
            before = len(new_ipv4)
            new_ipv4.update(cidrs)
            info.append(f'AS{asn}: {len(cidrs)} prefixes, '
                        f'+{len(new_ipv4) - before} new IPv4')
        except Exception as e:
            errors.append(f'AS{asn}: {e}')

    out_svc = dict(svc)
    out_svc['fqdn'] = sorted(new_fqdn)
    out_svc['ipv4_cidr'] = sorted(new_ipv4)
    return out_svc, info, errors
