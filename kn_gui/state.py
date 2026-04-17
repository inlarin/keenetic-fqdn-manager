"""Router running-config parser + apply-plan classifier.

Exposes pure-function utilities that can be unit-tested without a router:
just feed them `show running-config` transcripts."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .utils import cidr_to_mask


@dataclass(slots=True)
class DnsProxyRoute:
    group: str
    interface: str
    auto: bool
    reject: bool


@dataclass(slots=True)
class IpRoute:
    network: str
    mask: str
    interface: str
    auto: bool
    reject: bool


def parse_running_config(cfg: str) -> dict:
    """Parse show running-config into {'groups', 'group_descriptions',
    'dns_routes', 'ip_routes'}.

    `group_descriptions` maps `name → description string` (may be empty).
    Used by `list_managed_fqdn_groups()` to pick out app-created groups
    by the MANAGED_INTERFACE_TAG marker in the description field.
    """
    groups: dict[str, list[str]] = {}
    group_descriptions: dict[str, str] = {}
    current_group: Optional[str] = None
    dns_routes: list[dict] = []
    ip_routes: list[dict] = []
    in_dns_proxy = False
    dns_proxy_indent = -1

    for raw in cfg.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        indent = len(line) - len(line.lstrip()) if stripped else 0
        if stripped == '!':
            current_group = None
            in_dns_proxy = False
            dns_proxy_indent = -1
            continue
        m = re.match(r'object-group fqdn (\S+)', stripped)
        if m:
            current_group = m.group(1)
            groups[current_group] = []
            continue
        if current_group and stripped.startswith('include '):
            groups[current_group].append(stripped.split(' ', 1)[1])
            continue
        if current_group and stripped.startswith('description '):
            # description may be quoted or bare; strip surrounding quotes.
            desc_text = stripped.split(' ', 1)[1].strip()
            if desc_text.startswith('"') and desc_text.endswith('"'):
                desc_text = desc_text[1:-1]
            group_descriptions[current_group] = desc_text
            continue
        if stripped == 'dns-proxy':
            in_dns_proxy = True
            dns_proxy_indent = indent
            continue
        # dns-proxy children are indented deeper than the block itself.
        if in_dns_proxy and indent > dns_proxy_indent:
            m = re.match(r'route object-group (\S+) (\S+)(?:\s+(auto))?(?:\s+(reject))?',
                         stripped)
            if m:
                dns_routes.append({'group': m.group(1), 'interface': m.group(2),
                                   'auto': m.group(3) == 'auto',
                                   'reject': m.group(4) == 'reject'})
                continue
        elif in_dns_proxy and indent <= dns_proxy_indent and stripped:
            in_dns_proxy = False
        m = re.match(r'ip route (\S+) (\S+) (\S+)(?:\s+(auto))?(?:\s+(reject))?',
                     stripped)
        if m:
            ip_routes.append({'network': m.group(1), 'mask': m.group(2),
                              'interface': m.group(3), 'auto': m.group(4) == 'auto',
                              'reject': m.group(5) == 'reject'})
    return {
        'groups': groups,
        'group_descriptions': group_descriptions,
        'dns_routes': dns_routes,
        'ip_routes': ip_routes,
    }


def svc_includes(svc: dict) -> set[str]:
    """Combined set for unified object-group: FQDNs + IP/CIDR entries."""
    return set(svc.get('fqdn', [])) | set(svc.get('ipv4_cidr', []))


def svc_legacy_routes(svc: dict, ip_routes: list[dict]) -> list[dict]:
    """Pre-v0.4 standalone `ip route` entries whose subnet is now an include
    in the unified object-group. Candidates for migration."""
    legacy = []
    for cidr in svc.get('ipv4_cidr', []):
        try:
            net, mask = cidr_to_mask(cidr)
        except ValueError:
            continue
        for r in ip_routes:
            if r['network'] == net and r['mask'] == mask:
                legacy.append(r)
    return legacy


def compute_apply_plan(services_selected: list[dict],
                       state: dict,
                       iface: str,
                       exclusive: bool) -> dict:
    """Classify each service as create / update / skip given router state.

    Returns {'create': [...], 'update': [...], 'skip': [...]} where each
    item is {'svc': dict, 'reasons': list[str]}."""
    plan: dict = {'create': [], 'update': [], 'skip': []}
    for svc in services_selected:
        sid = svc['id']
        cat_inc = svc_includes(svc)
        rtr_inc = set(state.get('groups', {}).get(sid, []))
        route = next((r for r in state.get('dns_routes', [])
                      if r['group'] == sid), None)
        legacy = svc_legacy_routes(svc, state.get('ip_routes', []))

        if not rtr_inc and not route:
            reasons = ['new']
            if legacy:
                reasons.append(f'migrate {len(legacy)} legacy ip route(s)')
            plan['create'].append({'svc': svc, 'reasons': reasons})
            continue

        reasons: list[str] = []
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
