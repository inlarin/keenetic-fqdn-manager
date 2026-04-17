from kn_gui.state import (compute_apply_plan, parse_running_config,
                          svc_includes, svc_legacy_routes)


# ─── parse_running_config ────────────────────────────────────────────────────

def test_parse_empty():
    st = parse_running_config('')
    assert st == {'groups': {}, 'group_descriptions': {},
                   'dns_routes': [], 'ip_routes': []}


def test_parse_group_description_stripped_of_quotes():
    """Descriptions come back as the inner string only — outer quotes
    from `description "..."` are removed so downstream tag-matching
    works on the raw content."""
    cfg = (
        'object-group fqdn telegram\n'
        '    description "[kn-gui] Telegram"\n'
        '    include t.me\n'
        '!\n'
    )
    st = parse_running_config(cfg)
    assert st['group_descriptions'] == {'telegram': '[kn-gui] Telegram'}


def test_parse_group_description_without_quotes():
    cfg = (
        'object-group fqdn foo\n'
        '    description bare-description-no-quotes\n'
        '    include example.com\n'
        '!\n'
    )
    st = parse_running_config(cfg)
    assert st['group_descriptions'] == {'foo': 'bare-description-no-quotes'}


def test_parse_multiple_groups_mixed_descriptions():
    cfg = (
        'object-group fqdn a\n'
        '    description "[kn-gui] first"\n'
        '    include a.com\n'
        '!\n'
        'object-group fqdn b\n'
        '    include b.com\n'  # no description on this one
        '!\n'
        'object-group fqdn c\n'
        '    description "user made"\n'
        '    include c.com\n'
        '!\n'
    )
    st = parse_running_config(cfg)
    # Only groups that actually had a description key appear in the map.
    assert st['group_descriptions'] == {
        'a': '[kn-gui] first',
        'c': 'user made',
    }
    # All three still listed in groups/.
    assert set(st['groups']) == {'a', 'b', 'c'}


def test_parse_single_group_and_route():
    cfg = (
        'object-group fqdn claude\n'
        '    include claude.ai\n'
        '    include api.anthropic.com\n'
        '!\n'
        'dns-proxy\n'
        '    route object-group claude SSTP0 auto reject\n'
        '!\n'
    )
    st = parse_running_config(cfg)
    assert st['groups'] == {'claude': ['claude.ai', 'api.anthropic.com']}
    assert st['dns_routes'] == [{
        'group': 'claude', 'interface': 'SSTP0',
        'auto': True, 'reject': True,
    }]
    assert st['ip_routes'] == []


def test_parse_mixed_fqdn_and_cidr_in_group():
    cfg = (
        'object-group fqdn telegram\n'
        '    include t.me\n'
        '    include 91.108.4.0/22\n'
        '!\n'
    )
    st = parse_running_config(cfg)
    assert st['groups']['telegram'] == ['t.me', '91.108.4.0/22']


def test_parse_standalone_ip_route_with_reject():
    cfg = 'ip route 91.108.4.0 255.255.252.0 SSTP0 auto reject\n'
    st = parse_running_config(cfg)
    assert st['ip_routes'] == [{
        'network': '91.108.4.0', 'mask': '255.255.252.0',
        'interface': 'SSTP0', 'auto': True, 'reject': True,
    }]


def test_parse_ip_route_without_flags():
    cfg = 'ip route 10.0.0.0 255.0.0.0 Home\n'
    st = parse_running_config(cfg)
    assert st['ip_routes'][0]['auto'] is False
    assert st['ip_routes'][0]['reject'] is False


def test_parse_dns_proxy_block_isolated():
    """Ensures the parser doesn't treat a stray 'route object-group' line
    outside the dns-proxy block as a dns route."""
    cfg = (
        'dns-proxy\n'
        '    route object-group inside SSTP0 auto\n'
        '!\n'
        '# these non-indented lines must NOT be parsed as dns routes\n'
        'route object-group outside SSTP0 auto\n'
    )
    st = parse_running_config(cfg)
    groups = [r['group'] for r in st['dns_routes']]
    assert groups == ['inside']


# ─── svc_includes ────────────────────────────────────────────────────────────

def test_svc_includes_unites_fqdn_and_cidr():
    svc = {'fqdn': ['a.com', 'b.com'], 'ipv4_cidr': ['1.2.3.0/24']}
    assert svc_includes(svc) == {'a.com', 'b.com', '1.2.3.0/24'}


def test_svc_includes_empty():
    assert svc_includes({}) == set()


# ─── svc_legacy_routes ───────────────────────────────────────────────────────

def test_svc_legacy_routes_matches_subnet():
    svc = {'ipv4_cidr': ['91.108.4.0/22']}
    ip_routes = [
        {'network': '91.108.4.0', 'mask': '255.255.252.0',
         'interface': 'SSTP0', 'auto': True, 'reject': True},
        {'network': '10.0.0.0', 'mask': '255.0.0.0',
         'interface': 'Home', 'auto': False, 'reject': False},
    ]
    legacy = svc_legacy_routes(svc, ip_routes)
    assert len(legacy) == 1
    assert legacy[0]['network'] == '91.108.4.0'


def test_svc_legacy_routes_malformed_cidr_is_ignored():
    svc = {'ipv4_cidr': ['not-a-cidr']}
    assert svc_legacy_routes(svc, []) == []


# ─── compute_apply_plan ──────────────────────────────────────────────────────

def _state(groups, dns_routes=(), ip_routes=()):
    return {'groups': groups, 'dns_routes': list(dns_routes),
            'ip_routes': list(ip_routes)}


def test_plan_create_for_new_service():
    svc = {'id': 'foo', 'name': 'Foo', 'fqdn': ['a.com'], 'ipv4_cidr': []}
    plan = compute_apply_plan([svc], _state({}), 'SSTP0', True)
    assert [e['svc']['id'] for e in plan['create']] == ['foo']
    assert plan['update'] == [] and plan['skip'] == []


def test_plan_skip_when_identical():
    svc = {'id': 'foo', 'name': 'Foo', 'fqdn': ['a.com'], 'ipv4_cidr': []}
    state = _state(
        groups={'foo': ['a.com']},
        dns_routes=[{'group': 'foo', 'interface': 'SSTP0',
                     'auto': True, 'reject': True}],
    )
    plan = compute_apply_plan([svc], state, 'SSTP0', True)
    assert [e['svc']['id'] for e in plan['skip']] == ['foo']
    assert plan['create'] == [] and plan['update'] == []


def test_plan_update_when_iface_or_flags_change():
    svc = {'id': 'foo', 'name': 'Foo', 'fqdn': ['a.com'], 'ipv4_cidr': []}
    state = _state(
        groups={'foo': ['a.com']},
        dns_routes=[{'group': 'foo', 'interface': 'OldIface',
                     'auto': True, 'reject': False}],
    )
    plan = compute_apply_plan([svc], state, 'SSTP0', True)
    assert [e['svc']['id'] for e in plan['update']] == ['foo']
    reasons = ' '.join(plan['update'][0]['reasons'])
    assert 'iface' in reasons
    assert 'kill-switch' in reasons


def test_plan_update_when_domains_differ():
    svc = {'id': 'foo', 'name': 'Foo',
           'fqdn': ['a.com', 'b.com'], 'ipv4_cidr': []}
    state = _state(
        groups={'foo': ['a.com']},
        dns_routes=[{'group': 'foo', 'interface': 'SSTP0',
                     'auto': True, 'reject': True}],
    )
    plan = compute_apply_plan([svc], state, 'SSTP0', True)
    assert [e['svc']['id'] for e in plan['update']] == ['foo']
    assert 'entries' in ' '.join(plan['update'][0]['reasons'])


def test_plan_reports_legacy_ip_route_migration():
    svc = {'id': 'tg', 'name': 'TG',
           'fqdn': ['t.me'], 'ipv4_cidr': ['91.108.4.0/22']}
    state = _state(
        groups={'tg': ['t.me', '91.108.4.0/22']},
        dns_routes=[{'group': 'tg', 'interface': 'SSTP0',
                     'auto': True, 'reject': True}],
        # This legacy standalone ip route duplicates an include in the group:
        ip_routes=[{'network': '91.108.4.0', 'mask': '255.255.252.0',
                    'interface': 'SSTP0', 'auto': True, 'reject': True}],
    )
    plan = compute_apply_plan([svc], state, 'SSTP0', True)
    assert [e['svc']['id'] for e in plan['update']] == ['tg']
    assert 'migrate' in ' '.join(plan['update'][0]['reasons'])
