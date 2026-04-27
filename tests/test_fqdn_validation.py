"""Tests for FQDN / group-name validation and normalization in utils.py."""
from __future__ import annotations

import pytest

from kn_gui.utils import (
    MAX_ENTRIES_PER_GROUP,
    is_valid_fqdn,
    normalize_fqdn,
    validate_fqdns,
    validate_group_name,
)


# ── is_valid_fqdn ─────────────────────────────────────────────────────────

@pytest.mark.parametrize('fqdn, ok', [
    ('example.com',           True),
    ('a.b.c.example.com',     True),
    ('xn--e1afmkfd.xn--p1ai', True),   # Punycode
    ('example.com.',           True),   # trailing dot
    ('123.example.com',        True),   # numeric label
    # Invalid:
    ('',                       False),
    ('bare',                   False),  # no dot
    ('.example.com',           False),  # leading dot
    ('example..com',           False),  # empty label
    ('-example.com',           False),  # label starts with dash
    ('example-.com',           False),  # label ends with dash
    ('*.example.com',          False),  # wildcard character
    ('example com',            False),  # space
    ('a' * 64 + '.com',       False),  # label > 63 chars
])
def test_is_valid_fqdn(fqdn, ok):
    assert is_valid_fqdn(fqdn) is ok


# ── normalize_fqdn ────────────────────────────────────────────────────────

def test_normalize_strips_wildcard():
    name, warn = normalize_fqdn('*.example.com')
    assert name == 'example.com'
    assert 'wildcard' in warn
    assert 'auto-matches' in warn


def test_normalize_strips_bare_star():
    name, warn = normalize_fqdn('*.cdn.example.com')
    assert name == 'cdn.example.com'
    assert 'wildcard' in warn


def test_normalize_strips_trailing_dot():
    name, warn = normalize_fqdn('example.com.')
    assert name == 'example.com'
    assert warn == ''


def test_normalize_idn_punycode():
    """Unicode domain must be converted to Punycode, not rejected."""
    name, warn = normalize_fqdn('пример.рф')
    assert name.startswith('xn--'), f'expected Punycode, got {name!r}'
    assert '.xn--' in name, 'both labels should be Punycoded'
    assert 'IDN' in warn or 'Punycode' in warn


def test_normalize_idn_ascii_passthrough():
    """ASCII domain must not be touched by the IDN path."""
    name, warn = normalize_fqdn('example.com')
    assert name == 'example.com'
    assert warn == ''


def test_normalize_idn_with_wildcard():
    """`*.магазин.рф` — strip wildcard AND Punycode at once."""
    name, warn = normalize_fqdn('*.магазин.рф')
    assert name.startswith('xn--')
    # Warning mentions both wildcard and IDN.
    assert 'wildcard' in warn.lower() or '→' in warn
    assert 'IDN' in warn or 'xn--' in warn


def test_normalize_preserves_already_punycode():
    """An already-ASCII Punycode name (xn--...) must not be warned about."""
    name, warn = normalize_fqdn('xn--e1afmkfd.xn--p1ai')
    assert name == 'xn--e1afmkfd.xn--p1ai'
    assert warn == ''  # already ASCII — no conversion


def test_normalize_returns_invalid_warning():
    name, warn = normalize_fqdn('')
    assert 'invalid' in warn


# ── validate_fqdns ────────────────────────────────────────────────────────

def test_validate_fqdns_splits_correctly():
    valid, warnings, invalid = validate_fqdns([
        'good.com',
        '*.also-good.com',       # wildcard → normalized + warning
        'good.com',              # duplicate → silently deduped
        '',                      # invalid
        '-bad.com',              # invalid
    ])
    assert valid == ['good.com', 'also-good.com']
    assert len(warnings) == 1
    assert 'wildcard' in warnings[0]
    assert len(invalid) == 2


# ── IPv4 host / CIDR passthrough (Telegram MTProto subnets etc.) ─────────

@pytest.mark.parametrize('entry', [
    '149.154.160.0/20',
    '91.108.4.0/22',
    '91.108.8.0/22',
    '8.8.8.8',          # bare host, /32 implied
    '0.0.0.0/0',        # widest CIDR
    '255.255.255.255',  # broadcast
])
def test_normalize_passes_ipv4_cidr_unchanged(entry):
    """`object-group fqdn / include` accepts IPv4 host + CIDR. Validator
    used to reject these as 'invalid FQDN' which silently dropped
    Telegram's MTProto subnets at apply time."""
    norm, warn = normalize_fqdn(entry)
    assert norm == entry
    assert warn == ''


@pytest.mark.parametrize('bad', [
    '10.0.0.1/abc',       # non-numeric prefix — '/' breaks FQDN fallthrough
])
def test_normalize_rejects_unmistakably_bad_cidr(bad):
    """Strings that fail BOTH the IPv4-CIDR regex AND the FQDN syntax
    (e.g. contain ``/``) must end up as 'invalid'. Note: malformed
    numeric strings like ``256.0.0.1`` or ``10.0.0`` fall through to
    FQDN syntax and are accepted there — Keenetic CLI will reject them
    server-side. We don't try to second-guess that here."""
    _, warn = normalize_fqdn(bad)
    assert 'invalid' in warn


def test_validate_fqdns_mixed_fqdn_and_cidr():
    valid, warnings, invalid = validate_fqdns([
        'telegram.org',
        '149.154.160.0/20',
        '91.108.4.0/22',
        '8.8.8.8',
        'bad..fqdn',
    ])
    assert 'telegram.org' in valid
    assert '149.154.160.0/20' in valid
    assert '91.108.4.0/22' in valid
    assert '8.8.8.8' in valid
    assert any('bad..fqdn' in i for i in invalid)


# ── validate_group_name ───────────────────────────────────────────────────

def test_group_name_valid():
    assert validate_group_name('telegram') is None
    assert validate_group_name('my_group_42') is None
    assert validate_group_name('A') is None


def test_group_name_too_long():
    err = validate_group_name('a' * 33)
    assert err is not None
    assert '33' in err


def test_group_name_bad_chars():
    err = validate_group_name('my-group')
    assert err is not None
    assert 'invalid characters' in err


def test_group_name_starts_with_digit():
    err = validate_group_name('1group')
    assert err is not None


def test_group_name_empty():
    err = validate_group_name('')
    assert err is not None


# ── MAX_ENTRIES_PER_GROUP value ───────────────────────────────────────────

def test_max_entries_per_group_is_sane():
    """The constant should be in a range that Keenetic handles well
    (not too small = pointless splits; not too big = DNS degradation)."""
    assert 100 <= MAX_ENTRIES_PER_GROUP <= 500


# ── Integration: catalog services.json IDs are all valid group names ─────

def test_all_catalog_ids_are_valid_group_names():
    """Every service.id in the shipped catalog must pass Keenetic validation."""
    import json
    from kn_gui.paths import data_path
    with open(data_path('services.json'), 'r', encoding='utf-8') as f:
        services = json.load(f)['services']
    for svc in services:
        err = validate_group_name(svc['id'])
        assert err is None, f'service {svc["id"]!r} fails group-name check: {err}'


def test_all_catalog_fqdns_are_valid():
    """Every FQDN in the shipped catalog must pass validation."""
    import json
    from kn_gui.paths import data_path
    with open(data_path('services.json'), 'r', encoding='utf-8') as f:
        services = json.load(f)['services']
    for svc in services:
        for fqdn in svc.get('fqdn', []):
            assert is_valid_fqdn(fqdn), (
                f'service {svc["id"]!r}: FQDN {fqdn!r} is invalid')
