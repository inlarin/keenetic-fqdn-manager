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
