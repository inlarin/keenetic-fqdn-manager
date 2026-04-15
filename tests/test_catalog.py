import json

import pytest

from kn_gui.catalog import Catalog


def test_load_default_from_bundled_data():
    """The shipped services.json must load and expose a sane service list."""
    cat = Catalog.load_default()
    assert cat.name
    assert cat.version
    assert len(cat.services) > 10
    # Every service has the required identity fields.
    for s in cat.services:
        assert 'id' in s and 'name' in s and 'category' in s
        # fqdn is either missing (falsy) or a list.
        assert isinstance(s.get('fqdn', []), list)


def test_service_lookup_returns_none_for_unknown():
    cat = Catalog.load_default()
    assert cat.service('does_not_exist_really') is None


def test_service_lookup_finds_known():
    cat = Catalog.load_default()
    # Telegram ships in the default catalog across all releases — use as canary.
    svc = cat.service('telegram')
    assert svc is not None and 'fqdn' in svc


def test_load_file_accepts_v1_schema(tmp_path):
    doc = {
        'schema_version': 1,
        'catalog_version': '0.0.1',
        'catalog_name': 'test',
        'services': [{'id': 'x', 'name': 'X', 'category': 'AI',
                      'fqdn': ['x.com'], 'ipv4_cidr': []}],
    }
    p = tmp_path / 'svc.json'
    p.write_text(json.dumps(doc), encoding='utf-8')
    cat = Catalog.load_file(str(p))
    assert cat.name == 'test'
    assert len(cat.services) == 1


def test_load_file_rejects_wrong_schema(tmp_path):
    p = tmp_path / 'svc.json'
    p.write_text(json.dumps({'schema_version': 99, 'services': []}),
                 encoding='utf-8')
    with pytest.raises(ValueError, match='schema_version'):
        Catalog.load_file(str(p))
