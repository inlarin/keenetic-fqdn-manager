"""Upstream fetcher parsers. All network I/O monkeypatched — no real HTTP."""
import pytest

from kn_gui import upstream
from kn_gui.cache import CACHE


@pytest.fixture(autouse=True)
def _clear_cache():
    CACHE.clear()
    yield
    CACHE.clear()


def _monkey_http(monkeypatch, payload: str):
    """Replace _http_get used by the upstream module with a stub."""
    def fake(url, timeout=20.0, max_bytes=None):
        return payload
    monkeypatch.setattr(upstream, '_http_get', fake)


# ─── fetch_v2fly ─────────────────────────────────────────────────────────────

def test_v2fly_parses_domain_and_full(monkeypatch):
    body = (
        '# comment line\n'
        '\n'
        'domain:example.com\n'
        'full:specific.example.com\n'
        'keyword:drop  # should be ignored\n'
        'regexp:.*bad\n'
        'include:other  # recursive include ignored\n'
    )
    _monkey_http(monkeypatch, body)
    out = upstream.fetch_v2fly('https://example/data/x', force=True)
    assert out == ['example.com', 'specific.example.com']


def test_v2fly_accepts_plain_domain_lines(monkeypatch):
    _monkey_http(monkeypatch, 'foo.com\nbar.com\n')
    out = upstream.fetch_v2fly('https://example/data/y', force=True)
    assert out == ['bar.com', 'foo.com']


def test_v2fly_cache_hit(monkeypatch):
    _monkey_http(monkeypatch, 'domain:one.com\n')
    a = upstream.fetch_v2fly('https://example/data/z', force=True)
    # After first call the cache is warm. Change the stub to verify the
    # second call doesn't hit it (should come from cache).
    _monkey_http(monkeypatch, 'domain:other.com\n')
    b = upstream.fetch_v2fly('https://example/data/z', force=False)
    assert a == b == ['one.com']


def test_v2fly_force_bypasses_cache(monkeypatch):
    _monkey_http(monkeypatch, 'domain:one.com\n')
    upstream.fetch_v2fly('https://example/data/z2', force=True)
    _monkey_http(monkeypatch, 'domain:two.com\n')
    out = upstream.fetch_v2fly('https://example/data/z2', force=True)
    assert out == ['two.com']


# ─── fetch_plain_text ────────────────────────────────────────────────────────

def test_plain_text_drops_blank_and_comments(monkeypatch):
    body = '# header\n\nalpha.net\nbeta.io\n# tail\n'
    _monkey_http(monkeypatch, body)
    out = upstream.fetch_plain_text('https://example/list.txt', force=True)
    assert out == ['alpha.net', 'beta.io']


# ─── fetch_cloudflare_v4 ─────────────────────────────────────────────────────

def test_cloudflare_returns_only_cidrs(monkeypatch):
    _monkey_http(monkeypatch, '173.245.48.0/20\n103.21.244.0/22\n# junk\n')
    out = upstream.fetch_cloudflare_v4(force=True)
    assert out == ['103.21.244.0/22', '173.245.48.0/20']


# ─── fetch_github_meta ───────────────────────────────────────────────────────

def test_github_meta_filters_ipv4_cidrs(monkeypatch):
    import json as _json
    _monkey_http(monkeypatch, _json.dumps({
        'web':  ['140.82.112.0/20', '2a01::/64'],   # IPv6 must be skipped
        'api':  ['140.82.112.0/20'],                 # dedup across keys
        'git':  ['192.30.252.0/22'],
        'other_junk': ['not-an-ip'],
    }))
    out = upstream.fetch_github_meta(force=True)
    assert out == ['140.82.112.0/20', '192.30.252.0/22']


# ─── fetch_telegram ──────────────────────────────────────────────────────────

def test_telegram_parses_cidr_list(monkeypatch):
    body = (
        '# Telegram IPv4 CIDRs\n'
        '# generated at 2026-04-16\n'
        '91.108.4.0/22\n'
        '91.108.8.0/22\n'
        '\n'
        '149.154.160.0/20  # trailing comment\n'
        '2001:67c:4e8::/48\n'   # IPv6 must be skipped
        'not-a-cidr\n'          # malformed must be skipped
    )
    _monkey_http(monkeypatch, body)
    out = upstream.fetch_telegram(force=True)
    assert out == ['149.154.160.0/20', '91.108.4.0/22', '91.108.8.0/22']


def test_telegram_cache_hit(monkeypatch):
    _monkey_http(monkeypatch, '91.108.4.0/22\n')
    a = upstream.fetch_telegram(force=True)
    _monkey_http(monkeypatch, '1.2.3.0/24\n')
    b = upstream.fetch_telegram(force=False)
    assert a == b == ['91.108.4.0/22']
