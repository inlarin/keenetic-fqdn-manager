"""Tests for RCIClient.

All network calls are mocked via monkeypatching the opener's .open(). We
verify:
- the challenge-response hash is computed correctly
- 401 triggers re-auth + retry
- 404 returns None (not raise)
- non-2xx statuses other than 404/401 raise RCICommandError
- available() probes /auth without requiring credentials
"""
from __future__ import annotations

import io
import json
from hashlib import md5, sha256
from unittest.mock import patch

import pytest

from kn_gui.rci_client import RCIAuthError, RCIClient, RCICommandError


class FakeResponse:
    """Mimics the urllib response enough for RCIClient._request()."""

    def __init__(self, status: int, body: bytes = b'', headers: dict | None = None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def read(self, _=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class FakeHTTPError(Exception):
    """urllib.error.HTTPError-compatible fake."""

    def __init__(self, code: int, body: bytes = b'', headers: dict | None = None):
        self.code = code
        self._body = body
        self.headers = headers or {}

    def read(self):
        return self._body


@pytest.fixture
def rci():
    return RCIClient('192.168.1.1')


def _install_opener(rci, responder):
    """Patch rci._opener.open with a callable that returns FakeResponse
    (or raises FakeHTTPError for 4xx/5xx)."""

    def fake_open(req, timeout=None):
        result = responder(req)
        if isinstance(result, FakeHTTPError):
            # Mimic urllib: HTTPError is a valid response object when read.
            # Our _request code catches urllib.error.HTTPError — for the fake
            # we convert by subclassing in a minimal way below.
            import urllib.error
            err = urllib.error.HTTPError(
                req.full_url, result.code, 'fake', result.headers, None
            )
            # Override read() to return the fake body.
            err.read = lambda: result._body  # type: ignore[method-assign]
            raise err
        return result

    rci._opener = type('O', (), {'open': staticmethod(fake_open)})()


def test_auth_success_challenge_response(rci):
    """Happy path: 401+headers, then 200 with a cookie."""
    call_count = {'n': 0}

    def responder(req):
        call_count['n'] += 1
        if call_count['n'] == 1:
            # First /auth GET — return 401 with challenge
            return FakeHTTPError(401, headers={
                'X-NDM-Realm': 'keenetic',
                'X-NDM-Challenge': 'abcdef123456',
            })
        if call_count['n'] == 2:
            # POST /auth with the computed hash — verify then 200
            body = json.loads(req.data.decode())
            expected_md5 = md5(b'admin:keenetic:sekret').hexdigest()
            expected_sha = sha256(f'abcdef123456{expected_md5}'.encode()).hexdigest()
            assert body['login'] == 'admin'
            assert body['password'] == expected_sha
            return FakeResponse(200, b'{}')
        raise AssertionError(f'unexpected call #{call_count["n"]}')

    _install_opener(rci, responder)
    rci.login('admin', 'sekret')
    assert rci._authed is True


def test_auth_missing_challenge_raises(rci):
    def responder(req):
        return FakeHTTPError(401, headers={})  # no X-NDM-* headers

    _install_opener(rci, responder)
    with pytest.raises(RCIAuthError) as exc_info:
        rci.login('admin', 'x')
    assert 'X-NDM' in str(exc_info.value)


def test_auth_rejected_raises(rci):
    call_count = {'n': 0}

    def responder(req):
        call_count['n'] += 1
        if call_count['n'] == 1:
            return FakeHTTPError(401, headers={
                'X-NDM-Realm': 'r', 'X-NDM-Challenge': 'c',
            })
        return FakeHTTPError(401, b'{"error":"denied"}')

    _install_opener(rci, responder)
    with pytest.raises(RCIAuthError):
        rci.login('admin', 'wrong')


def test_get_returns_none_on_404(rci):
    """`/rci/show/foo` → 404 should yield None, not raise."""
    rci._authed = True  # skip auth for this test

    def responder(req):
        return FakeHTTPError(404, b'')

    _install_opener(rci, responder)
    assert rci.get('show/nonexistent') is None


def test_get_raises_on_500(rci):
    rci._authed = True

    def responder(req):
        return FakeHTTPError(500, b'internal')

    _install_opener(rci, responder)
    with pytest.raises(RCICommandError) as exc_info:
        rci.get('show/version')
    assert '500' in str(exc_info.value)


def test_get_reauth_on_401(rci):
    """Session expiry mid-flight → reauth + retry."""
    rci._user = 'admin'
    rci._password = 'sekret'
    rci._authed = True
    calls: list[str] = []

    def responder(req):
        calls.append(req.method + ' ' + req.full_url.rsplit('/', 2)[-1])
        # 1st GET /rci/show/version → 401 (session dropped)
        # 2nd GET /auth             → 401 + challenge (reauth starts)
        # 3rd POST /auth            → 200
        # 4th GET /rci/show/version → 200 + data
        match len(calls):
            case 1:
                return FakeHTTPError(401)
            case 2:
                return FakeHTTPError(401, headers={
                    'X-NDM-Realm': 'r', 'X-NDM-Challenge': 'c',
                })
            case 3:
                return FakeResponse(200, b'{}')
            case 4:
                return FakeResponse(200, b'{"release":"5.0"}')
        raise AssertionError(f'unexpected call #{len(calls)}: {calls}')

    _install_opener(rci, responder)
    result = rci.get('show/version')
    assert result == {'release': '5.0'}


def test_available_true_on_401_with_challenge(rci):
    def responder(req):
        return FakeHTTPError(401, headers={'X-NDM-Challenge': 'c'})

    _install_opener(rci, responder)
    assert rci.available() is True


def test_available_false_on_connection_error(rci):
    def responder(req):
        raise OSError('connection refused')

    _install_opener(rci, responder)
    assert rci.available() is False


def test_show_running_config_tries_fallback_path(rci):
    """If /rci/show/running-config returns 404, fall back to /rci/show/configuration."""
    rci._authed = True
    paths_tried: list[str] = []

    def responder(req):
        paths_tried.append(req.full_url)
        if 'running-config' in req.full_url:
            return FakeHTTPError(404, b'')
        if 'configuration' in req.full_url:
            body = json.dumps({'message': '! config text\n'}).encode()
            return FakeResponse(200, body)
        raise AssertionError(f'unexpected URL {req.full_url}')

    _install_opener(rci, responder)
    text = rci.show_running_config()
    assert '! config text' in text
    assert any('running-config' in p for p in paths_tried)
    assert any('configuration' in p for p in paths_tried)


def test_show_interface_returns_empty_dict_on_404(rci):
    rci._authed = True

    def responder(req):
        return FakeHTTPError(404, b'')

    _install_opener(rci, responder)
    assert rci.show_interface('Nowhere') == {}


def test_show_running_config_falls_back_to_parse_when_native_is_json(rci):
    """Regression: when /rci/show/running-config returns a structured
    JSON dict instead of a text dump, we MUST fall back to /rci/parse
    to get the CLI-format text. Otherwise parse_running_config() sees
    no `object-group fqdn` lines and the UI shows "no applied services"
    on a router that clearly has them.
    """
    rci._authed = True

    def responder(req):
        url = req.full_url
        if 'rci/parse' in url:
            # parse() returns { parse, prompt, status: [ { message: ... } ] }
            body = json.dumps({
                'parse': 'show running-config',
                'prompt': '(config)>',
                'status': [
                    {'message': 'object-group fqdn telegram'},
                    {'message': '    include t.me'},
                    {'message': '!'},
                ],
            }).encode()
            return FakeResponse(200, body)
        if 'running-config' in url or 'configuration' in url:
            # Native endpoint returns a raw JSON tree without text.
            body = json.dumps({'interfaces': {'PPPoE0': {}}}).encode()
            return FakeResponse(200, body)
        raise AssertionError(f'unexpected URL {url}')

    _install_opener(rci, responder)
    text = rci.show_running_config()
    assert 'object-group fqdn telegram' in text, (
        'running_config must return CLI text, not a JSON dump — '
        'otherwise the running-config parser sees nothing')
    assert 'include t.me' in text


def test_extract_parse_text_joins_status_messages():
    from kn_gui.rci_client import _extract_parse_text
    resp = {
        'parse': 'show x',
        'prompt': '(config)>',
        'status': [
            {'message': 'line 1', 'code': 0},
            {'text': 'line 2'},
            {'code': 0},  # no message
            {'message': 'line 3'},
        ],
    }
    text = _extract_parse_text(resp)
    assert text == 'line 1\nline 2\nline 3'


def test_extract_parse_text_handles_empty_status():
    from kn_gui.rci_client import _extract_parse_text
    # When status is empty but parse echo has content, fall back to it.
    resp = {'parse': '! some text', 'prompt': '(config)>', 'status': []}
    assert _extract_parse_text(resp) == '! some text'
    # When both are empty, return ''.
    assert _extract_parse_text({'parse': '', 'status': []}) == ''
    assert _extract_parse_text(None) == ''


def test_looks_like_cli_text():
    from kn_gui.rci_client import _looks_like_cli_text
    # CLI text — accepted.
    assert _looks_like_cli_text('! Keenetic config\ninterface PPPoE0\n')
    assert _looks_like_cli_text('object-group fqdn x\n')
    assert _looks_like_cli_text('    indented text')
    # JSON — rejected.
    assert not _looks_like_cli_text('{"message": "..."}')
    assert not _looks_like_cli_text('[{"x":1}]')
    # Empty — rejected.
    assert not _looks_like_cli_text('')
    assert not _looks_like_cli_text('   ')


# ── _config_from_json ──────────────────────────────────────────────────────

def test_config_from_json_object_group_fqdn_as_dict():
    """Shape typical of NDMS 4.x: include as dict with host[]."""
    from kn_gui.rci_client import _config_from_json
    text = _config_from_json({
        'object-group': {
            'fqdn': {
                'telegram': {
                    'include': {
                        'host': [{'name': 't.me'}, {'name': 'telegram.org'}],
                    }
                }
            }
        }
    })
    assert 'object-group fqdn telegram' in text
    assert 'include t.me' in text
    assert 'include telegram.org' in text


def test_config_from_json_object_group_fqdn_as_list():
    """Alternative shape: include as list of dicts or strings."""
    from kn_gui.rci_client import _config_from_json
    text = _config_from_json({
        'object-group': {
            'fqdn': {
                'x': {'include': [{'host': 'a.com'}, 'b.com']},
            }
        }
    })
    assert 'include a.com' in text
    assert 'include b.com' in text


def test_config_from_json_dns_proxy_route():
    from kn_gui.rci_client import _config_from_json
    text = _config_from_json({
        'dns-proxy': {
            'route': [
                {'object-group': 'telegram', 'interface': 'SSTP0',
                 'auto': True, 'reject': True},
            ]
        }
    })
    assert 'dns-proxy' in text
    assert 'route object-group telegram SSTP0 auto reject' in text


def test_config_from_json_ip_route():
    from kn_gui.rci_client import _config_from_json
    text = _config_from_json({
        'ip': {
            'route': [
                {'network': '91.108.4.0', 'mask': '255.255.252.0',
                 'interface': 'SSTP0', 'auto': True},
            ]
        }
    })
    assert 'ip route 91.108.4.0 255.255.252.0 SSTP0 auto' in text


def test_config_from_json_empty_input():
    """None or empty dict → empty string, no exceptions."""
    from kn_gui.rci_client import _config_from_json
    assert _config_from_json({}) == ''


def test_config_from_json_unknown_shape_silently_ignored():
    """Defensive parsing — unknown shapes must not raise."""
    from kn_gui.rci_client import _config_from_json
    # dns-proxy.route is a string here, which is none of the expected
    # dict/list shapes; the parser should just skip it without exception.
    text = _config_from_json({'dns-proxy': {'route': 'garbage'}})
    # Nothing produced, but no crash either.
    assert isinstance(text, str)


def test_join_message_handles_list_format():
    """Netcraze OEM returns message as list — must join with \\n."""
    from kn_gui.rci_client import _join_message
    assert _join_message(['a', 'b', 'c']) == 'a\nb\nc'
    assert _join_message('plain string') == 'plain string'
    assert _join_message(None) == ''
    # Skips None elements inside the list.
    assert _join_message(['a', None, 'b']) == 'a\nb'
