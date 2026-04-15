import pytest

from kn_gui.utils import cidr_to_mask, is_error_output, strip_ansi


# ─── cidr_to_mask ────────────────────────────────────────────────────────────

@pytest.mark.parametrize('cidr, expected', [
    ('91.108.4.0/22',    ('91.108.4.0',    '255.255.252.0')),
    ('149.154.160.0/20', ('149.154.160.0', '255.255.240.0')),
    ('10.0.0.0/8',       ('10.0.0.0',      '255.0.0.0')),
    ('192.168.1.1/32',   ('192.168.1.1',   '255.255.255.255')),
    ('0.0.0.0/0',        ('0.0.0.0',       '0.0.0.0')),
])
def test_cidr_to_mask_good(cidr, expected):
    assert cidr_to_mask(cidr) == expected


@pytest.mark.parametrize('bad', ['10.0.0.0', '10.0.0.0/', 'x/y', '10.0.0.0/33', '10.0.0.0/-1'])
def test_cidr_to_mask_bad(bad):
    with pytest.raises(ValueError):
        cidr_to_mask(bad)


# ─── is_error_output ─────────────────────────────────────────────────────────

@pytest.mark.parametrize('text, expected', [
    ('', False),
    ('Done.', False),
    ('Network::RoutingTable: Added route.', False),
    ('Command::Base error[7405602]: argument parse error.', True),
    ('Invalid argument.', True),
    ('ERROR: something', True),
    ('INVALID input', True),
])
def test_is_error_output(text, expected):
    assert is_error_output(text) is expected


# ─── strip_ansi ──────────────────────────────────────────────────────────────

def test_strip_ansi_clears_erase_line():
    # Keenetic CLI emits ESC[K after the prompt.
    assert strip_ansi('(config)> \x1b[K') == '(config)> '


def test_strip_ansi_handles_no_ansi():
    assert strip_ansi('plain text') == 'plain text'


def test_strip_ansi_multiple():
    assert strip_ansi('\x1b[2Jfoo\x1b[K\x1b[31mbar\x1b[0m') == 'foobar'
