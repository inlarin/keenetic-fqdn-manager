"""Tests for the transport-agnostic FQDN-group helper.

Before v3.4.1 these tests had to be written twice — once for
client.KeeneticClient (Telnet) and once for KeeneticRCIClient (RCI) —
because each transport carried its own copy of the logic. Now the
helper is a pure function and we can cover all the edge cases in one
place, with the transports just wrapping it.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from kn_gui import _fqdn_group_ops
from kn_gui.constants import MANAGED_INTERFACE_TAG
from kn_gui.utils import MAX_ENTRIES_PER_GROUP


def _make_fakes():
    """Build noop run_expect / run callables that record their calls."""
    calls: list[str] = []

    def run_expect(cmd, timeout=10.0):
        calls.append(cmd)
        return ''

    def run(cmd, timeout=10.0):
        calls.append(cmd)
        return ('', True)

    return calls, run_expect, run


# ── create_fqdn_group ─────────────────────────────────────────────────────

def test_create_rejects_invalid_group_name():
    calls, run_expect, run = _make_fakes()
    created, errs = _fqdn_group_ops.create_fqdn_group(
        '1invalid', ['a.com'], '', run_expect, run)
    assert created == []
    assert any('group name' in e for e in errs)
    # Nothing sent to the router.
    assert calls == []


def test_create_rejects_empty_entries():
    calls, run_expect, run = _make_fakes()
    created, errs = _fqdn_group_ops.create_fqdn_group(
        'foo', [], '', run_expect, run)
    assert created == []
    assert any('no valid entries' in e for e in errs)


def test_create_tags_description_unconditionally():
    calls, run_expect, run = _make_fakes()
    # No description provided — we still emit the bare tag.
    created, _ = _fqdn_group_ops.create_fqdn_group(
        'mine', ['a.com'], '', run_expect, run)
    assert created == ['mine']
    desc_calls = [c for c in calls if c.startswith('description ')]
    assert desc_calls
    assert MANAGED_INTERFACE_TAG in desc_calls[0]


def test_create_prefixes_user_description_with_tag():
    calls, run_expect, run = _make_fakes()
    _fqdn_group_ops.create_fqdn_group(
        'mine', ['a.com'], 'Telegram (vpngate)', run_expect, run)
    desc_calls = [c for c in calls if c.startswith('description ')]
    assert desc_calls
    assert MANAGED_INTERFACE_TAG in desc_calls[0]
    assert 'Telegram (vpngate)' in desc_calls[0]


def test_create_auto_splits_into_name_name_2_name_3():
    """>= 2*MAX_ENTRIES must produce primary + suffixed siblings."""
    calls, run_expect, run = _make_fakes()
    entries = [f'd{i}.example.com' for i in range(MAX_ENTRIES_PER_GROUP * 2 + 1)]
    created, errs = _fqdn_group_ops.create_fqdn_group(
        'big', entries, '', run_expect, run)
    assert created == ['big', 'big_2', 'big_3']
    # Each chunk emitted its own `object-group fqdn <name>` line.
    og_calls = [c for c in calls if c.startswith('object-group fqdn ')]
    assert og_calls == [
        'object-group fqdn big',
        'object-group fqdn big_2',
        'object-group fqdn big_3',
    ]
    # Warning about the split is in errs.
    assert any('split' in e for e in errs)


def test_create_truncates_long_base_name_when_suffix_is_needed():
    """If name_2 would exceed 32 chars, the base is clipped."""
    calls, run_expect, run = _make_fakes()
    # 32-char base + `_2` = 34 chars → must truncate.
    base = 'a' * 32
    entries = [f'd{i}.example.com' for i in range(MAX_ENTRIES_PER_GROUP + 1)]
    created, _ = _fqdn_group_ops.create_fqdn_group(
        base, entries, '', run_expect, run)
    assert all(len(n) <= 32 for n in created)
    assert created[0] == base        # first chunk keeps the exact name
    assert created[1].endswith('_2')


def test_create_emits_exit_after_each_chunk():
    """Every group must be closed with `exit`, even if includes raised."""
    calls = []

    def run_expect(cmd, timeout=10.0):
        calls.append(cmd)
        if cmd.startswith('include '):
            raise RuntimeError('simulated failure')
        return ''

    def run(cmd, timeout=10.0):
        calls.append(cmd)
        return ('', True)

    created, errs = _fqdn_group_ops.create_fqdn_group(
        'foo', ['ok.com'], '', run_expect, run)
    assert created == ['foo']       # group created, just entries failed
    assert 'exit' in calls           # exit still called in finally


def test_create_stripped_wildcards_and_invalid_reported():
    """Wildcards normalize (`*.example.com` → `example.com`), bad
    entries land in errs, good ones go to the router."""
    calls, run_expect, run = _make_fakes()
    created, errs = _fqdn_group_ops.create_fqdn_group(
        'mix', ['*.good.com', 'bad name with space', 'also-good.net'],
        '', run_expect, run)
    includes = [c for c in calls if c.startswith('include ')]
    # Wildcard should have been stripped.
    assert 'include good.com' in includes
    assert 'include also-good.net' in includes
    # Bad entry not sent.
    assert not any('bad name with space' in c for c in includes)


# ── delete_fqdn_group ─────────────────────────────────────────────────────

def test_delete_removes_main_route_and_group_plus_siblings():
    calls, _run_expect, run = _make_fakes()
    _fqdn_group_ops.delete_fqdn_group('telegram', run)
    # Main ones.
    assert 'no dns-proxy route object-group telegram' in calls
    assert 'no object-group fqdn telegram' in calls
    # All split siblings (_2 through _50 = 49 items, each emits 2 cmds).
    assert 'no object-group fqdn telegram_2' in calls
    assert 'no object-group fqdn telegram_50' in calls
    # _51 must NOT be emitted — we stop at 50.
    assert 'no object-group fqdn telegram_51' not in calls


# ── list_managed_fqdn_groups ──────────────────────────────────────────────

def test_list_managed_uses_tag_filter():
    cfg = (
        'object-group fqdn mine_a\n'
        f'    description "{MANAGED_INTERFACE_TAG} Telegram"\n'
        '    include t.me\n'
        '!\n'
        'object-group fqdn user_x\n'
        '    description "hand made"\n'
        '    include example.com\n'
        '!\n'
        'object-group fqdn mine_b\n'
        f'    description "{MANAGED_INTERFACE_TAG}"\n'  # tag alone
        '    include y.com\n'
        '!\n'
    )
    cfg_fn = lambda: cfg
    managed = _fqdn_group_ops.list_managed_fqdn_groups(cfg_fn)
    assert sorted(g['name'] for g in managed) == ['mine_a', 'mine_b']
    for g in managed:
        assert MANAGED_INTERFACE_TAG in g['description']


def test_list_managed_empty_when_nothing_tagged():
    cfg_fn = lambda: (
        'object-group fqdn user_only\n'
        '    description "custom"\n'
        '    include example.com\n'
        '!\n'
    )
    assert _fqdn_group_ops.list_managed_fqdn_groups(cfg_fn) == []


def test_list_managed_carries_entries():
    cfg = (
        'object-group fqdn mine\n'
        f'    description "{MANAGED_INTERFACE_TAG} Telegram"\n'
        '    include t.me\n'
        '    include telegram.org\n'
        '    include web.telegram.org\n'
        '!\n'
    )
    managed = _fqdn_group_ops.list_managed_fqdn_groups(lambda: cfg)
    assert len(managed) == 1
    assert sorted(managed[0]['entries']) == [
        't.me', 'telegram.org', 'web.telegram.org',
    ]
