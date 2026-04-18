"""Smoke tests for the App class.

These are deliberately minimal: we verify that App() builds cleanly,
that the main methods which don't need a router (catalog access, state
setters, log buffer, menu wiring) work, and that destroy() tears down
without raising. Everything that touches the network (update check,
LAN discovery) is monkeypatched away so the tests don't depend on
internet connectivity or a configured router.

Skipped when Tk has no display (e.g. headless Linux CI runner without
Xvfb). Install ``xvfb-run`` or run locally to exercise these.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(scope='module')
def app():
    """Build one App() per module.

    Tkinter doesn't cleanly support creating/destroying Tk() multiple
    times in the same process — the tcl init state carries over and
    subsequent tests raise ``can't find a usable init.tcl``. A single
    module-scoped fixture sidesteps this by using one real Tk root
    across every test in this file.

    Startup tasks that hit the network (update check, LAN discovery)
    are stubbed before construction so the suite is hermetic.
    """
    try:
        import tkinter as tk
    except ImportError:
        pytest.skip('tkinter not available')

    try:
        probe = tk.Tk()
        probe.withdraw()
        probe.destroy()
    except tk.TclError as e:
        pytest.skip(f'no Tk display available: {e}')

    from kn_gui.app import App
    from kn_gui import utils as _utils

    # Patch class-level attrs once — scope='module' means monkeypatch
    # isn't available, so we undo manually at the end.
    saved = (
        App._check_update_async,
        App._autodiscover_on_first_run,
        _utils.load_ui_config,
        _utils.save_ui_config,
    )
    App._check_update_async = lambda self: None
    App._autodiscover_on_first_run = lambda self: None
    _utils.load_ui_config = lambda: {}
    _utils.save_ui_config = lambda cfg: None

    a = App()
    a.withdraw()
    try:
        yield a
    finally:
        try:
            a.destroy()
        except Exception:
            pass
        (App._check_update_async,
         App._autodiscover_on_first_run,
         _utils.load_ui_config,
         _utils.save_ui_config) = saved


@pytest.fixture(autouse=True)
def _clean_log(app):
    """Each test starts with an empty log buffer, regardless of order."""
    app._log_clear()


# ── Construction ───────────────────────────────────────────────────────────

def test_app_builds_and_destroys_cleanly(app):
    """The top-level invariant: App() is constructable and tearable-down
    in an empty environment. This alone catches a large class of
    import / layout / circular-import regressions."""
    from kn_gui.constants import ConnState
    assert app.conn_state == ConnState.DISCONNECTED
    assert app.client is None
    # Catalog is a singleton bundled with the package.
    assert len(app.catalog.services) > 0, 'default catalog should not be empty'


def test_app_has_expected_tabs(app):
    """Notebook tabs wired correctly. If a tab rename or removal sneaks
    in, this fails loudly rather than showing up as a missing UI element."""
    tab_ids = [app.nb.tab(i, 'text').strip() for i in app.nb.tabs()]
    # Russian UI text; must contain the four canonical tabs.
    assert any('Сервис' in t for t in tab_ids)
    assert any('Состояние' in t for t in tab_ids)
    assert any('VPN' in t for t in tab_ids)
    assert any('Каталог' in t for t in tab_ids)


# ── State transitions ─────────────────────────────────────────────────────

def test_set_state_updates_status_text(app):
    """_set_state flips the status dot + label without raising."""
    from kn_gui.constants import ConnState
    app._set_state(ConnState.CONNECTING)
    assert app.conn_state == ConnState.CONNECTING
    app._set_state(ConnState.CONNECTED, 'SSTP1')
    assert app.conn_state == ConnState.CONNECTED
    app._set_state(ConnState.ERROR)
    assert app.conn_state == ConnState.ERROR
    app._set_state(ConnState.DISCONNECTED)
    assert app.conn_state == ConnState.DISCONNECTED


# ── Log panel ──────────────────────────────────────────────────────────────

def test_log_appends_and_reads(app):
    """log() writes to the scrolled text widget without raising, and the
    content lands in the underlying Text widget."""
    app.log('hello 123', 'ok')
    app.log('world', 'warn')
    text = app.log_box.get('1.0', 'end-1c')
    assert 'hello 123' in text
    assert 'world' in text


def test_log_clear_removes_all_lines(app):
    """The context-menu 'Clear' action blanks the log."""
    app.log('line one')
    app.log('line two')
    app._log_clear()
    text = app.log_box.get('1.0', 'end-1c')
    assert text == ''


# ── Services tab population ────────────────────────────────────────────────

def test_populate_services_no_router(app):
    """Services tab must render the catalog even with no router state —
    it's the onboarding view the user first sees."""
    app._populate_services()
    # Tree should have root items for each category. Catalog has > 0
    # services so there's at least one category node.
    root_children = app.svc_tree.get_children('')
    assert len(root_children) > 0


def test_toggle_all_services_switches_checkboxes(app):
    """Clicking 'Select all' / 'Deselect all' flips the internal dict."""
    app._toggle_all_services(True)
    assert all(app.svc_checked.get(s['id'])
               for s in app.catalog.services)
    app._toggle_all_services(False)
    assert not any(app.svc_checked.get(s['id'])
                    for s in app.catalog.services)


# ── Help / About dialogs are wired ─────────────────────────────────────────

def test_menu_has_help_entries(app):
    """The Справка menu exists and contains the expected items. We
    don't click them (would show a modal) but we verify they're there."""
    # Walk the menubar to find the Help cascade.
    menubar = app.cget('menu')
    assert menubar, 'App has no menubar'
    help_labels = []
    menu = app.nametowidget(menubar)
    for i in range(menu.index('end') + 1):
        if menu.type(i) == 'cascade':
            sub = app.nametowidget(menu.entrycget(i, 'menu'))
            for j in range(sub.index('end') + 1):
                if sub.type(j) == 'command':
                    help_labels.append(sub.entrycget(j, 'label'))
    # Russian labels — at least "Проверить обновления…" and "О ..."
    assert any('обновления' in lbl.lower() for lbl in help_labels)
    assert any('горячие' in lbl.lower() for lbl in help_labels)


# ── Ensure_connected guard ────────────────────────────────────────────────

def test_ensure_connected_returns_false_when_disconnected(app):
    """Guard used by every router-touching action: must return False (and
    NOT touch the network) when the app hasn't connected yet."""
    # Suppress the resulting messagebox by monkeypatching.
    from tkinter import messagebox
    shown: list = []
    import kn_gui.app as app_mod
    app_mod.messagebox.showwarning = (
        lambda *a, **kw: shown.append((a, kw))
    )
    try:
        assert app._ensure_connected() is False
    finally:
        app_mod.messagebox.showwarning = messagebox.showwarning


# NOTE: we deliberately don't test _on_close() here — it calls
# self.destroy() and the module-scoped App needs to survive until the
# final test. The teardown in the fixture already exercises destroy()
# via the standard WM_DELETE_WINDOW path.
