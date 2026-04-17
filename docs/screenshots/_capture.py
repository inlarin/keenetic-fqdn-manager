"""Automate capturing README screenshots.

Launches the App(), drives it through each tab with a short delay, grabs
the window region via PIL.ImageGrab, saves PNGs next to this script.

Run:
    python docs/screenshots/_capture.py

Windows-only (Tkinter + ImageGrab). Requires Pillow.
"""
from __future__ import annotations

import ctypes
import os
import sys
import time
from pathlib import Path

# Windows DPI-awareness MUST be set before Tk creates its first window,
# otherwise winfo_{rootx,rooty,width,height} return *logical* pixels while
# ImageGrab works in *physical* pixels — giving a clipped / offset image.
if sys.platform == 'win32':
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PER_MONITOR_AWARE_V2
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass

# Make the repo root importable.
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from PIL import ImageGrab  # noqa: E402


OUT_DIR = Path(__file__).resolve().parent


def _bring_to_front(window) -> None:
    """Force Tk window to the top-most Z-order. Without this, ImageGrab
    captures whatever is visually on top (usually the browser running the
    router web-UI in another window)."""
    try:
        window.deiconify()
        window.lift()
        window.attributes('-topmost', True)
        window.focus_force()
        # Some Windows versions need an explicit activate via HWND.
        if sys.platform == 'win32':
            hwnd = int(window.wm_frame(), 16) if window.wm_frame() else 0
            if hwnd:
                ctypes.windll.user32.SetForegroundWindow(hwnd)
    except Exception as e:
        print(f'  warn: bring_to_front: {e}')


def grab(window, out_name: str, settle_ms: int = 500) -> None:
    """Capture the Toplevel window region and save as PNG."""
    _bring_to_front(window)
    window.update_idletasks()
    window.update()
    # Let the layout finish + any Tk tag-configure painting settle.
    end = time.time() + settle_ms / 1000
    while time.time() < end:
        window.update_idletasks()
        window.update()
        time.sleep(0.02)
    x = window.winfo_rootx()
    y = window.winfo_rooty()
    w = window.winfo_width()
    h = window.winfo_height()
    img = ImageGrab.grab(bbox=(x, y, x + w, y + h), all_screens=True)
    path = OUT_DIR / out_name
    img.save(path, 'PNG', optimize=True)
    print(f'  saved {path.name}  {w}x{h}  (bbox=({x},{y},{x+w},{y+h}))')
    # Drop topmost so subsequent grabs of sibling Toplevels actually appear
    # on top of the main window.
    try:
        window.attributes('-topmost', False)
    except Exception:
        pass


def main() -> int:
    # Ensure we don't accidentally trigger a real GitHub release check.
    os.environ['KN_GUI_DISABLE_UPDATE_CHECK'] = '1'

    from kn_gui.app import App
    from kn_gui.constants import APP_VERSION

    print(f'Launching Keenetic FQDN Manager v{APP_VERSION}...')

    app = App()
    # Place the window in a predictable spot so all screenshots align.
    app.geometry('1180x760+80+60')
    # Pick some catalog entries so the "Services" tab has content.
    for sid in ('telegram', 'claude', 'youtube', 'gemini', 'notion'):
        if sid in app.svc_checked or any(s.get('id') == sid
                                          for s in app.catalog.services):
            app.svc_checked[sid] = True
    app._populate_services()
    app.update_idletasks()

    # 01 — main window, Services tab visible, nothing connected.
    print('01-connect (main window)')
    app.nb.select(app.tab_services)
    grab(app, '01-connect.png')

    # 02 — Services tab with a detail panel populated.
    print('02-services (service details)')
    try:
        # Focus a row so the detail panel populates.
        iid = f'svc::telegram'
        if app.svc_tree.exists(iid):
            app.svc_tree.see(iid)
            app.svc_tree.selection_set(iid)
            app.svc_tree.focus(iid)
            app._on_svc_select()
    except Exception as e:
        print(f'  warn: could not focus telegram row: {e}')
    grab(app, '02-services.png')

    # 03 — State tab (empty without a router, still shows chrome).
    print('03-state (state tab)')
    app.nb.select(app.tab_state)
    grab(app, '03-state.png')

    # 04 — VPN Gate tab (bootstrap servers always loaded).
    print('04-vpngate (vpn gate bootstrap)')
    app.nb.select(app.tab_vpngate)
    grab(app, '04-vpngate.png')

    # 05 — Catalog tab.
    print('05-catalog (catalog tab)')
    app.nb.select(app.tab_catalog)
    grab(app, '05-catalog.png')

    # 06 — Update-available dialog (mocked).
    print('06-update-available (update dialog, mocked)')
    app.nb.select(app.tab_services)
    app.update_idletasks()
    import tkinter as tk
    from tkinter import ttk
    dlg = tk.Toplevel(app)
    dlg.title(f'Keenetic FQDN Manager — обновление')
    dlg.resizable(False, False)
    dlg.transient(app)
    ttk.Label(
        dlg, font=('Segoe UI', 10, 'bold'),
        text='Доступна новая версия: v3.3.0',
    ).pack(padx=24, pady=(18, 4))
    ttk.Label(
        dlg,
        text='Текущая: v3.2.0',
        foreground='#555',
    ).pack(padx=24)
    ttk.Label(
        dlg,
        text='• авто-поиск роутера в LAN\n'
             '• проверка SHA-256 для .exe\n'
             '• 23 новых теста',
        justify='left',
    ).pack(padx=24, pady=(10, 4))
    pbar = ttk.Progressbar(dlg, length=380, mode='determinate',
                            maximum=100, value=42)
    pbar.pack(padx=24, pady=(12, 4))
    ttk.Label(dlg, text='5.0 / 12.0 МБ',
              foreground='#555').pack(padx=24)
    btns = ttk.Frame(dlg, padding=(12, 12, 12, 14))
    btns.pack()
    ttk.Button(btns, text='Скачать и перезапустить',
               style='Accent.TButton').pack(side='right', padx=(6, 0))
    ttk.Button(btns, text='Позже').pack(side='right')
    dlg.update_idletasks()
    px = app.winfo_rootx() + (app.winfo_width() - dlg.winfo_width()) // 2
    py = app.winfo_rooty() + (app.winfo_height() - dlg.winfo_height()) // 2
    dlg.geometry(f'+{px}+{py}')
    grab(dlg, '06-update-available.png')
    dlg.destroy()

    # 07 — Discovery button / log highlight.
    # We capture the header + log area with a discovery-success log line.
    print('07-discover (discovery result)')
    app.log('Поиск Keenetic в локальной сети…', 'info')
    app.log('  Найдено шлюзов: 1', 'info')
    app.log('  Проверка 192.168.32.1…', 'info')
    app.log('Найден Keenetic: 192.168.32.1 (18 мс, realm=keenetic)', 'ok')
    app.host_var.set('192.168.32.1')
    # Flash the discover button visually by gaining focus.
    try:
        app.btn_discover.focus_set()
    except Exception:
        pass
    grab(app, '07-discover.png')

    app.destroy()
    print('Done.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
