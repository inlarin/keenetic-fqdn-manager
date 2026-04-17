"""Main Tkinter App.

Concurrency model:
- UI runs on the main thread.
- Long-running router / HTTP ops are posted via Worker.run(...) to a
  single background thread. Results come back via ui_queue; _drain_queue
  runs on the UI thread (after_idle) and invokes the on_done callback.
- Worker is thread-safe: a lock prevents rapid double-clicks from
  spawning two workers.
- _drain_queue catches callback exceptions so a bug in a handler can't
  kill the main loop."""
from __future__ import annotations

import json
import logging
import queue
import socket
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from concurrent.futures import ThreadPoolExecutor
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Callable, Optional

from .cache import CACHE
from .catalog import Catalog
from .client import KeeneticClient
from .rci_client import RCIClient
from .rci_transport import KeeneticRCIClient
from .constants import (APP_NAME, APP_VERSION, CATEGORY_ICON, ConnState,
                        DEFAULT_ROUTER, DEFAULT_USER, GROUP_NAME_RE,
                        IID_BOOT, IID_CATEGORY, IID_GROUP, IID_IPROUTE,
                        IID_SECTION, IID_SERVICE, STATE_COLOR, STATE_LABEL,
                        TTL_VPNGATE)
from .paths import CACHE_FILE
from .state import (compute_apply_plan, parse_running_config,
                    svc_includes, svc_legacy_routes)
from .net import check_tcp_reachable
from .upstream import refresh_service
from .utils import cidr_to_mask, load_ui_config, save_ui_config
from .vpngate import fetch_vpngate, load_bootstrap_servers
from .worker import Worker


# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

class _UiLogHandler(logging.Handler):
    """Forwards WARNING+ messages from background modules to the App UI log.

    Uses after_idle() so emit() is safe to call from any thread.
    """

    def __init__(self, app: 'App'):
        super().__init__(logging.WARNING)
        self._app = app

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            # Schedule on the main thread — Tkinter is not thread-safe.
            self._app.after_idle(
                lambda m=msg: self._app.log(f'[diag] {m}', 'warn'))
        except Exception:
            pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f'{APP_NAME} v{APP_VERSION}')
        self.minsize(960, 640)

        self.ui_cfg = load_ui_config()
        self.geometry(self.ui_cfg.get('geometry', '1180x760+100+80'))

        self.client: Optional[KeeneticClient] = None
        self.catalog: Catalog = Catalog.load_default()
        self.bootstrap_servers: list[dict] = load_bootstrap_servers()
        self.ui_queue: queue.Queue = queue.Queue()
        self.worker = Worker(self.ui_queue)
        self.interfaces: list[dict] = []
        self.state: dict = {'groups': {}, 'dns_routes': [], 'ip_routes': []}
        self.conn_state: ConnState = ConnState.DISCONNECTED

        self.svc_checked: dict[str, bool] = {}
        self.exclusive_var = tk.BooleanVar(value=bool(self.ui_cfg.get('exclusive', True)))

        self._init_style()
        self._build_menu()
        self._build_ui()
        self._bind_hotkeys()
        self._set_state(ConnState.DISCONNECTED)
        self.protocol('WM_DELETE_WINDOW', self._on_close)
        self._drain_queue()
        # Route WARNING+ messages from rci_client to the UI log.
        self._rci_log_handler = _UiLogHandler(self)
        logging.getLogger('kn_gui.rci_client').addHandler(self._rci_log_handler)
        # Non-blocking update check at startup.
        self._check_update_async()

    def _build_menu(self):
        menubar = tk.Menu(self)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label='Проверить обновления…',
                              command=self._check_update_manual)
        help_menu.add_separator()
        help_menu.add_command(label='Горячие клавиши…', command=self._show_hotkeys,
                              accelerator='F1')
        help_menu.add_separator()
        help_menu.add_command(label=f'О {APP_NAME}…', command=self._show_about)
        menubar.add_cascade(label='Справка', menu=help_menu)
        self.configure(menu=menubar)

    def _show_hotkeys(self):
        messagebox.showinfo(
            f'{APP_NAME} — горячие клавиши',
            'Enter в поле пароля     → Подключиться\n'
            'Ctrl+Enter              → Применить выбранные сервисы\n'
            'F5                      → Обновить состояние с роутера\n'
            'Esc                     → Отключиться (если подключено)\n'
            'Space на строке сервиса → Переключить чекбокс\n'
            'F1                      → Показать это окно',
        )

    def _show_about(self):
        messagebox.showinfo(
            f'О {APP_NAME}',
            f'{APP_NAME} v{APP_VERSION}\n\n'
            'GUI для управления FQDN-маршрутами и IP-маршрутами на роутерах\n'
            'Keenetic (и OEM-форках типа Netcraze).\n\n'
            'Настройки UI сохраняются в %APPDATA%\\KeeneticFqdnManager\\ui.json.\n'
            'Пароль никогда не сохраняется между сессиями.',
        )

    # ── Auto-update ────────────────────────────────────────────────────
    def _check_update_async(self):
        """Non-blocking update check at startup. Silent on failure or
        when already up-to-date — only shows a dialog if a new version
        is available."""
        from .updater import check_for_update

        def do():
            return check_for_update(timeout=6.0)

        def done(info, err):
            if err is not None or info is None:
                return  # silent on errors at startup
            if not info.available:
                return  # up-to-date, nothing to show
            if info.download_url:
                if messagebox.askyesno(
                        f'{APP_NAME} — обновление',
                        f'Доступна новая версия: v{info.latest}\n'
                        f'(текущая: v{info.current})\n\n'
                        'Скачать и установить автоматически?'):
                    self._download_and_apply(info)
            else:
                from .updater import open_release_page
                if messagebox.askyesno(
                        f'{APP_NAME} — обновление',
                        f'Доступна новая версия: v{info.latest}\n'
                        f'(текущая: v{info.current})\n\n'
                        'Открыть страницу загрузки?'):
                    open_release_page(info.release_url)

        self.worker.run(do, on_done=done)

    def _check_update_manual(self):
        """Explicit menu-triggered update check — shows result even when
        up-to-date or on error."""
        from .updater import check_for_update

        def do():
            return check_for_update(timeout=10.0)

        def done(info, err):
            if err is not None:
                messagebox.showwarning(APP_NAME,
                                       f'Не удалось проверить обновления:\n{err}')
                return
            if info is None:
                messagebox.showinfo(APP_NAME, 'Не удалось получить информацию.')
                return
            if info.error:
                messagebox.showwarning(APP_NAME,
                                       f'Ошибка проверки:\n{info.error}')
                return
            if not info.available:
                messagebox.showinfo(APP_NAME,
                                    f'Установлена актуальная версия v{info.current}.')
                return
            if info.download_url:
                if messagebox.askyesno(
                        f'{APP_NAME} — обновление',
                        f'Доступна новая версия: v{info.latest}\n'
                        f'(текущая: v{info.current})\n\n'
                        'Скачать и установить автоматически?'):
                    self._download_and_apply(info)
            else:
                from .updater import open_release_page
                if messagebox.askyesno(
                        f'{APP_NAME} — обновление',
                        f'Доступна новая версия: v{info.latest}\n'
                        f'(текущая: v{info.current})\n\n'
                        'Открыть страницу загрузки?'):
                    open_release_page(info.release_url)

        self.worker.run(do, on_done=done)

    def _download_and_apply(self, info) -> None:
        """Show a progress dialog, download the new exe, then apply the update.

        Uses a plain daemon thread (not the Worker) so the UI stays fully
        responsive and the Worker remains free for other operations.
        The progress bar is driven by ``self.after(0, ...)`` callbacks that
        are safe to post from any thread.
        """
        import os
        import tempfile
        from .updater import IS_FROZEN, apply_update, download_update

        dest = os.path.join(
            tempfile.gettempdir(),
            f'KeeneticFqdnManager_{info.latest}.exe',
        )

        # ── Progress dialog ──────────────────────────────────────────────
        dlg = tk.Toplevel(self)
        dlg.title('Загрузка обновления')
        dlg.resizable(False, False)
        dlg.protocol('WM_DELETE_WINDOW', lambda: None)  # disable × button

        ttk.Label(
            dlg, text=f'Скачивание v{info.latest}…',
            font=('Segoe UI', 10, 'bold'),
        ).pack(padx=24, pady=(18, 6))

        pbar = ttk.Progressbar(dlg, length=380, mode='determinate', maximum=100)
        pbar.pack(padx=24, pady=4)

        status_var = tk.StringVar(value='Инициализация…')
        ttk.Label(dlg, textvariable=status_var,
                  font=('Segoe UI', 9)).pack(padx=24, pady=(4, 4))

        cancelled = threading.Event()

        def _cancel():
            cancelled.set()
            btn_cancel.configure(state='disabled', text='Отмена…')

        btn_cancel = ttk.Button(dlg, text='Отмена', command=_cancel, width=10)
        btn_cancel.pack(pady=(6, 18))

        dlg.update_idletasks()
        px = self.winfo_rootx() + (self.winfo_width() - dlg.winfo_width()) // 2
        py = self.winfo_rooty() + (self.winfo_height() - dlg.winfo_height()) // 2
        dlg.geometry(f'+{px}+{py}')
        dlg.grab_set()

        # ── Background download ──────────────────────────────────────────
        error_box: list = [None]

        def _set_ui(pct: float, text: str) -> None:
            try:
                pbar['value'] = pct
                status_var.set(text)
            except Exception:
                pass

        def _on_progress(done: int, total: int) -> None:
            if cancelled.is_set():
                return
            if total > 0:
                pct = done / total * 100
                mb_d = done / (1 << 20)
                mb_t = total / (1 << 20)
                self.after(0, lambda: _set_ui(pct, f'{mb_d:.1f} / {mb_t:.1f} МБ'))
            else:
                mb_d = done / (1 << 20)
                self.after(0, lambda: _set_ui(0, f'{mb_d:.1f} МБ…'))

        def _run() -> None:
            try:
                download_update(
                    info.download_url, dest,
                    on_progress=_on_progress,
                    is_cancelled=cancelled.is_set,
                )
            except Exception as exc:
                error_box[0] = exc
            self.after(0, _finish)

        def _finish() -> None:
            try:
                dlg.grab_release()
                dlg.destroy()
            except Exception:
                pass

            if cancelled.is_set():
                # Clean up partial file silently.
                try:
                    os.remove(dest)
                except OSError:
                    pass
                return

            if error_box[0]:
                messagebox.showerror(APP_NAME,
                                     f'Ошибка загрузки:\n{error_box[0]}')
                return

            if IS_FROZEN:
                if messagebox.askyesno(
                        f'{APP_NAME} — обновление',
                        f'Версия v{info.latest} готова.\n'
                        'Перезапустить приложение сейчас?'):
                    apply_update(dest)
            else:
                # Dev mode: just report where the file landed.
                messagebox.showinfo(APP_NAME, f'Файл скачан:\n{dest}')

        threading.Thread(target=_run, daemon=True).start()

    # ── Styling ─────────────────────────────────────────────────────────
    def _init_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use('vista' if sys.platform == 'win32' else 'clam')
        except Exception:
            pass
        self._tree_font = tkfont.Font(family='Segoe UI', size=10)
        self._tree_font_bold = tkfont.Font(family='Segoe UI', size=10, weight='bold')
        self._label_font = tkfont.Font(family='Segoe UI', size=9)
        self._mono_font = tkfont.Font(family='Consolas', size=9)
        style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('Status.TLabel', font=('Segoe UI', 9))

    # ── Layout ──────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        main_pane = ttk.PanedWindow(self, orient='vertical')
        main_pane.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self._main_pane = main_pane
        # After first layout pass, put the sash at ~75% (tabs) / 25% (log).
        self.after(120, self._set_default_sash)

        nb_holder = ttk.Frame(main_pane)
        main_pane.add(nb_holder, weight=4)

        nb = ttk.Notebook(nb_holder)
        nb.pack(fill='both', expand=True)
        self.nb = nb
        self.tab_services = ttk.Frame(nb)
        self.tab_state    = ttk.Frame(nb)
        self.tab_vpngate  = ttk.Frame(nb)
        self.tab_catalog  = ttk.Frame(nb)
        nb.add(self.tab_services, text='  Сервисы  ')
        nb.add(self.tab_state,    text='  Состояние роутера  ')
        nb.add(self.tab_vpngate,  text='  VPN Gate  ')
        nb.add(self.tab_catalog,  text='  Каталог  ')
        self._build_services_tab()
        self._build_state_tab()
        self._build_vpngate_tab()
        self._build_catalog_tab()

        log_frame = ttk.LabelFrame(main_pane, text=' Журнал ')
        main_pane.add(log_frame, weight=1)
        log_top = ttk.Frame(log_frame)
        log_top.pack(fill='x', padx=4, pady=(4, 0))
        ttk.Button(log_top, text='Копировать всё', command=self._log_copy_all
                   ).pack(side='left')
        ttk.Button(log_top, text='Копировать выделенное', command=self._log_copy_selection
                   ).pack(side='left', padx=4)
        ttk.Button(log_top, text='Очистить', command=self._log_clear
                   ).pack(side='left', padx=4)
        ttk.Label(log_top, text='(Ctrl+A выделить всё · Ctrl+C копировать · правая кнопка — меню)',
                  foreground='#888', style='Status.TLabel'
                  ).pack(side='left', padx=12)
        # The log widget is display-only: we use Tk's built-in
        # state='disabled' which disables both keyboard input AND typing;
        # selection / copy still work. The log() method momentarily flips
        # it back to 'normal' to append — that's the canonical Tk pattern.
        # The old _log_block_keys hack (selectively dropping keypresses)
        # missed things like Ctrl+V and was brittle.
        self.log_box = scrolledtext.ScrolledText(
            log_frame, height=6, font=self._mono_font, wrap='word',
            relief='flat', borderwidth=0, state='disabled')
        self.log_box.pack(fill='both', expand=True, padx=4, pady=4)

        self.log_box.bind('<Control-a>', lambda e: self._log_select_all())
        self.log_box.bind('<Control-A>', lambda e: self._log_select_all())
        self.log_box.bind('<Button-3>', self._log_context_menu)
        self.log_box.tag_configure('info',  foreground='#333')
        self.log_box.tag_configure('ok',    foreground='#1e7e1e')
        self.log_box.tag_configure('warn',  foreground='#a05c00')
        self.log_box.tag_configure('err',   foreground='#a51818')
        self.log_box.tag_configure('ts',    foreground='#888')
        self._log_menu = tk.Menu(self, tearoff=0)
        self._log_menu.add_command(label='Копировать выделенное', command=self._log_copy_selection)
        self._log_menu.add_command(label='Копировать всё',        command=self._log_copy_all)
        self._log_menu.add_separator()
        self._log_menu.add_command(label='Выделить всё',          command=self._log_select_all)
        self._log_menu.add_command(label='Очистить',              command=self._log_clear)

    def _build_header(self):
        wrap = ttk.Frame(self, padding=(8, 8, 8, 4))
        wrap.pack(fill='x')

        self.status_dot = tk.Label(wrap, text='●',
                                    fg=STATE_COLOR[ConnState.DISCONNECTED],
                                    bg=self.cget('background'),
                                    font=('Segoe UI', 14))
        self.status_dot.grid(row=0, column=0, rowspan=2, padx=(0, 6))
        self.status_label = ttk.Label(wrap, text=STATE_LABEL[ConnState.DISCONNECTED],
                                       style='Status.TLabel')
        self.status_label.grid(row=0, column=1, sticky='w', padx=(0, 12))

        ttk.Label(wrap, text='Адрес:').grid(row=0, column=2, sticky='e', padx=(8, 4))
        self.host_var = tk.StringVar(value=self.ui_cfg.get('last_host', DEFAULT_ROUTER))
        self.host_entry = ttk.Entry(wrap, textvariable=self.host_var, width=18)
        self.host_entry.grid(row=0, column=3, sticky='w')

        ttk.Label(wrap, text='Логин:').grid(row=0, column=4, sticky='e', padx=(12, 4))
        self.user_var = tk.StringVar(value=self.ui_cfg.get('last_user', DEFAULT_USER))
        self.user_entry = ttk.Entry(wrap, textvariable=self.user_var, width=12)
        self.user_entry.grid(row=0, column=5, sticky='w')

        ttk.Label(wrap, text='Пароль:').grid(row=0, column=6, sticky='e', padx=(12, 4))
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(wrap, textvariable=self.pass_var, show='•', width=18)
        self.pass_entry.grid(row=0, column=7, sticky='w')

        self.btn_connect = ttk.Button(wrap, text='Подключить',
                                       command=self._on_connect_click, width=14)
        self.btn_connect.grid(row=0, column=8, padx=10)

        ttk.Label(wrap, text='Интерфейс:').grid(row=1, column=2, sticky='e',
                                                 padx=(8, 4), pady=(4, 0))
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(wrap, textvariable=self.iface_var,
                                         state='disabled', width=22)
        self.iface_combo.grid(row=1, column=3, columnspan=2, sticky='w', pady=(4, 0))

        self.info_var = tk.StringVar(value='')
        ttk.Label(wrap, textvariable=self.info_var, foreground='#555',
                  style='Status.TLabel').grid(row=1, column=5, columnspan=4,
                                               sticky='w', padx=(12, 0), pady=(4, 0))

        # Indeterminate progress bar (shown only while Worker is busy).
        self.progress = ttk.Progressbar(self, mode='indeterminate')

        self.warn_frame = ttk.Frame(self, padding=(8, 4))
        self.warn_frame.pack(fill='x', padx=8, pady=(0, 4))
        self.warn_frame.pack_forget()
        self.warn_label = tk.Label(self.warn_frame, text='', bg='#fff3cd',
                                    fg='#664d03', font=('Segoe UI', 9),
                                    anchor='w', padx=10, pady=6, justify='left',
                                    wraplength=1000)
        self.warn_label.pack(fill='x')

    def _set_default_sash(self):
        try:
            h = self._main_pane.winfo_height()
            if h > 200:
                self._main_pane.sashpos(0, int(h * 0.75))
        except Exception:
            pass

    def _bind_hotkeys(self):
        self.bind('<Control-Return>', lambda e: self._on_apply_services())
        self.bind('<F5>',              lambda e: self._on_refresh_state())
        self.bind('<F1>',              lambda e: self._show_hotkeys())
        self.bind('<Escape>',          lambda e:
                  self._on_disconnect() if self.conn_state == ConnState.CONNECTED else None)
        self.pass_entry.bind('<Return>', lambda e: self._on_connect_click())
        self.host_entry.bind('<Return>', lambda e: self.pass_entry.focus_set())
        self.user_entry.bind('<Return>', lambda e: self.pass_entry.focus_set())

    # ── State transitions & log ─────────────────────────────────────────
    def _set_state(self, s: ConnState, extra: str = ''):
        self.conn_state = s
        self.status_dot.configure(fg=STATE_COLOR[s])
        label = STATE_LABEL[s]
        if extra:
            label += f' — {extra}'
        self.status_label.configure(text=label)
        entry_state = 'normal' if s in (ConnState.DISCONNECTED, ConnState.ERROR) else 'disabled'
        self.host_entry.configure(state=entry_state)
        self.user_entry.configure(state=entry_state)
        self.pass_entry.configure(state=entry_state)
        if s == ConnState.CONNECTED:
            self.btn_connect.configure(text='Отключить', state='normal')
        elif s == ConnState.CONNECTING:
            self.btn_connect.configure(text='Подключение…', state='disabled')
        else:
            self.btn_connect.configure(text='Подключить', state='normal')
        if s != ConnState.CONNECTED:
            self.iface_combo.configure(state='disabled')

    def log(self, msg: str, level: str = 'info'):
        ts = time.strftime('%H:%M:%S')
        # Temporarily enable to append; leave disabled for user input.
        self.log_box.configure(state='normal')
        try:
            self.log_box.insert('end', f'[{ts}] ', 'ts')
            self.log_box.insert('end', f'{msg}\n', level)
            self.log_box.see('end')
        finally:
            self.log_box.configure(state='disabled')

    def _log_select_all(self):
        # Selection works on a disabled Text widget.
        self.log_box.tag_add('sel', '1.0', 'end-1c')
        return 'break'

    def _log_copy_selection(self):
        try:
            text = self.log_box.selection_get()
        except tk.TclError:
            return
        self.clipboard_clear()
        self.clipboard_append(text)

    def _log_copy_all(self):
        text = self.log_box.get('1.0', 'end-1c')
        self.clipboard_clear()
        self.clipboard_append(text)

    def _log_clear(self):
        self.log_box.configure(state='normal')
        try:
            self.log_box.delete('1.0', 'end')
        finally:
            self.log_box.configure(state='disabled')

    def _log_context_menu(self, event):
        try:
            self._log_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._log_menu.grab_release()

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                try:
                    if kind == 'log':
                        if isinstance(payload, tuple) and len(payload) == 2:
                            level, msg = payload
                            self.log(msg, level)
                        else:
                            self.log(str(payload))
                    elif kind == 'done':
                        cb, result, err = payload
                        if cb is not None:
                            cb(result, err)
                    elif kind == 'busy':
                        self._set_busy(bool(payload))
                except Exception as inner:
                    # Never let a buggy callback crash the event loop.
                    try:
                        self.log(f'UI callback raised: {inner!r}', 'err')
                    except Exception:
                        pass
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def _set_busy(self, busy: bool):
        """Toggle the indeterminate progress bar + visual 'busy' hint."""
        if busy:
            self.progress.pack(fill='x', padx=8, pady=(0, 2))
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    # ── Services tab ────────────────────────────────────────────────────
    def _build_services_tab(self):
        from .tabs import services as _svc_tab
        _svc_tab.build(self)

    def _populate_services(self):
        from .tabs import services as _svc_tab
        _svc_tab.populate(self)

    def _svc_state(self, svc: dict) -> tuple[str, str]:
        sid = svc['id']
        if sid not in self.state.get('groups', {}):
            return '', ''
        route = next((r for r in self.state.get('dns_routes', [])
                      if r['group'] == sid), None)
        if not route:
            return 'drifted', '● orphaned group'
        cat_inc = svc_includes(svc)
        rtr_inc = set(self.state['groups'].get(sid, []))
        has_legacy = bool(svc_legacy_routes(svc, self.state.get('ip_routes', [])))
        flags = []
        if route.get('reject'):
            flags.append('kill')
        label_suffix = f' ({",".join(flags)})' if flags else ''
        if cat_inc == rtr_inc and not has_legacy:
            return 'applied', f'● {route["interface"]}{label_suffix}'
        return 'drifted', f'⚠ {route["interface"]}{label_suffix} · drift'

    def _select_applied(self):
        for svc in self.catalog.services:
            state, _ = self._svc_state(svc)
            self.svc_checked[svc['id']] = state in ('applied', 'drifted')
        self._populate_services()

    def _on_svc_click(self, event):
        col = self.svc_tree.identify_column(event.x)
        iid = self.svc_tree.identify_row(event.y)
        if not iid or not iid.startswith(IID_SERVICE):
            return
        # Click on the check column (#1) OR the name column (#0) toggles.
        # Clicks on data columns (#2 FQDN, #3 IPv4, #4 State) just select
        # (to let user inspect details without toggling).
        if col in ('#0', '#1'):
            self._toggle_svc(iid)

    def _on_svc_space(self, event):
        sel = self.svc_tree.selection()
        if sel and sel[0].startswith(IID_SERVICE):
            self._toggle_svc(sel[0])
        return 'break'

    def _toggle_svc(self, iid: str):
        sid = iid.split('::', 1)[1]
        self.svc_checked[sid] = not self.svc_checked.get(sid, False)
        vals = list(self.svc_tree.item(iid, 'values'))
        vals[0] = '☑' if self.svc_checked[sid] else '☐'
        self.svc_tree.item(iid, values=vals)

    def _on_svc_select(self, event=None):
        sel = self.svc_tree.selection()
        if not sel:
            return
        iid = sel[0]
        if iid.startswith(IID_SERVICE):
            sid = iid.split('::', 1)[1]
            svc = self.catalog.service(sid)
            if svc is not None:
                self._show_service_details(svc)
        elif iid.startswith(IID_CATEGORY):
            self._set_details_placeholder()

    def _show_service_details(self, svc: dict):
        t = self.svc_details
        t.configure(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', f'{svc["name"]}\n', 'h1')
        t.insert('end', f'{svc.get("category", "Other")} · id = {svc["id"]}\n', 'muted')
        if svc.get('description'):
            t.insert('end', f'\n{svc["description"]}\n')
        sources = []
        for u in svc.get('upstream', []) or []:
            sources.append(f'{u.get("type", "?")}:{u.get("url", "").rsplit("/", 1)[-1]}')
        for p in svc.get('ipv4_providers', []) or []:
            sources.append(p)
        for a in svc.get('asn', []) or []:
            sources.append(f'AS{a}')
        if sources:
            t.insert('end', '\nИсточники для обновления: ', 'h2')
            t.insert('end', ', '.join(sources) + '\n', 'mono')
            btn = ttk.Button(t, text='⟳ Обновить из upstream',
                              command=lambda s=svc: self._on_refresh_upstream_one(s))
            t.window_create('end', window=btn)
            t.insert('end', '\n')
        state, label = self._svc_state(svc)
        if state == 'applied':
            t.insert('end', '\nПрименено на роутере: ', 'h2')
            t.insert('end', label + '\n', 'ok')
        elif state == 'drifted':
            t.insert('end', '\nПрименено с расхождением: ', 'h2')
            t.insert('end', label + '\n', 'warn')
            cat_inc = svc_includes(svc)
            rtr_inc = set(self.state['groups'].get(svc['id'], []))
            missing = cat_inc - rtr_inc
            extra   = rtr_inc - cat_inc
            if missing:
                t.insert('end', f'  отсутствует на роутере: {", ".join(sorted(missing))}\n', 'mono')
            if extra:
                t.insert('end', f'  лишнее на роутере:      {", ".join(sorted(extra))}\n', 'mono')
            legacy = svc_legacy_routes(svc, self.state.get('ip_routes', []))
            if legacy:
                legacy_txt = ', '.join(
                    f'{r["network"]}/{r["mask"]} через {r["interface"]}' for r in legacy)
                t.insert('end',
                         f'  legacy ip routes для миграции: {legacy_txt}\n', 'mono')
            # Inline one-click recovery
            fix_btn = ttk.Button(t, text='⚒ Исправить расхождение (Apply этот сервис)',
                                   command=lambda s=svc: self._fix_drift(s),
                                   style='Accent.TButton')
            t.window_create('end', window=fix_btn)
            t.insert('end', '\n')
        else:
            t.insert('end', '\nНа роутере отсутствует.\n', 'muted')
        t.insert('end', f'\nFQDN ({len(svc.get("fqdn", []))}):\n', 'h2')
        for d in svc.get('fqdn', []):
            t.insert('end', f'  {d}\n', 'mono')
        if svc.get('ipv4_cidr'):
            t.insert('end', f'\nIPv4 ({len(svc["ipv4_cidr"])}):\n', 'h2')
            for c in svc['ipv4_cidr']:
                t.insert('end', f'  {c}\n', 'mono')
        t.configure(state='disabled')

    def _fix_drift(self, svc: dict):
        """One-click: tick only this service, run Apply."""
        # Preserve prior ticks; overlay this one
        self.svc_checked[svc['id']] = True
        self._populate_services()
        # Also ensure the service is visible (no filter hiding it)
        if hasattr(self, 'svc_filter_var'):
            self.svc_filter_var.set('Все')
            self._populate_services()
        self._on_apply_services()

    def _set_details_placeholder(self):
        t = self.svc_details
        t.configure(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', 'Выберите сервис слева, чтобы увидеть детали.\n', 'muted')
        t.configure(state='disabled')

    # ── Tooltip helper ──────────────────────────────────────────────────
    def _make_tooltip(self, widget, text: str):
        """Show a small tooltip window on hover over the given widget."""
        tip: dict = {'win': None}

        def show(_e=None):
            if tip['win'] is not None:
                return
            x, y = widget.winfo_rootx() + 20, widget.winfo_rooty() + widget.winfo_height() + 4
            w = tk.Toplevel(widget)
            w.wm_overrideredirect(True)
            w.wm_geometry(f'+{x}+{y}')
            tk.Label(w, text=text, justify='left', bg='#ffffe0',
                     fg='#333', relief='solid', borderwidth=1,
                     font=('Segoe UI', 9), padx=8, pady=4).pack()
            tip['win'] = w

        def hide(_e=None):
            if tip['win'] is not None:
                tip['win'].destroy()
                tip['win'] = None

        widget.bind('<Enter>', show)
        widget.bind('<Leave>', hide)

    def _toggle_all_services(self, on: bool):
        for svc in self.catalog.services:
            self.svc_checked[svc['id']] = on
        self._populate_services()

    # ── Current state tab ───────────────────────────────────────────────
    def _build_state_tab(self):
        from .tabs import state as _state_tab
        _state_tab.build(self)

    def _refresh_state_view(self):
        from .tabs import state as _state_tab
        _state_tab.refresh(self)

    def _on_refresh_state(self):
        if not self._ensure_connected():
            return

        def do():
            return self.client.running_config()

        def done(result, err):
            if err is not None:
                self.log(f'Refresh failed: {err}', 'err'); return
            self.state = parse_running_config(result)
            self._refresh_state_view()
            self._populate_services()
            self._update_warnings()
            self.log('State refreshed.', 'ok')

        self.worker.run(do, on_done=done)

    def _on_delete_selected(self):
        if not self._ensure_connected():
            return
        sel = self.state_tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, 'Выберите запись для удаления.')
            return
        iid = sel[0]
        if iid.startswith(IID_GROUP):
            name = iid.split('::', 1)[1]
            if not messagebox.askyesno(APP_NAME,
                    f'Delete FQDN group "{name}" and its dns-proxy route?'):
                return

            def do():
                self.client.delete_fqdn_group(name)
                self.client.save_config()
                return self.client.running_config()

            def done(result, err):
                if err is not None:
                    self.log(f'Delete failed: {err}', 'err'); return
                self.state = parse_running_config(result)
                self._refresh_state_view()
                self._populate_services()
                self.log(f'Deleted group {name}.', 'ok')

            self.worker.run(do, on_done=done)

        elif iid.startswith(IID_IPROUTE):
            idx = int(iid.split('::', 1)[1])
            r = self.state['ip_routes'][idx]
            if not messagebox.askyesno(APP_NAME,
                    f'Delete IP route {r["network"]}/{r["mask"]} via {r["interface"]}?'):
                return

            def do():
                self.client.delete_ip_route(r['network'], r['mask'], r['interface'])
                self.client.save_config()
                return self.client.running_config()

            def done(result, err):
                if err is not None:
                    self.log(f'Delete failed: {err}', 'err'); return
                self.state = parse_running_config(result)
                self._refresh_state_view()
                self._populate_services()
                self.log(f'Deleted IP route {r["network"]}/{r["mask"]}.', 'ok')

            self.worker.run(do, on_done=done)

    def _on_save_config(self):
        if not self._ensure_connected():
            return

        def do():
            return self.client.save_config()

        def done(result, err):
            if err is None:
                self.log('Configuration saved.', 'ok')
            else:
                self.log(f'Save failed: {err}', 'err')

        self.worker.run(do, on_done=done)

    # ── VPN Gate tab ────────────────────────────────────────────────────
    def _build_vpngate_tab(self):
        from .tabs import vpngate as _vpn_tab
        _vpn_tab.build(self)

    def _build_vpngate_bootstrap_tab(self):
        from .tabs import vpngate as _vpn_tab
        _vpn_tab.build_bootstrap(self)

    def _bootstrap_populate(self, results: Optional[dict] = None):
        from .tabs import vpngate as _vpn_tab
        _vpn_tab.populate_bootstrap(self, results)

    def _bootstrap_sort(self, col: str):
        if self.bootstrap_sort_col == col:
            self.bootstrap_sort_rev = not self.bootstrap_sort_rev
        else:
            self.bootstrap_sort_col = col
            self.bootstrap_sort_rev = col in ('mbps', 'uptime', 'reach')
        self._bootstrap_populate()

    def _bootstrap_test_all(self):
        bs = self.bootstrap_servers
        if not bs:
            messagebox.showinfo(APP_NAME, 'Список встроенных серверов пуст.')
            return
        self.bootstrap_status_var.set(
            'Проверяю TCP-доступность на порту 443 (параллельно, до 2с на каждый)…')
        self.bootstrap_reach_results = {}
        self._bootstrap_populate()

        def do():
            results: dict[str, tuple[bool, float]] = {}
            t0 = time.time()
            def probe(srv):
                target = srv.get('ip') or srv['host']
                return srv['host'], check_tcp_reachable(target, 443, timeout=2.0)
            with ThreadPoolExecutor(max_workers=len(bs)) as pool:
                for host, res in pool.map(probe, bs):
                    results[host] = res
            return results, time.time() - t0

        def done(result, err):
            if err is not None:
                self.log(f'Проверка доступности не удалась: {err}', 'err')
                return
            results, dt = result
            ok_count = sum(1 for v in results.values() if v[0])
            self.bootstrap_sort_col = 'reach'
            self.bootstrap_sort_rev = True
            self._bootstrap_populate(results)
            self.bootstrap_status_var.set(
                f'{ok_count}/{len(results)} доступно с этого ПК · {dt:.1f} с')
            self.log(f'Доступность встроенных серверов: {ok_count}/{len(results)} '
                     f'({dt:.1f} с).', 'ok' if ok_count else 'warn')

        self.worker.run(do, on_done=done)

    def _bootstrap_create_interface(self):
        if not self._ensure_connected():
            return
        comps = self.client.router_info.get('components') or set()
        if comps and 'sstp' not in comps:
            messagebox.showerror(APP_NAME,
                'Компонент SSTP-клиент не установлен на роутере. '
                'Установите через веб-UI (страница Компоненты), перезагрузите и попробуйте снова.')
            return
        sel = self.bootstrap_tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME,
                'Сначала выберите сервер в таблице.\n\n'
                'Совет: сперва нажмите «Проверить доступность» — доступные '
                'станут зелёными.')
            return
        host_id = sel[0].split('::', 1)[1]
        server = next((s for s in self.bootstrap_servers
                       if s['host'] == host_id), None)
        if not server:
            return
        self._create_sstp_from_server(
            peer=server.get('ip') or server['host'],
            country=server['country_long'],
            label=f'{server["country"]} {server["host"]}',
            extra_info=(f'Скорость: {server["speed_mbps"]} Мбит/с\n'
                        f'Uptime:    {server["uptime_days"]} дней\n'))

    def _create_sstp_from_server(self, peer: str, country: str,
                                  label: str, extra_info: str = ''):
        existing_names = [i['name'] for i in self.interfaces]
        idx = self.client.find_free_sstp_index(existing_names)
        new_name = f'SSTP{idx}'
        desc = f'VPN Gate {label}'
        if not messagebox.askyesno(APP_NAME,
                f'Создать SSTP-интерфейс «{new_name}»?\n\n'
                f'Пир:     {peer}\n'
                f'Страна:  {country}\n'
                f'{extra_info}'
                f'Логин:   vpn / vpn\n\n'
                'Интерфейс подключится сразу после создания.'):
            return
        self.log(f'Создаю {new_name} ({peer})…')

        def do():
            errs = self.client.create_sstp_interface(
                new_name, peer=peer, user='vpn', password='vpn',
                description=desc, auto_connect=True)
            self.client.save_config()
            ifaces = self.client.list_interfaces()
            return new_name, ifaces, errs

        def done(result, err):
            if err is not None:
                self.log(f'Не удалось создать интерфейс: {err}', 'err')
                messagebox.showerror(APP_NAME, str(err))
                return
            nm, ifaces, errs = result
            self.interfaces = ifaces
            names = [i['name'] for i in ifaces]
            self.iface_combo.configure(values=names, state='readonly')
            if nm in names:
                self.iface_var.set(nm)
            for e in errs:
                self.log(f'  {nm}: {e}', 'warn')
            self.log(f'✓ Создан {nm}, выбран как текущий интерфейс.', 'ok')
            self._update_warnings()
            messagebox.showinfo(APP_NAME,
                f'Интерфейс {nm} создан.\n\n'
                'Дальше: на вкладке Сервисы отметьте «VPN Gate (vpngate.net)» и '
                'нажмите Применить — это откроет vpngate.net через новый туннель, '
                'после чего вкладка «Актуальный список» заработает.')

        self.worker.run(do, on_done=done)

    def _build_vpngate_live_tab(self):
        from .tabs import vpngate as _vpn_tab
        _vpn_tab.build_live(self)

    def _vpngate_populate_country_filter(self):
        from .tabs import vpngate as _vpn_tab
        _vpn_tab.populate_country_filter(self)

    def _vpngate_repaint(self):
        from .tabs import vpngate as _vpn_tab
        _vpn_tab.repaint_live(self)

    def _vpngate_sort(self, col: str):
        if self.vpngate_sort_col == col:
            self.vpngate_sort_rev = not self.vpngate_sort_rev
        else:
            self.vpngate_sort_col = col
            self.vpngate_sort_rev = col in ('mbps', 'uptime', 'sessions', 'reach')
        self._vpngate_repaint()

    def _vpngate_selected(self) -> Optional[dict]:
        sel = self.vpngate_tree.selection()
        if not sel:
            return None
        hn = sel[0]
        for s in self.vpngate_shown:
            if s.get('HostName') == hn:
                return s
        return None

    def _vpngate_copy_host(self):
        s = self._vpngate_selected()
        if not s:
            messagebox.showinfo(APP_NAME, 'Выберите сервер в таблице.'); return
        text = f'{s.get("HostName")}:443'
        self.clipboard_clear(); self.clipboard_append(text)
        self.log(f'Скопировано: {text}', 'ok')

    def _vpngate_copy_creds(self):
        self.clipboard_clear(); self.clipboard_append('vpn')
        messagebox.showinfo(APP_NAME,
                             'Скопирован логин «vpn». Нажмите OK, затем нажмите кнопку ещё '
                             'раз чтобы скопировать пароль.')
        self.clipboard_clear(); self.clipboard_append('vpn')
        self.log('Скопированы учётные данные VPN Gate (vpn/vpn)', 'ok')

    def _vpngate_create_interface(self):
        if not self._ensure_connected():
            return
        comps = self.client.router_info.get('components') or set()
        if comps and 'sstp' not in comps:
            messagebox.showerror(APP_NAME,
                'Компонент SSTP-клиент не установлен на роутере.')
            return
        s = self._vpngate_selected()
        if not s:
            messagebox.showinfo(APP_NAME, 'Выберите сервер в таблице.')
            return
        self._create_sstp_from_server(
            peer=s.get('HostName', ''),
            country=s.get('CountryLong', '?'),
            label=f'{s.get("CountryShort", "?")} {s.get("HostName", "")}')

    def _on_vpngate_refresh(self):
        self.vpngate_status_var.set('Загружаю…')

        def do():
            return fetch_vpngate(force=True)

        def done(result, err):
            if err is not None:
                self.vpngate_status_var.set(f'Ошибка загрузки: {err}')
                self.log(f'VPN Gate — ошибка загрузки: {err}', 'err')
                return
            self.vpngate_all = result
            self.vpngate_reach_results = {}
            self._vpngate_populate_country_filter()
            self._vpngate_repaint()
            self.vpngate_status_var.set(
                f'{len(result)} серверов (свежий список) · нажмите «Проверить '
                'доступность», чтобы увидеть какие из них действительно доступны')
            self.log(f'VPN Gate: загружено {len(result)} серверов.', 'ok')

        self.worker.run(do, on_done=done)

    def _vpngate_test_reach(self):
        if not self.vpngate_all:
            messagebox.showinfo(APP_NAME, 'Сначала обновите актуальный список.')
            return
        targets = list(self.vpngate_shown) or list(self.vpngate_all)
        self.vpngate_status_var.set(
            f'Проверяю TCP-доступность на {len(targets)} серверах '
            '(параллельно, до 2с на каждый)…')
        self.vpngate_reach_results = {}
        self._vpngate_repaint()

        def do():
            results: dict[str, tuple[bool, float]] = {}
            t0 = time.time()
            def probe(srv):
                target = srv.get('IP') or srv.get('HostName')
                return srv.get('HostName', ''), check_tcp_reachable(target, 443, timeout=2.0)
            with ThreadPoolExecutor(max_workers=min(32, len(targets))) as pool:
                for host, res in pool.map(probe, targets):
                    if host:
                        results[host] = res
            return results, time.time() - t0, len(targets)

        def done(result, err):
            if err is not None:
                self.log(f'Проверка доступности не удалась: {err}', 'err')
                return
            results, dt, tested = result
            self.vpngate_reach_results = results
            self.vpngate_sort_col = 'reach'
            self.vpngate_sort_rev = True
            self._vpngate_repaint()
            ok_count = sum(1 for v in results.values() if v[0])
            self.vpngate_status_var.set(
                f'{ok_count}/{tested} доступно · {dt:.1f} с · отсортировано по доступности')
            self.log(f'Доступность в актуальном списке: {ok_count}/{tested} '
                     f'({dt:.1f} с).', 'ok' if ok_count else 'warn')

        self.worker.run(do, on_done=done)

    # ── Catalog tab ─────────────────────────────────────────────────────
    def _build_catalog_tab(self):
        from .tabs import catalog as _catalog_tab
        _catalog_tab.build(self)

    # ── Connection management ───────────────────────────────────────────
    def _on_connect_click(self):
        if self.conn_state == ConnState.CONNECTED:
            self._on_disconnect()
        else:
            self._on_connect()

    def _on_connect(self):
        host = self.host_var.get().strip()
        user = self.user_var.get().strip()
        password = self.pass_var.get()
        if not host or not user or not password:
            messagebox.showwarning(APP_NAME, 'Введите адрес, имя пользователя и пароль.')
            return
        self._set_state(ConnState.CONNECTING)
        self.log(f'Connecting to {host} as {user}…')

        def connect_and_probe():
            if self.client is not None:
                try:
                    self.client.close()
                except Exception:
                    pass
            # Try RCI first (no plaintext password); fall back to Telnet.
            c = None
            transport_name = 'RCI'
            try:
                rci_probe = RCIClient(host)
                if rci_probe.available():
                    rc = KeeneticRCIClient(host)
                    rc.login(user, password)
                    c = rc
                    transport_name = 'RCI (HTTP)'
                else:
                    rci_probe.close()
            except Exception:
                transport_name = 'Telnet (RCI unavailable)'
            if c is None:
                c = KeeneticClient(host)
                c.login(user, password)
                transport_name = 'Telnet'
                try:
                    components = c.get_components()
                except Exception:
                    components = set()
                c.router_info['components'] = components
            ifaces = c.list_interfaces()
            cfg = c.running_config()
            c.router_info['_transport'] = transport_name
            return c, ifaces, cfg

        def done(result, err):
            # Clear the password from the StringVar on both success AND failure.
            self.pass_var.set('')
            if err is not None:
                self._set_state(ConnState.ERROR)
                self._handle_connect_error(err)
                return
            self.client, self.interfaces, cfg = result
            self.state = parse_running_config(cfg)
            if not cfg:
                self.log(
                    'Конфиг роутера не удалось прочитать — '
                    'текущее состояние неизвестно (нажмите «Обновить» чтобы повторить).',
                    'warn',
                )
            names = [i['name'] for i in self.interfaces]
            self.iface_combo.configure(values=names, state='readonly')
            saved_iface = self.ui_cfg.get('last_interface', '')
            if saved_iface in names:
                self.iface_var.set(saved_iface)
            else:
                preferred = next((i for i in self.interfaces
                                  if i.get('type') in ('SSTP', 'Wireguard', 'OpenVPN', 'L2TP', 'PPTP')
                                  and i.get('connected') == 'yes'), None)
                if preferred:
                    self.iface_var.set(preferred['name'])
                elif names:
                    self.iface_var.set(names[0])
            v = self.client.router_info.get('version', '?')
            vendor = self.client.router_info.get('vendor', '')
            transport = self.client.router_info.get('_transport', '?')
            self.info_var.set(
                f'{vendor} NDMS {v} · {transport} · '
                f'{len(self.interfaces)} interfaces · '
                f'{len(self.state["groups"])} FQDN groups · '
                f'{len(self.state["ip_routes"])} IP routes')
            self._set_state(ConnState.CONNECTED,
                            f'{self.iface_var.get() or "нет интерфейса"}')
            self.log(f'Подключено. Интерфейс: {self.iface_var.get()}', 'ok')
            self._populate_services()
            self._refresh_state_view()
            self._update_warnings()
            self.ui_cfg['last_host'] = host
            self.ui_cfg['last_user'] = user
            save_ui_config(self.ui_cfg)
            # First-run redirect: if there are no VPN-client interfaces at all,
            # jump to the VPN Gate bootstrap tab — that's the onboarding path.
            if not any(i.get('type') in ('SSTP', 'L2TP', 'OpenVPN', 'Wireguard', 'PPTP')
                       for i in self.interfaces):
                try:
                    self.nb.select(self.tab_vpngate)
                except Exception:
                    pass

        self.worker.run(connect_and_probe, on_done=done)

    def _on_disconnect(self):
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
        self.client = None
        self.interfaces = []
        self.state = {'groups': {}, 'dns_routes': [], 'ip_routes': []}
        self.info_var.set('')
        self.iface_combo.configure(values=[], state='disabled')
        self.iface_var.set('')
        self._set_state(ConnState.DISCONNECTED)
        self._populate_services()
        self._refresh_state_view()
        self.warn_frame.pack_forget()
        self.log('Disconnected.', 'info')

    def _update_warnings(self):
        warns: list[str] = []
        if self.client:
            comps = self.client.router_info.get('components') or set()
            if comps and 'sstp' not in comps:
                warns.append(
                    '⚠  На роутере НЕ установлен компонент «SSTP-клиент». '
                    'Создавать/использовать SSTP-интерфейсы не получится. '
                    'В веб-UI: Настройки системы → Компоненты → включить '
                    '«SSTP-клиент», применить, перезагрузить.')
            iface_name = self.iface_var.get().strip()
            if iface_name:
                st = next((i for i in self.interfaces if i.get('name') == iface_name), {})
                connected = st.get('connected', '') == 'yes'
                link_up = st.get('link', '') == 'up'
                if not (connected and link_up):
                    bits = []
                    if st.get('link'):      bits.append(f'link={st["link"]}')
                    if st.get('connected'): bits.append(f'connected={st["connected"]}')
                    warns.append(
                        f'⚠  Выбранный интерфейс «{iface_name}» НЕ активен '
                        f'({", ".join(bits) or "нет данных"}). При включённом kill switch '
                        'трафик к защищённым сервисам будет дропаться, пока '
                        'интерфейс не поднимется.')
        if self.client and not any(i.get('type') in
                                   ('SSTP', 'L2TP', 'OpenVPN', 'Wireguard', 'PPTP')
                                   for i in self.interfaces):
            warns.append(
                'ℹ  На роутере нет ни одного VPN-клиента. Откройте вкладку VPN Gate → '
                'Встроенные серверы и создайте первый SSTP-интерфейс.')
        if warns:
            self.warn_label.configure(text='\n\n'.join(warns))
            self.warn_frame.pack(fill='x', padx=8, pady=(0, 4),
                                  before=self._main_pane)
        else:
            self.warn_frame.pack_forget()

    def _handle_connect_error(self, err: Exception):
        cls = type(err).__name__
        msg = str(err)
        if isinstance(err, PermissionError):
            human = (f'Ошибка логина — проверьте логин и пароль.\n\n{msg}')
        elif isinstance(err, socket.timeout) or 'timed out' in msg.lower():
            human = ('Таймаут подключения к роутеру. '
                     'Роутер доступен по сети? Правильный IP?')
        elif isinstance(err, ConnectionRefusedError):
            human = ('Соединение отклонено. '
                     'Доступен ли веб-интерфейс роутера? '
                     'Если RCI недоступен — включите Telnet (порт 23):\n'
                     'Веб-UI → Настройки системы → Компоненты → Telnet.')
        elif isinstance(err, socket.gaierror):
            human = f'Не удаётся разрешить имя «{self.host_var.get()}».'
        elif isinstance(err, ConnectionError):
            human = f'Ошибка протокола: {msg}'
        else:
            human = f'{cls}: {msg}'
        self.log(f'Не подключено: {human}', 'err')
        messagebox.showerror(APP_NAME, human)

    def _ensure_connected(self) -> bool:
        if self.client is None or self.conn_state != ConnState.CONNECTED:
            messagebox.showwarning(APP_NAME, 'Сначала подключитесь к роутеру.')
            return False
        return True

    # ── Apply ────────────────────────────────────────────────────────────
    def _on_apply_services(self):
        if not self._ensure_connected():
            return
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showwarning(APP_NAME, 'Выберите интерфейс.')
            return
        selected = [s for s in self.catalog.services
                     if self.svc_checked.get(s['id'])]
        if not selected:
            messagebox.showinfo(APP_NAME, 'Отметьте хотя бы один сервис.')
            return
        exclusive = self.exclusive_var.get()
        plan = compute_apply_plan(selected, self.state, iface, exclusive)

        def fmt(items: list, verb: str) -> str:
            if not items:
                return ''
            lines = [f'  • {verb}:']
            for it in items[:8]:
                rsn = ', '.join(it['reasons'][:3])
                lines.append(f'      {it["svc"]["name"]} ({rsn})')
            if len(items) > 8:
                lines.append(f'      … and {len(items) - 8} more')
            return '\n'.join(lines) + '\n'

        if not plan['create'] and not plan['update']:
            messagebox.showinfo(APP_NAME,
                f'Все {len(plan["skip"])} выбранных сервис(ов) уже актуальны. '
                'Нечего применять.')
            return

        summary = [
            f'План применения через {iface}',
            f'Kill switch: {"ВКЛ" if exclusive else "выкл"}', '',
            fmt(plan['create'], f'СОЗДАТЬ   ({len(plan["create"])})'),
            fmt(plan['update'], f'ОБНОВИТЬ  ({len(plan["update"])})'),
            fmt(plan['skip'],   f'ПРОПУСТИТЬ ({len(plan["skip"])} уже актуально)'),
            'Применить?']
        if not messagebox.askyesno(APP_NAME, '\n'.join(x for x in summary if x)):
            return

        # Snapshot legacy-route index before kicking off worker, so it can't
        # see an intermediate mutated state from any concurrent Refresh.
        ip_routes_snapshot = list(self.state.get('ip_routes', []))
        to_do = plan['create'] + plan['update']
        skip = plan['skip']

        def do_apply():
            c = self.client
            assert c is not None
            total_inc = touched = migrated = 0
            for entry in to_do:
                svc = entry['svc']
                group = svc['id']
                if not GROUP_NAME_RE.match(group):
                    self.ui_queue.put(('log', ('warn',
                        f'SKIP {svc["name"]}: invalid group id "{group}"')))
                    continue
                includes = list(svc.get('fqdn', [])) + list(svc.get('ipv4_cidr', []))
                c.delete_fqdn_group(group)
                created_names, errs = c.create_fqdn_group(
                    group, includes, description=svc.get('name', ''))
                for e in errs:
                    self.ui_queue.put(('log', ('warn', f'  {group}: {e}')))
                # Bind EVERY created group (including split-parts like
                # name_2, name_3) to the VPN interface. Without this,
                # traffic to domains in split-parts leaks via ISP.
                for gn in created_names:
                    c.bind_fqdn_route(gn, iface, auto=True, reject=exclusive)
                total_inc += len(includes)
                suffix = ' [kill switch]' if exclusive else ''
                self.ui_queue.put(('log', ('ok',
                    f'✓ {svc["name"]}  →  {iface}{suffix}  '
                    f'({len(svc.get("fqdn", []))} FQDN + '
                    f'{len(svc.get("ipv4_cidr", []))} IPv4)')))
                for legacy in svc_legacy_routes(svc, ip_routes_snapshot):
                    c.delete_ip_route(legacy['network'], legacy['mask'],
                                       legacy['interface'])
                    self.ui_queue.put(('log', ('warn',
                        f'  ↳ migrated: removed legacy ip route '
                        f'{legacy["network"]}/{legacy["mask"]} via '
                        f'{legacy["interface"]}')))
                    migrated += 1
                touched += 1
            for entry in skip:
                self.ui_queue.put(('log', ('info',
                    f'= {entry["svc"]["name"]} already up-to-date, skipped')))
            c.save_config()
            cfg = c.running_config()
            return touched, total_inc, migrated, cfg

        def done(result, err):
            if err is not None:
                self.log(f'Применение не удалось: {err}', 'err')
                messagebox.showerror(APP_NAME, str(err))
                return
            touched, total_inc, migrated, cfg = result
            self.state = parse_running_config(cfg)
            self._refresh_state_view()
            self._populate_services()
            extra = f', мигрировано {migrated} legacy ip route' if migrated else ''
            self.log(
                f'Применено {touched} сервис(ов): {total_inc} записей (FQDN+IPv4)'
                f'{extra}. Конфиг сохранён.', 'ok')
            # Switch to Current state so the user sees what actually landed.
            try:
                self.nb.select(self.tab_state)
            except Exception:
                pass

        self.worker.run(do_apply, on_done=done)

    # ── Upstream refresh / import ────────────────────────────────────────
    def _on_refresh_upstream_all(self):
        targets = [s for s in self.catalog.services
                    if s.get('upstream') or s.get('ipv4_providers') or s.get('asn')]
        if not targets:
            messagebox.showinfo(APP_NAME,
                'No services in the catalog declare an upstream.')
            return
        if not messagebox.askyesno(APP_NAME,
                f'Fetch upstream lists for {len(targets)} service(s)?\n\n'
                'Domains / CIDRs from v2fly, Cloudflare, AWS, RIPEstat etc. will '
                'be merged into the in-memory catalog.\n\n'
                'This does NOT push to the router — run Apply after to propagate.'):
            return
        self.log(f'Refreshing upstream for {len(targets)} service(s)…')

        def do():
            results = []
            for svc in targets:
                bf = len(svc.get('fqdn', [])); bi = len(svc.get('ipv4_cidr', []))
                new_svc, info, errs = refresh_service(svc, merge=True)
                af = len(new_svc.get('fqdn', [])); ai = len(new_svc.get('ipv4_cidr', []))
                results.append((svc['id'], new_svc, info, errs, bf, af, bi, ai))
            return results

        def done(result, err):
            if err is not None:
                self.log(f'Refresh failed: {err}', 'err')
                messagebox.showerror(APP_NAME, str(err))
                return
            updated = 0
            for sid, new_svc, info_lines, errs, bf, af, bi, ai in result:
                for idx, s in enumerate(self.catalog.data.get('services', [])):
                    if s.get('id') == sid:
                        self.catalog.data['services'][idx] = new_svc
                        break
                delta_f = af - bf; delta_i = ai - bi
                if errs:
                    for e in errs:
                        self.log(f'  {sid}: {e}', 'warn')
                if delta_f or delta_i:
                    self.log(f'↻ {sid}: FQDN {bf}→{af} (+{delta_f}), '
                             f'IPv4 {bi}→{ai} (+{delta_i})', 'ok')
                    updated += 1
                else:
                    self.log(f'= {sid}: no changes', 'info')
            self._populate_services()
            self._set_details_placeholder()
            self.log(f'Upstream refresh done: {updated} service(s) updated.', 'ok')
            messagebox.showinfo(APP_NAME,
                f'Refreshed {updated} service(s) out of {len(result)}.')

        self.worker.run(do, on_done=done)

    def _on_refresh_upstream_one(self, svc: dict):
        self.log(f'Refreshing upstream for {svc["id"]}…')

        def do():
            return refresh_service(svc, merge=True)

        def done(result, err):
            if err is not None:
                self.log(f'Refresh failed: {err}', 'err')
                messagebox.showerror(APP_NAME, str(err))
                return
            new_svc, info_lines, errs = result
            for idx, s in enumerate(self.catalog.data.get('services', [])):
                if s.get('id') == svc['id']:
                    self.catalog.data['services'][idx] = new_svc
                    break
            for ln in info_lines:
                self.log(f'  {svc["id"]}: {ln}', 'info')
            for e in errs:
                self.log(f'  {svc["id"]}: {e}', 'warn')
            self.log(f'↻ {svc["id"]}: FQDN→{len(new_svc["fqdn"])}, '
                     f'IPv4→{len(new_svc["ipv4_cidr"])}', 'ok')
            self._populate_services()
            self._show_service_details(new_svc)

        self.worker.run(do, on_done=done)

    def _on_cache_clear(self):
        if not messagebox.askyesno(APP_NAME,
                'Clear the on-disk cache? Next refresh will re-fetch everything.'):
            return
        CACHE.clear()
        self.log('Disk cache cleared.', 'ok')
        self._build_catalog_tab()

    def _on_import_url(self):
        url = self.url_var.get().strip()
        if not url:
            return

        def do():
            return Catalog.load_url(url)

        def done(result, err):
            if err is not None:
                self.log(f'Import failed: {err}', 'err')
                messagebox.showerror(APP_NAME, f'Import failed:\n\n{err}')
                return
            self.catalog = result
            self.svc_checked.clear()
            self._populate_services()
            self._build_catalog_tab()
            self.log(f'Loaded "{self.catalog.name}" v{self.catalog.version} '
                     f'({len(self.catalog.services)} services).', 'ok')

        self.worker.run(do, on_done=done)

    def _on_import_file(self):
        path = filedialog.askopenfilename(
            filetypes=[('JSON', '*.json'), ('All', '*.*')])
        if not path:
            return

        def do():
            return Catalog.load_file(path)

        def done(result, err):
            if err is not None:
                self.log(f'Load failed: {err}', 'err')
                messagebox.showerror(APP_NAME, f'Failed to load: {err}')
                return
            self.catalog = result
            self.svc_checked.clear()
            self._populate_services()
            self._build_catalog_tab()
            self.log(f'Loaded local "{self.catalog.name}" '
                     f'({len(self.catalog.services)} services).', 'ok')

        self.worker.run(do, on_done=done)

    def _on_export_catalog(self):
        path = filedialog.asksaveasfilename(
            defaultextension='.json', filetypes=[('JSON', '*.json')],
            initialfile='services.json')
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.catalog.data, f, ensure_ascii=False, indent=2)
            self.log(f'Catalog exported to {path}', 'ok')
        except Exception as e:
            messagebox.showerror(APP_NAME, f'Export failed: {e}')

    # ── Close ────────────────────────────────────────────────────────────
    def _on_close(self):
        try:
            self.ui_cfg['geometry'] = self.geometry()
            self.ui_cfg['last_interface'] = self.iface_var.get()
            self.ui_cfg['exclusive'] = bool(self.exclusive_var.get())
            save_ui_config(self.ui_cfg)
        except Exception:
            pass
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
        self.destroy()


def main():
    try:
        app = App()
        app.mainloop()
    except Exception as e:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, str(e), APP_NAME, 0x10)
        except Exception:
            print(f'FATAL: {e}', file=sys.stderr)
        raise


if __name__ == '__main__':
    main()
