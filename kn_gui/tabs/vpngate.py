"""VPN Gate tab: two sub-tabs (bootstrap + live list) with shared style.

Only the UI-building + UI-refresh code lives here. All event callbacks
— sort, reachability tests, SSTP creation, clipboard, filtering
controls wired to Entry/Combobox — remain methods on App so the existing
button bindings keep working without rewriting every self.*
reference.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from ..cache import CACHE
from ..constants import IID_BOOT, TTL_VPNGATE


# ── Outer container ───────────────────────────────────────────────────────
def build(app) -> None:
    f = app.tab_vpngate
    inner = ttk.Notebook(f)
    inner.pack(fill='both', expand=True)
    app.tab_vpngate_bootstrap = ttk.Frame(inner)
    app.tab_vpngate_live      = ttk.Frame(inner)
    inner.add(app.tab_vpngate_bootstrap, text='  Встроенные серверы  ')
    inner.add(app.tab_vpngate_live,      text='  Актуальный список  ')
    build_bootstrap(app)
    build_live(app)


# ── Bootstrap (bundled) sub-tab ───────────────────────────────────────────
def build_bootstrap(app) -> None:
    f = app.tab_vpngate_bootstrap
    bs = app.bootstrap_servers
    subnets = len({'.'.join(s['ip'].split('.')[:3]) for s in bs}) if bs else 0
    ttk.Label(f,
              text=f'{len(bs)} серверов, вшитых в приложение, из {subnets} разных /24-подсетей. '
                   'Пригодятся когда vpngate.net недоступен напрямую. '
                   'Логин/пароль универсальны для VPN Gate: vpn / vpn.',
              foreground='#555', wraplength=1100, justify='left'
              ).pack(anchor='w', padx=6, pady=(6, 4))

    toolbar = ttk.Frame(f)
    toolbar.pack(fill='x', padx=4, pady=(0, 4))
    ttk.Button(toolbar, text='🔍 Проверить доступность',
               command=app._bootstrap_test_all).pack(side='left')
    ttk.Button(toolbar, text='▶ Создать SSTP-интерфейс из выбранного',
               command=app._bootstrap_create_interface,
               style='Accent.TButton').pack(side='left', padx=(6, 0))
    # Placed on the right: cleanup action that affects whichever sub-tab
    # the user is on. Wired to a single handler in App.
    ttk.Button(toolbar, text='🗑 Удалить созданные приложением VPN',
               command=app._on_delete_managed_vpns).pack(side='right')
    app.bootstrap_status_var = tk.StringVar(value='Ещё не проверялось')
    ttk.Label(toolbar, textvariable=app.bootstrap_status_var, foreground='#555',
              style='Status.TLabel').pack(side='left', padx=10)

    tf = ttk.Frame(f)
    tf.pack(fill='both', expand=True, padx=4, pady=4)
    cols = ('reach', 'country', 'host', 'ip', 'mbps', 'uptime', 'op')
    app.bootstrap_tree = ttk.Treeview(tf, columns=cols, show='headings',
                                        selectmode='browse')
    headings = {'reach': 'Доступ', 'country': 'Страна', 'host': 'Хост',
                'ip': 'IP', 'mbps': 'Мбит/с', 'uptime': 'Дней', 'op': 'Оператор'}
    widths = {'reach': 80, 'country': 70, 'host': 150, 'ip': 120,
              'mbps': 65, 'uptime': 55, 'op': 280}
    for c in cols:
        app.bootstrap_tree.heading(c, text=headings[c],
            command=lambda col=c: app._bootstrap_sort(col))
        app.bootstrap_tree.column(c, width=widths[c],
            anchor='e' if c in ('mbps', 'uptime') else 'w')
    app.bootstrap_tree.tag_configure('reach_ok',  background='#dff5df')
    app.bootstrap_tree.tag_configure('reach_bad', background='#ffe0e0')
    app.bootstrap_tree.pack(side='left', fill='both', expand=True)
    ysc = ttk.Scrollbar(tf, orient='vertical',
                          command=app.bootstrap_tree.yview)
    ysc.pack(side='right', fill='y')
    app.bootstrap_tree.configure(yscrollcommand=ysc.set)
    app.bootstrap_reach_results = {}
    app.bootstrap_sort_col = 'uptime'
    app.bootstrap_sort_rev = True
    populate_bootstrap(app)


def populate_bootstrap(app, results: Optional[dict] = None) -> None:
    if results is not None:
        app.bootstrap_reach_results = results
    app.bootstrap_tree.delete(*app.bootstrap_tree.get_children())
    sort_col = getattr(app, 'bootstrap_sort_col', 'uptime')
    rev = getattr(app, 'bootstrap_sort_rev', True)
    key_map = {
        'reach':   lambda s: (1 if app.bootstrap_reach_results.get(s['host'], (False, -1))[0] else 0,
                               -(app.bootstrap_reach_results.get(s['host'], (False, 99999))[1]
                                 if app.bootstrap_reach_results.get(s['host'], (False, 99999))[1] is not None
                                 else 99999)),
        'country': lambda s: s['country'],
        'host':    lambda s: s['host'],
        'ip':      lambda s: tuple(int(o) for o in s['ip'].split('.')),
        'mbps':    lambda s: s.get('speed_mbps', 0),
        'uptime':  lambda s: s.get('uptime_days', 0),
        'op':      lambda s: s.get('operator', ''),
    }
    key = key_map.get(sort_col, key_map['uptime'])
    rows = sorted(app.bootstrap_servers, key=key, reverse=rev)
    for s in rows:
        if not app.bootstrap_reach_results:
            reach = '—'; tag: tuple = ()
        else:
            ok, rtt = app.bootstrap_reach_results.get(s['host'], (False, -1))
            if ok:
                reach = f'✓ {int(rtt)} мс'; tag = ('reach_ok',)
            else:
                reach = '✗ блок'; tag = ('reach_bad',)
        app.bootstrap_tree.insert('', 'end',
            iid=f'{IID_BOOT}{s["host"]}',
            values=(reach, f'{s["country"]} {s["country_long"]}',
                    s['host'], s['ip'], s['speed_mbps'],
                    s['uptime_days'], s.get('operator', '')),
            tags=tag)


# ── Live (fetched from vpngate.net) sub-tab ───────────────────────────────
def build_live(app) -> None:
    f = app.tab_vpngate_live
    ttk.Label(f,
              text='Актуальный список с vpngate.net. Если vpngate.net недоступен — '
                   'сначала используйте встроенный сервер, отметьте на вкладке Сервисы '
                   '«VPN Gate (vpngate.net)», нажмите Применить, а потом возвращайтесь сюда.',
              foreground='#555', wraplength=1100, justify='left'
              ).pack(anchor='w', padx=6, pady=(6, 4))

    toolbar = ttk.Frame(f)
    toolbar.pack(fill='x', padx=4, pady=(0, 4))
    ttk.Button(toolbar, text='⟳ Обновить', command=app._on_vpngate_refresh,
               style='Accent.TButton').pack(side='left')
    ttk.Button(toolbar, text='🔍 Проверить доступность',
               command=app._vpngate_test_reach).pack(side='left', padx=(6, 0))
    ttk.Button(toolbar, text='🗑 Удалить созданные приложением VPN',
               command=app._on_delete_managed_vpns).pack(side='right')
    app.vpngate_status_var = tk.StringVar(value='Ещё не загружено')
    ttk.Label(toolbar, textvariable=app.vpngate_status_var, foreground='#555',
              style='Status.TLabel').pack(side='left', padx=10)

    filt = ttk.Frame(f)
    filt.pack(fill='x', padx=4, pady=(0, 4))
    ttk.Label(filt, text='Страна:').pack(side='left')
    app.vpngate_country_var = tk.StringVar(value='Любая')
    app.vpngate_country_combo = ttk.Combobox(filt,
        textvariable=app.vpngate_country_var, state='readonly', width=18)
    app.vpngate_country_combo.pack(side='left', padx=(4, 8))
    app.vpngate_country_combo.bind('<<ComboboxSelected>>',
        lambda e: app._vpngate_repaint())
    ttk.Label(filt, text='Макс. пинг:').pack(side='left')
    app.vpngate_ping_var = tk.StringVar(value='1000')
    ttk.Entry(filt, textvariable=app.vpngate_ping_var, width=6
              ).pack(side='left', padx=(4, 8))
    ttk.Label(filt, text='Мин. Мбит/с:').pack(side='left')
    app.vpngate_speed_var = tk.StringVar(value='5')
    ttk.Entry(filt, textvariable=app.vpngate_speed_var, width=6
              ).pack(side='left', padx=(4, 8))
    app.vpngate_nolog_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(filt, text='Только «no logs»',
                    variable=app.vpngate_nolog_var,
                    command=app._vpngate_repaint
                    ).pack(side='left', padx=(0, 8))
    ttk.Button(filt, text='Применить фильтр',
               command=app._vpngate_repaint).pack(side='left')

    tf = ttk.Frame(f)
    tf.pack(fill='both', expand=True, padx=4, pady=4)
    cols = ('reach', 'country', 'host', 'ip', 'ping', 'mbps',
            'uptime', 'sessions', 'log', 'op')
    app.vpngate_tree = ttk.Treeview(tf, columns=cols,
                                      show='headings', selectmode='browse')
    headings = {'reach': 'Доступ', 'country': 'Страна', 'host': 'Хост',
                'ip': 'IP', 'ping': 'Пинг', 'mbps': 'Мбит/с', 'uptime': 'Дней',
                'sessions': 'Юзеров', 'log': 'Политика логов', 'op': 'Оператор'}
    widths = {'reach': 80, 'country': 75, 'host': 170, 'ip': 120,
              'ping': 55, 'mbps': 65, 'uptime': 55, 'sessions': 55,
              'log': 80, 'op': 190}
    for c in cols:
        app.vpngate_tree.heading(c, text=headings[c],
            command=lambda col=c: app._vpngate_sort(col))
        app.vpngate_tree.column(c, width=widths[c],
            anchor='w' if c in ('country', 'host', 'ip', 'op', 'log') else 'e')
    app.vpngate_tree.tag_configure('reach_ok',  background='#dff5df')
    app.vpngate_tree.tag_configure('reach_bad', background='#ffe0e0')
    app.vpngate_tree.pack(side='left', fill='both', expand=True)
    ysc = ttk.Scrollbar(tf, orient='vertical', command=app.vpngate_tree.yview)
    ysc.pack(side='right', fill='y')
    app.vpngate_tree.configure(yscrollcommand=ysc.set)

    act = ttk.Frame(f)
    act.pack(fill='x', padx=4, pady=(0, 4))
    ttk.Button(act, text='Скопировать host:port',
               command=app._vpngate_copy_host).pack(side='left')
    ttk.Button(act, text='Скопировать логин/пароль',
               command=app._vpngate_copy_creds).pack(side='left', padx=(4, 0))
    ttk.Button(act, text='▶ Создать SSTP-интерфейс на роутере',
               command=app._vpngate_create_interface,
               style='Accent.TButton').pack(side='right')

    app.vpngate_all = []
    app.vpngate_shown = []
    app.vpngate_reach_results = {}
    app.vpngate_sort_col = 'mbps'
    app.vpngate_sort_rev = True
    cached_sv = CACHE.get('vpngate', TTL_VPNGATE * 6)
    if cached_sv:
        app.vpngate_all = cached_sv
        populate_country_filter(app)
        repaint_live(app)
        age = CACHE.age('vpngate') or 0
        app.vpngate_status_var.set(
            f'{len(cached_sv)} серверов (из кеша, возраст {int(age / 60)} мин)')


def populate_country_filter(app) -> None:
    countries = sorted({s.get('CountryLong', '') for s in app.vpngate_all
                          if s.get('CountryLong')})
    app.vpngate_country_combo.configure(values=['Любая'] + countries)


def repaint_live(app) -> None:
    app.vpngate_tree.delete(*app.vpngate_tree.get_children())
    try:
        max_ping = int(app.vpngate_ping_var.get() or '99999')
    except ValueError:
        max_ping = 99999
    try:
        min_mbps = float(app.vpngate_speed_var.get() or '0')
    except ValueError:
        min_mbps = 0
    country = app.vpngate_country_var.get().strip()
    nolog = app.vpngate_nolog_var.get()

    out = []
    for s in app.vpngate_all:
        if country and country != 'Любая' and s.get('CountryLong') != country:
            continue
        if s.get('Ping', 0) > max_ping:
            continue
        if s.get('SpeedMbps', 0) < min_mbps:
            continue
        if nolog and 'no logs' not in (s.get('LogType', '') or '').lower():
            continue
        out.append(s)

    def reach_sort_key(s: dict):
        r = app.vpngate_reach_results.get(s.get('HostName', ''))
        if not r:
            return (0, 0)
        ok, rtt = r
        return (2 if ok else 1, -(rtt if ok else 0))

    key_map = {'country':  lambda s: s.get('CountryShort', ''),
               'host':     lambda s: s.get('HostName', ''),
               'ip':       lambda s: s.get('IP', ''),
               'ping':     lambda s: s.get('Ping', 0),
               'mbps':     lambda s: s.get('SpeedMbps', 0),
               'uptime':   lambda s: s.get('UptimeDays', 0),
               'sessions': lambda s: s.get('NumVpnSessions', 0),
               'log':      lambda s: s.get('LogType', '') or '',
               'op':       lambda s: s.get('Operator', '') or '',
               'reach':    reach_sort_key}
    key_fn = key_map.get(app.vpngate_sort_col, key_map['mbps'])
    out.sort(key=key_fn, reverse=app.vpngate_sort_rev)
    app.vpngate_shown = out

    for s in out:
        hn = s.get('HostName', '')
        r = app.vpngate_reach_results.get(hn)
        if r is None:
            reach = '—'; tag: tuple = ()
        else:
            ok, rtt = r
            reach = f'✓ {int(rtt)} мс' if ok else '✗ блок'
            tag = ('reach_ok',) if ok else ('reach_bad',)
        app.vpngate_tree.insert('', 'end', iid=hn,
            values=(reach,
                    f'{s.get("CountryShort", "")} {s.get("CountryLong", "")}',
                    hn, s.get('IP', ''), s.get('Ping', 0),
                    s.get('SpeedMbps', 0), s.get('UptimeDays', 0),
                    s.get('NumVpnSessions', 0),
                    (s.get('LogType', '') or '')[:30],
                    (s.get('Operator', '') or '')[:40]),
            tags=tag)
