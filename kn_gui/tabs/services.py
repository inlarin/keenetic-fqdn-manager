"""Services tab: catalog treeview + Apply action bar + details panel.

All service-row event handlers (`_on_svc_click`, `_on_svc_space`,
`_on_svc_select`, `_toggle_svc`, `_show_service_details`, etc.) stay
on App — they're wired through `bind()`/`command=` refs and rewiring
all of them to module-level functions would churn more than it saves.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk

from ..constants import CATEGORY_ICON, IID_CATEGORY, IID_SERVICE


def build(app) -> None:
    f = app.tab_services
    # Top toolbar — filters + selection helpers only; primary Apply
    # lives in a sticky bar at the bottom (below the split).
    top = ttk.Frame(f, padding=(0, 4))
    top.pack(fill='x', padx=4, pady=(4, 0))
    ttk.Button(top, text='Выбрать все', width=14,
               command=lambda: app._toggle_all_services(True)
               ).pack(side='left', padx=(0, 4))
    ttk.Button(top, text='Снять все', width=12,
               command=lambda: app._toggle_all_services(False)
               ).pack(side='left', padx=2)
    ttk.Button(top, text='Отметить применённые', width=22,
               command=app._select_applied).pack(side='left', padx=2)

    ttk.Label(top, text='Показать:').pack(side='left', padx=(12, 2))
    app.svc_filter_var = tk.StringVar(value='Все')
    flt = ttk.Combobox(top, textvariable=app.svc_filter_var,
                        values=('Все', 'Применённые', 'С расхождениями',
                                'Не применённые', 'Отмеченные'),
                        state='readonly', width=18)
    flt.pack(side='left')
    flt.bind('<<ComboboxSelected>>', lambda e: app._populate_services())

    app.svc_summary_var = tk.StringVar(value='')
    ttk.Label(top, textvariable=app.svc_summary_var, foreground='#555',
              style='Status.TLabel').pack(side='left', padx=12)

    # Sticky bottom action bar.
    action_bar = ttk.Frame(f, padding=(6, 6))
    action_bar.pack(side='bottom', fill='x', padx=4, pady=(0, 4))
    app.btn_apply = ttk.Button(action_bar, text='▶  Применить  (Ctrl+Enter)',
                                 command=app._on_apply_services,
                                 style='Accent.TButton')
    app.btn_apply.pack(side='right', padx=(8, 0))
    ks_chk = ttk.Checkbutton(
        action_bar, text='Блокировать при разрыве VPN (kill switch)',
        variable=app.exclusive_var)
    ks_chk.pack(side='right', padx=10)
    app._make_tooltip(ks_chk,
        'Если VPN-туннель упадёт, трафик к защищённым сервисам будет\n'
        'отбрасываться, а НЕ улетать через обычный канал провайдера.\n'
        'Защита от VPN-leak. Включено по умолчанию.')

    svc_pane = ttk.PanedWindow(f, orient='horizontal')
    svc_pane.pack(fill='both', expand=True, padx=4, pady=4)

    tree_frame = ttk.Frame(svc_pane)
    svc_pane.add(tree_frame, weight=3)
    app.svc_tree = ttk.Treeview(
        tree_frame, columns=('check', 'fqdn', 'ipv4', 'applied'),
        show='tree headings', selectmode='browse', height=20)
    app.svc_tree.heading('#0',      text='Категория / Сервис')
    app.svc_tree.heading('check',   text='✓')
    app.svc_tree.heading('fqdn',    text='FQDN')
    app.svc_tree.heading('ipv4',    text='IPv4')
    app.svc_tree.heading('applied', text='Состояние')
    app.svc_tree.column('#0',      width=300, anchor='w')
    app.svc_tree.column('check',   width=36, stretch=False, anchor='center')
    app.svc_tree.column('fqdn',    width=55, stretch=False, anchor='e')
    app.svc_tree.column('ipv4',    width=55, stretch=False, anchor='e')
    app.svc_tree.column('applied', width=140, stretch=False, anchor='center')
    app.svc_tree.tag_configure('category', font=app._tree_font_bold, background='#eef2f7')
    app.svc_tree.tag_configure('applied',  foreground='#0a6b0a', background='#dff5df')
    app.svc_tree.tag_configure('drifted',  foreground='#8a4500', background='#ffeccc')
    app.svc_tree.tag_configure('stripe',   background='#fafafa')
    app.svc_tree.pack(side='left', fill='both', expand=True)
    yscroll = ttk.Scrollbar(tree_frame, orient='vertical',
                              command=app.svc_tree.yview)
    yscroll.pack(side='right', fill='y')
    app.svc_tree.configure(yscrollcommand=yscroll.set)
    app.svc_tree.bind('<Button-1>', app._on_svc_click)
    app.svc_tree.bind('<<TreeviewSelect>>', app._on_svc_select)
    app.svc_tree.bind('<space>', app._on_svc_space)

    right = ttk.LabelFrame(svc_pane, text=' Детали ')
    svc_pane.add(right, weight=2)
    app.svc_details = scrolledtext.ScrolledText(
        right, state='disabled', font=app._label_font, wrap='word',
        relief='flat', padx=8, pady=8)
    app.svc_details.pack(fill='both', expand=True)
    app.svc_details.tag_configure('h1', font=('Segoe UI', 12, 'bold'), spacing3=6)
    app.svc_details.tag_configure('h2', font=('Segoe UI', 9, 'bold'),
                                     spacing1=8, spacing3=2)
    app.svc_details.tag_configure('mono',  font=app._mono_font)
    app.svc_details.tag_configure('muted', foreground='#888')
    app.svc_details.tag_configure('ok',    foreground='#1e7e1e')
    app.svc_details.tag_configure('warn',  foreground='#a05c00')

    app._populate_services()
    app._set_details_placeholder()


def populate(app) -> None:
    """Repopulate the services tree honouring the filter dropdown."""
    app.svc_tree.delete(*app.svc_tree.get_children())
    flt = getattr(app, 'svc_filter_var', None)
    filter_mode = flt.get() if flt else 'Все'

    all_applied = all_drifted = 0
    for s in app.catalog.services:
        st, _ = app._svc_state(s)
        if st == 'applied':
            all_applied += 1
        elif st == 'drifted':
            all_drifted += 1

    by_cat: dict[str, list[dict]] = {}
    for svc in app.catalog.services:
        by_cat.setdefault(svc.get('category', 'Other'), []).append(svc)

    shown = 0
    stripe = False
    for cat in sorted(by_cat.keys()):
        visible = []
        for svc in by_cat[cat]:
            state, _ = app._svc_state(svc)
            checked = app.svc_checked.get(svc['id'], False)
            if filter_mode == 'Применённые' and state != 'applied':
                continue
            if filter_mode == 'С расхождениями' and state != 'drifted':
                continue
            if filter_mode == 'Не применённые' and state in ('applied', 'drifted'):
                continue
            if filter_mode == 'Отмеченные' and not checked:
                continue
            visible.append((svc, state, checked))
        if not visible:
            continue
        icon = CATEGORY_ICON.get(cat, '📦')
        cat_id = f'{IID_CATEGORY}{cat}'
        app.svc_tree.insert('', 'end', iid=cat_id,
                              text=f'  {icon}  {cat}  ({len(visible)})',
                              values=('', '', '', ''),
                              tags=('category',), open=True)
        for svc, state, checked in visible:
            tags: tuple = ('stripe',) if stripe else ()
            if state == 'applied':
                tags = tags + ('applied',)
            elif state == 'drifted':
                tags = tags + ('drifted',)
            status_icon = {'applied': '✓ ', 'drifted': '⚠ ', '': '◯ '}[state]
            _, label = app._svc_state(svc)
            app.svc_tree.insert(cat_id, 'end', iid=f'{IID_SERVICE}{svc["id"]}',
                                  text=f'    {status_icon} {svc["name"]}',
                                  values=('☑' if checked else '☐',
                                          len(svc.get('fqdn', [])),
                                          len(svc.get('ipv4_cidr', [])),
                                          label),
                                  tags=tags)
            stripe = not stripe
            shown += 1

    total = len(app.catalog.services)
    not_applied = total - all_applied - all_drifted
    parts = [f'✓ {all_applied} применено',
             f'⚠ {all_drifted} с расхождениями',
             f'◯ {not_applied} не применено',
             f'всего {total}']
    if filter_mode != 'Все':
        parts.append(f'показано {shown}')
    app.svc_summary_var.set('  ·  '.join(parts))
