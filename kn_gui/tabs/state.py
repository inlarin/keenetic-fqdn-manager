"""State tab: Treeview showing FQDN groups + IP routes, with status tags.

All callbacks (`_on_refresh_state`, `_on_delete_selected`, `_on_save_config`)
remain on App.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..constants import IID_GROUP, IID_IPROUTE, IID_SECTION


def build(app) -> None:
    f = app.tab_state
    top = ttk.Frame(f, padding=(0, 4))
    top.pack(fill='x', padx=4, pady=(4, 0))
    ttk.Button(top, text='Обновить (F5)',
               command=app._on_refresh_state).pack(side='left', padx=2)
    ttk.Button(top, text='Удалить выбранное',
               command=app._on_delete_selected).pack(side='left', padx=2)
    ttk.Button(top, text='Сохранить конфиг',
               command=app._on_save_config).pack(side='left', padx=12)
    # Right side: bulk cleanup of groups tagged as ours.
    ttk.Button(top, text='🗑 Удалить созданные приложением FQDN-группы',
               command=app._on_delete_managed_fqdn_groups).pack(side='right', padx=2)
    app.state_summary_var = tk.StringVar(value='')
    ttk.Label(top, textvariable=app.state_summary_var, foreground='#555',
              style='Status.TLabel').pack(side='right', padx=4)

    tree_frame = ttk.Frame(f)
    tree_frame.pack(fill='both', expand=True, padx=4, pady=4)
    app.state_tree = ttk.Treeview(tree_frame, columns=('details',),
                                    show='tree headings', height=20)
    app.state_tree.heading('#0', text='Элемент')
    app.state_tree.heading('details', text='Детали')
    app.state_tree.column('#0', width=340, anchor='w')
    app.state_tree.column('details', width=560, anchor='w')
    app.state_tree.tag_configure('section',     font=app._tree_font_bold,
                                                 background='#eef2f7')
    app.state_tree.tag_configure('exclusive',   foreground='#1e7e1e')
    app.state_tree.tag_configure('unprotected', foreground='#a05c00')
    app.state_tree.pack(side='left', fill='both', expand=True)
    yscroll = ttk.Scrollbar(tree_frame, orient='vertical',
                              command=app.state_tree.yview)
    yscroll.pack(side='right', fill='y')
    app.state_tree.configure(yscrollcommand=yscroll.set)


def refresh(app) -> None:
    """Repopulate the tree from `app.state`. Called after connect /
    apply / F5."""
    app.state_tree.delete(*app.state_tree.get_children())
    groups = app.state['groups']
    dns_routes = app.state['dns_routes']
    ip_routes = app.state['ip_routes']

    g_root = app.state_tree.insert('', 'end', iid=f'{IID_SECTION}fqdn',
                                     text=f'  📁  FQDN-группы ({len(groups)})',
                                     values=('',), open=True, tags=('section',))
    for g, domains in sorted(groups.items()):
        route = next((r for r in dns_routes if r['group'] == g), None)
        if route:
            flags = []
            if route.get('auto'):
                flags.append('auto')
            if route.get('reject'):
                flags.append('kill switch')
            details = f'→ {route["interface"]}  [{", ".join(flags) if flags else "—"}]'
            tag = ('exclusive',) if route.get('reject') else ('unprotected',)
        else:
            details = 'не привязана к маршруту'
            tag = ('unprotected',)
        node = app.state_tree.insert(g_root, 'end', iid=f'{IID_GROUP}{g}',
                                       text=f'      {g}  ·  {len(domains)} записей',
                                       values=(details,), tags=tag)
        for d in domains:
            app.state_tree.insert(node, 'end',
                                    text=f'            {d}', values=('',))

    r_root = app.state_tree.insert('', 'end', iid=f'{IID_SECTION}ip',
                                     text=f'  🌐  IP-маршруты ({len(ip_routes)})',
                                     values=('',), open=True, tags=('section',))
    for i, r in enumerate(ip_routes):
        flags = []
        if r.get('auto'):
            flags.append('auto')
        if r.get('reject'):
            flags.append('kill switch')
        if r.get('system_managed'):
            flags.append('system')
        tag = ('exclusive',) if r.get('reject') else ('unprotected',)
        # System-managed routes (e.g. `ip route default 172.19.X.1 OpkgTunN`)
        # get a 🔒 prefix so the user knows the Delete button will refuse
        # to remove them. Removing them silently blackholes selective-
        # routing traffic; see _on_delete_selected for the guard.
        lock = '🔒 ' if r.get('system_managed') else ''
        app.state_tree.insert(r_root, 'end', iid=f'{IID_IPROUTE}{i}',
                                text=f'      {lock}{r["network"]}/{r["mask"]}',
                                values=(f'→ {r["interface"]}  [{", ".join(flags) if flags else "—"}]',),
                                tags=tag)

    exc_groups = sum(1 for r in dns_routes if r.get('reject'))
    exc_ips    = sum(1 for r in ip_routes if r.get('reject'))
    app.state_summary_var.set(
        f'{len(groups)} FQDN-групп ({exc_groups} c kill switch) · '
        f'{len(ip_routes)} IP-маршрутов ({exc_ips} c kill switch)')
