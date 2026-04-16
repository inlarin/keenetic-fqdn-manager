"""Catalog tab: catalog metadata, upstream refresh, disk cache, JSON import.

Callbacks (`app._on_refresh_upstream_all`, `_on_export_catalog`,
`_on_cache_clear`, `_on_import_url`, `_on_import_file`) stay on App.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk

from ..cache import CACHE
from ..constants import CATEGORY_ICON
from ..paths import CACHE_FILE


def build(app) -> None:
    f = app.tab_catalog
    for w in f.winfo_children():
        w.destroy()

    header = ttk.Frame(f, padding=(8, 12, 8, 4))
    header.pack(fill='x')
    ttk.Label(header, text=app.catalog.name,
              font=('Segoe UI', 11, 'bold')).pack(anchor='w')

    by_cat: dict[str, int] = {}
    for svc in app.catalog.services:
        cat = svc.get('category', 'Other')
        by_cat[cat] = by_cat.get(cat, 0) + 1
    stats = ' · '.join(f'{CATEGORY_ICON.get(c, "📦")} {c}: {n}'
                       for c, n in sorted(by_cat.items()))
    ttk.Label(header,
              text=f'Версия {app.catalog.version} · {len(app.catalog.services)} сервисов',
              foreground='#555').pack(anchor='w')
    ttk.Label(header, text=stats, foreground='#555').pack(anchor='w', pady=(2, 0))

    n_upstream = sum(1 for s in app.catalog.services
                     if s.get('upstream') or s.get('ipv4_providers') or s.get('asn'))
    refresh_box = ttk.LabelFrame(f, text=' Обновление из upstream ', padding=8)
    refresh_box.pack(fill='x', padx=8, pady=(10, 6))
    ttk.Label(refresh_box,
              text=f'{n_upstream} из {len(app.catalog.services)} сервисов объявляют upstream '
                   '(v2fly, Cloudflare, AWS, RIPEstat и т.д.)').pack(anchor='w')
    ttk.Label(refresh_box,
              text='Подтянуть свежие списки FQDN / IPv4 CIDR и объединить с локальным каталогом. '
                   'После обновления — Применить, чтобы протолкнуть изменения на роутер.',
              foreground='#555', wraplength=700, justify='left').pack(anchor='w', pady=(2, 6))
    row = ttk.Frame(refresh_box)
    row.pack(anchor='w')
    ttk.Button(row, text='⟳  Обновить все upstream',
               command=app._on_refresh_upstream_all,
               style='Accent.TButton').pack(side='left')
    ttk.Button(row, text='Экспортировать каталог в файл…',
               command=app._on_export_catalog).pack(side='left', padx=(8, 0))

    cache_box = ttk.LabelFrame(f, text=' Дисковый кеш ', padding=8)
    cache_box.pack(fill='x', padx=8, pady=6)
    size_kb = CACHE.size_bytes() / 1024.0
    ttk.Label(cache_box,
              text=f'{CACHE.num_entries()} записей, {size_kb:.1f} КБ — {str(CACHE_FILE)}'
              ).pack(anchor='w')
    ttk.Label(cache_box,
              text='TTL: v2fly и plain-text 6 ч, IP-провайдеры 24 ч, RIPEstat 24 ч, '
                   'VPN Gate 5 мин. Кнопки Обновить игнорируют кеш.',
              foreground='#555', wraplength=700, justify='left').pack(anchor='w', pady=(2, 6))
    ttk.Button(cache_box, text='Очистить кеш',
               command=app._on_cache_clear).pack(anchor='w')

    url_box = ttk.LabelFrame(f, text=' Импорт с URL ', padding=8)
    url_box.pack(fill='x', padx=8, pady=6)
    app.url_var = tk.StringVar()
    ttk.Label(url_box, text='URL до services.json (schema_version=1):'
              ).pack(anchor='w')
    row = ttk.Frame(url_box)
    row.pack(fill='x', pady=(4, 0))
    ttk.Entry(row, textvariable=app.url_var).pack(side='left', fill='x', expand=True)
    ttk.Button(row, text='Импорт', command=app._on_import_url
               ).pack(side='left', padx=(6, 0))

    file_box = ttk.LabelFrame(f, text=' Импорт из файла ', padding=8)
    file_box.pack(fill='x', padx=8, pady=4)
    ttk.Button(file_box, text='Выбрать JSON…',
               command=app._on_import_file).pack(anchor='w')

    schema_box = ttk.LabelFrame(f, text=' Схема JSON ', padding=8)
    schema_box.pack(fill='both', expand=True, padx=8, pady=(6, 8))
    schema_txt = (
        '{\n'
        '  "schema_version": 1,\n'
        '  "catalog_version": "x.y.z",\n'
        '  "catalog_name": "My list",\n'
        '  "services": [\n'
        '    {\n'
        '      "id": "foo",\n'
        '      "name": "Foo Service",\n'
        '      "category": "AI | Video | Messaging | Social | Music | Dev | ...",\n'
        '      "description": "...",\n'
        '      "fqdn": ["example.com", "api.example.com"],\n'
        '      "ipv4_cidr": ["1.2.3.0/24"]\n'
        '    }\n'
        '  ]\n'
        '}\n')
    txt = scrolledtext.ScrolledText(schema_box, height=12, font=app._mono_font,
                                     wrap='none', relief='flat', borderwidth=0)
    txt.pack(fill='both', expand=True)
    txt.insert('1.0', schema_txt)
    txt.configure(state='disabled')
