"""
Keenetic FQDN Router Manager
A GUI tool to manage FQDN object-groups and dns-proxy routes on Keenetic
(and OEM forks like Netcraze) routers via telnet CLI.

Single-file app. Bundle with:
    pyinstaller --onefile --windowed --add-data "services.json;." kn_router_gui.py
"""
from __future__ import annotations

import json
import os
import queue
import re
import socket
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import urllib.request
from enum import Enum
from pathlib import Path
from tkinter import ttk, messagebox, filedialog, scrolledtext
from typing import Callable, Optional

APP_NAME = 'Keenetic FQDN Manager'
APP_VERSION = '0.2.0'
DEFAULT_ROUTER = '192.168.32.1'
DEFAULT_USER = 'admin'
DEFAULT_TELNET_PORT = 23
GROUP_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]{0,31}$')

CONFIG_DIR = Path(os.environ.get('APPDATA', os.path.expanduser('~'))) / 'KeeneticFqdnManager'
CONFIG_FILE = CONFIG_DIR / 'ui.json'

CATEGORY_ICON = {
    'AI': '🤖', 'Video': '📺', 'Music': '🎵', 'Messaging': '💬',
    'Social': '👥', 'Dev': '⚙', 'Productivity': '📝', 'Content': '📰',
    'Other': '📦',
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def resource_path(relative_path: str) -> str:
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


def cidr_to_mask(cidr: str) -> tuple[str, str]:
    net, prefix_s = cidr.split('/')
    prefix = int(prefix_s)
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    mask = '.'.join(str((mask_int >> (24 - 8 * i)) & 0xFF) for i in range(4))
    return net, mask


def strip_ansi(s: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', s)


def load_ui_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
    except Exception:
        return {}


def save_ui_config(data: dict) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding='utf-8')
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Connection state
# ─────────────────────────────────────────────────────────────────────────────

class ConnState(Enum):
    DISCONNECTED = 'disconnected'
    CONNECTING = 'connecting'
    CONNECTED = 'connected'
    ERROR = 'error'


STATE_COLOR = {
    ConnState.DISCONNECTED: '#888',
    ConnState.CONNECTING:   '#e6a500',
    ConnState.CONNECTED:    '#2c9f2c',
    ConnState.ERROR:        '#c33',
}

STATE_LABEL = {
    ConnState.DISCONNECTED: 'Disconnected',
    ConnState.CONNECTING:   'Connecting…',
    ConnState.CONNECTED:    'Connected',
    ConnState.ERROR:        'Error',
}


# ─────────────────────────────────────────────────────────────────────────────
# Router connection (telnet)
# ─────────────────────────────────────────────────────────────────────────────

class KeeneticClient:
    IAC = 0xff
    WILL, WONT, DO, DONT, SB, SE = 0xfb, 0xfc, 0xfd, 0xfe, 0xfa, 0xf0
    CONFIG_PROMPT = r'\(config(-[a-z-]+)?\)>\s*$'

    def __init__(self, host: str, port: int = DEFAULT_TELNET_PORT):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.connected = False
        self.router_info: dict = {}

    def _negotiate(self, buf: bytes) -> bytes:
        out = bytearray()
        resp = bytearray()
        i = 0
        while i < len(buf):
            b = buf[i]
            if b == self.IAC and i + 1 < len(buf):
                cmd = buf[i + 1]
                if cmd in (self.WILL, self.WONT, self.DO, self.DONT) and i + 2 < len(buf):
                    opt = buf[i + 2]
                    rc = self.DONT if cmd == self.WILL else self.WONT if cmd == self.DO else None
                    if rc is not None:
                        resp += bytes([self.IAC, rc, opt])
                    i += 3
                    continue
                elif cmd == self.SB:
                    j = i + 2
                    while j < len(buf) - 1 and not (buf[j] == self.IAC and buf[j + 1] == self.SE):
                        j += 1
                    i = j + 2
                    continue
                else:
                    i += 2
                    continue
            out.append(b)
            i += 1
        if resp and self.sock is not None:
            self.sock.sendall(bytes(resp))
        return bytes(out)

    def _read_until_any(self, patterns: list[str], timeout: float = 8.0) -> tuple[str, int]:
        """Wait for any of the regexes (against ANSI-stripped text).
        Returns (text_so_far, matched_index or -1).
        The Keenetic CLI emits ANSI erase sequences (\\x1b[K) right after the
        prompt, so we must strip ANSI before regex matching or '$' anchors
        never match."""
        assert self.sock is not None
        self.sock.settimeout(0.3)
        buf = b''
        end = time.time() + timeout
        compiled = [re.compile(p) for p in patterns]
        def _check() -> tuple[str, int]:
            txt = strip_ansi(buf.decode('utf-8', 'replace'))
            for i, rx in enumerate(compiled):
                if rx.search(txt):
                    return txt, i
            return txt, -1
        while time.time() < end:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buf += self._negotiate(chunk)
                txt, idx = _check()
                if idx >= 0:
                    return txt, idx
            except socket.timeout:
                txt, idx = _check()
                if idx >= 0:
                    return txt, idx
        return strip_ansi(buf.decode('utf-8', 'replace')), -1

    def _read_until(self, pattern: str, timeout: float = 8.0) -> str:
        text, _ = self._read_until_any([pattern], timeout)
        return text

    def _send(self, line: str) -> None:
        assert self.sock is not None
        self.sock.sendall((line + '\n').encode())

    def login(self, user: str, password: str, timeout: float = 8.0) -> None:
        """Connect + authenticate. Fails fast on wrong password via multi-pattern wait."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect((self.host, self.port))
            banner1, idx = self._read_until_any([r'(?i)login\s*:'], timeout)
            if idx < 0:
                raise ConnectionError('Router did not send login prompt')
            self._send(user)
            _, idx = self._read_until_any([r'(?i)password\s*:'], timeout)
            if idx < 0:
                raise ConnectionError('Router did not ask for password')
            self._send(password)
            # Wait for EITHER success, explicit failure message, or re-prompt
            out, idx = self._read_until_any([
                self.CONFIG_PROMPT,                              # 0 = success
                r'(?i)(fail|incorrect|invalid|locked|denied)',   # 1 = auth error msg
                r'(?im)^\s*login\s*:\s*$',                       # 2 = re-prompt = failed
            ], timeout)
            if idx == 0:
                self.connected = True
                combined = (banner1 or '') + (out or '')
                m = re.search(r'NDMS version\s+(\S+)', combined)
                if m:
                    self.router_info['version'] = m.group(1)
                m = re.search(r'copyright.*?\d{4}\s+(.+?)\.', combined)
                if m:
                    self.router_info['vendor'] = m.group(1).strip()
            elif idx < 0:
                raise ConnectionError('Timeout waiting for login result')
            else:
                snippet = out.strip().splitlines()[-1] if out.strip() else ''
                raise PermissionError(f'Login failed: {snippet[:120] or "wrong credentials"}')
        except Exception:
            try:
                if self.sock is not None:
                    self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.connected = False
            raise

    def close(self) -> None:
        if self.sock is not None:
            try:
                self._send('exit')
                time.sleep(0.2)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self.connected = False

    def run(self, cmd: str, timeout: float = 10.0) -> str:
        self._send(cmd)
        return self._read_until(self.CONFIG_PROMPT, timeout)

    def list_interfaces(self) -> list[dict]:
        out = self.run('show interface', timeout=15.0)
        ifaces: list[dict] = []
        current: dict = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('interface-name:'):
                if current.get('name'):
                    ifaces.append(current)
                current = {'name': line.split(':', 1)[1].strip()}
            elif line.startswith('type:'):
                current['type'] = line.split(':', 1)[1].strip()
            elif line.startswith('description:'):
                current['description'] = line.split(':', 1)[1].strip()
            elif line.startswith('link:'):
                current['link'] = line.split(':', 1)[1].strip()
            elif line.startswith('connected:'):
                current['connected'] = line.split(':', 1)[1].strip()
        if current.get('name'):
            ifaces.append(current)
        return [i for i in ifaces if i.get('type') in
                ('PPPoE', 'SSTP', 'L2TP', 'PPTP', 'Wireguard', 'OpenVPN',
                 'ZeroTier', 'GigabitEthernet', 'Vlan', 'Ipoe', 'Ipip', 'Gre')]

    def running_config(self) -> str:
        return self.run('show running-config', timeout=20.0)

    def create_fqdn_group(self, name: str, domains: list[str]) -> list[str]:
        errs: list[str] = []
        self.run(f'object-group fqdn {name}')
        for d in domains:
            out = self.run(f'include {d}')
            if 'rror' in out or 'nvalid' in out.lower():
                errs.append(f'include {d}: {out.strip().splitlines()[-1] if out.strip() else "error"}')
        self.run('exit')
        return errs

    def bind_fqdn_route(self, group: str, interface: str, auto: bool = True,
                        reject: bool = False) -> str:
        parts = [f'dns-proxy route object-group {group} {interface}']
        if auto:   parts.append('auto')
        if reject: parts.append('reject')
        return self.run(' '.join(parts))

    def delete_fqdn_group(self, name: str) -> str:
        self.run(f'no dns-proxy route object-group {name}')
        return self.run(f'no object-group fqdn {name}')

    def add_ip_route(self, network: str, mask: str, interface: str, auto: bool = True,
                     reject: bool = False) -> str:
        parts = [f'ip route {network} {mask} {interface}']
        if auto:   parts.append('auto')
        if reject: parts.append('reject')
        return self.run(' '.join(parts))

    def delete_ip_route(self, network: str, mask: str, interface: str) -> str:
        return self.run(f'no ip route {network} {mask} {interface}')

    def save_config(self) -> str:
        return self.run('system configuration save', timeout=15.0)


# ─────────────────────────────────────────────────────────────────────────────
# Catalog
# ─────────────────────────────────────────────────────────────────────────────

class Catalog:
    def __init__(self, data: dict):
        self.data = data

    @property
    def version(self) -> str: return self.data.get('catalog_version', '?')
    @property
    def name(self) -> str:    return self.data.get('catalog_name', 'Unnamed catalog')
    @property
    def services(self) -> list[dict]: return self.data.get('services', [])

    def service(self, sid: str) -> Optional[dict]:
        for s in self.services:
            if s.get('id') == sid:
                return s
        return None

    @classmethod
    def load_default(cls) -> 'Catalog':
        path = resource_path('services.json')
        with open(path, 'r', encoding='utf-8') as f:
            return cls(json.load(f))

    @classmethod
    def load_url(cls, url: str, timeout: float = 10.0) -> 'Catalog':
        req = urllib.request.Request(url, headers={'User-Agent': f'{APP_NAME}/{APP_VERSION}'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        if data.get('schema_version') != 1:
            raise ValueError(f'Unsupported schema_version: {data.get("schema_version")}')
        return cls(data)


# ─────────────────────────────────────────────────────────────────────────────
# Running-config parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_running_config(cfg: str) -> dict:
    groups: dict[str, list[str]] = {}
    current_group: Optional[str] = None
    dns_routes: list[dict] = []
    ip_routes: list[dict] = []
    in_dns_proxy = False

    for raw in cfg.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if stripped == '!':
            current_group = None
            in_dns_proxy = False
            continue
        m = re.match(r'object-group fqdn (\S+)', stripped)
        if m:
            current_group = m.group(1)
            groups[current_group] = []
            continue
        if current_group and stripped.startswith('include '):
            groups[current_group].append(stripped.split(' ', 1)[1])
            continue
        if stripped == 'dns-proxy':
            in_dns_proxy = True
            continue
        if in_dns_proxy:
            m = re.match(r'route object-group (\S+) (\S+)(?:\s+(auto))?(?:\s+(reject))?', stripped)
            if m:
                dns_routes.append({'group': m.group(1), 'interface': m.group(2),
                                   'auto': m.group(3) == 'auto',
                                   'reject': m.group(4) == 'reject'})
                continue
        m = re.match(r'ip route (\S+) (\S+) (\S+)(?:\s+(auto))?(?:\s+(reject))?', stripped)
        if m:
            ip_routes.append({'network': m.group(1), 'mask': m.group(2),
                              'interface': m.group(3), 'auto': m.group(4) == 'auto',
                              'reject': m.group(5) == 'reject'})
    return {'groups': groups, 'dns_routes': dns_routes, 'ip_routes': ip_routes}


# ─────────────────────────────────────────────────────────────────────────────
# Background worker
# ─────────────────────────────────────────────────────────────────────────────

class Worker:
    def __init__(self, ui_queue: queue.Queue):
        self.ui_queue = ui_queue
        self.thread: Optional[threading.Thread] = None

    def busy(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def run(self, fn: Callable, *args, on_done: Optional[Callable] = None):
        if self.busy():
            self.ui_queue.put(('log', ('warn', 'Busy — another operation is in progress.')))
            return

        def target():
            try:
                result = fn(*args)
                self.ui_queue.put(('done', (on_done, result, None)))
            except Exception as e:
                self.ui_queue.put(('done', (on_done, None, e)))

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()


# ─────────────────────────────────────────────────────────────────────────────
# Application
# ─────────────────────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f'{APP_NAME} v{APP_VERSION}')
        self.minsize(960, 640)

        self.ui_cfg = load_ui_config()
        self.geometry(self.ui_cfg.get('geometry', '1180x760+100+80'))

        self.client: Optional[KeeneticClient] = None
        self.catalog: Catalog = Catalog.load_default()
        self.ui_queue: queue.Queue = queue.Queue()
        self.worker = Worker(self.ui_queue)
        self.interfaces: list[dict] = []
        self.state: dict = {'groups': {}, 'dns_routes': [], 'ip_routes': []}
        self.conn_state: ConnState = ConnState.DISCONNECTED

        self.svc_checked: dict[str, bool] = {}
        self.exclusive_var = tk.BooleanVar(value=bool(self.ui_cfg.get('exclusive', True)))

        self._init_style()
        self._build_ui()
        self._bind_hotkeys()
        self._set_state(ConnState.DISCONNECTED)
        self.protocol('WM_DELETE_WINDOW', self._on_close)
        self._drain_queue()

    # ── Styling ─────────────────────────────────────────────────────────────
    def _init_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use('vista' if sys.platform == 'win32' else 'clam')
        except Exception:
            pass
        # Emoji-capable font for tree (Segoe UI Emoji ships with Windows 10+)
        self._tree_font = tkfont.Font(family='Segoe UI', size=10)
        self._tree_font_bold = tkfont.Font(family='Segoe UI', size=10, weight='bold')
        self._label_font = tkfont.Font(family='Segoe UI', size=9)
        self._mono_font = tkfont.Font(family='Consolas', size=9)
        # Accent button style for primary Apply button
        style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('Status.TLabel', font=('Segoe UI', 9))

    # ── Layout ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        main_pane = ttk.PanedWindow(self, orient='vertical')
        main_pane.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self._main_pane = main_pane

        nb_holder = ttk.Frame(main_pane)
        main_pane.add(nb_holder, weight=4)

        nb = ttk.Notebook(nb_holder)
        nb.pack(fill='both', expand=True)
        self.nb = nb
        self.tab_services = ttk.Frame(nb)
        self.tab_state    = ttk.Frame(nb)
        self.tab_catalog  = ttk.Frame(nb)
        nb.add(self.tab_services, text='  Services  ')
        nb.add(self.tab_state,    text='  Current state  ')
        nb.add(self.tab_catalog,  text='  Catalog  ')
        self._build_services_tab()
        self._build_state_tab()
        self._build_catalog_tab()

        log_frame = ttk.LabelFrame(main_pane, text=' Log ')
        main_pane.add(log_frame, weight=1)
        self.log_box = scrolledtext.ScrolledText(
            log_frame, height=6, state='disabled',
            font=self._mono_font, wrap='word', relief='flat', borderwidth=0)
        self.log_box.pack(fill='both', expand=True, padx=4, pady=4)
        # Color tags for log levels
        self.log_box.tag_configure('info',  foreground='#333')
        self.log_box.tag_configure('ok',    foreground='#1e7e1e')
        self.log_box.tag_configure('warn',  foreground='#a05c00')
        self.log_box.tag_configure('err',   foreground='#a51818')
        self.log_box.tag_configure('ts',    foreground='#888')

    def _build_header(self):
        wrap = ttk.Frame(self, padding=(8, 8, 8, 4))
        wrap.pack(fill='x')

        # Status dot (colored ●) + label
        self.status_dot = tk.Label(wrap, text='●', fg=STATE_COLOR[ConnState.DISCONNECTED],
                                    bg=self.cget('background'), font=('Segoe UI', 14))
        self.status_dot.grid(row=0, column=0, rowspan=2, padx=(0, 6))
        self.status_label = ttk.Label(wrap, text=STATE_LABEL[ConnState.DISCONNECTED],
                                       style='Status.TLabel')
        self.status_label.grid(row=0, column=1, sticky='w', padx=(0, 12))

        ttk.Label(wrap, text='Host:').grid(row=0, column=2, sticky='e', padx=(8, 4))
        self.host_var = tk.StringVar(value=self.ui_cfg.get('last_host', DEFAULT_ROUTER))
        self.host_entry = ttk.Entry(wrap, textvariable=self.host_var, width=18)
        self.host_entry.grid(row=0, column=3, sticky='w')

        ttk.Label(wrap, text='User:').grid(row=0, column=4, sticky='e', padx=(12, 4))
        self.user_var = tk.StringVar(value=self.ui_cfg.get('last_user', DEFAULT_USER))
        self.user_entry = ttk.Entry(wrap, textvariable=self.user_var, width=12)
        self.user_entry.grid(row=0, column=5, sticky='w')

        ttk.Label(wrap, text='Password:').grid(row=0, column=6, sticky='e', padx=(12, 4))
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(wrap, textvariable=self.pass_var, show='•', width=18)
        self.pass_entry.grid(row=0, column=7, sticky='w')

        self.btn_connect = ttk.Button(wrap, text='Connect', command=self._on_connect_click,
                                       width=12)
        self.btn_connect.grid(row=0, column=8, padx=10)

        # Row 2: interface + info
        ttk.Label(wrap, text='Interface:').grid(row=1, column=2, sticky='e', padx=(8, 4), pady=(4, 0))
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(wrap, textvariable=self.iface_var, state='disabled',
                                         width=22)
        self.iface_combo.grid(row=1, column=3, columnspan=2, sticky='w', pady=(4, 0))

        self.info_var = tk.StringVar(value='')
        ttk.Label(wrap, textvariable=self.info_var, foreground='#555',
                  style='Status.TLabel').grid(row=1, column=5, columnspan=4,
                                              sticky='w', padx=(12, 0), pady=(4, 0))

    # ── Services tab ────────────────────────────────────────────────────────
    def _build_services_tab(self):
        f = self.tab_services

        top = ttk.Frame(f, padding=(0, 4))
        top.pack(fill='x', padx=4, pady=(4, 0))

        ttk.Button(top, text='Select all', width=10,
                   command=lambda: self._toggle_all_services(True)).pack(side='left', padx=(0, 4))
        ttk.Button(top, text='Clear',      width=8,
                   command=lambda: self._toggle_all_services(False)).pack(side='left', padx=2)

        self.btn_apply = ttk.Button(top, text='▶  Apply  (Ctrl+Enter)',
                                     command=self._on_apply_services,
                                     style='Accent.TButton')
        self.btn_apply.pack(side='right', padx=(8, 0))
        ttk.Checkbutton(top, text='Exclusive / Kill switch',
                        variable=self.exclusive_var).pack(side='right', padx=10)

        svc_pane = ttk.PanedWindow(f, orient='horizontal')
        svc_pane.pack(fill='both', expand=True, padx=4, pady=4)

        # Left: tree with checkbox column
        tree_frame = ttk.Frame(svc_pane)
        svc_pane.add(tree_frame, weight=3)

        self.svc_tree = ttk.Treeview(
            tree_frame,
            columns=('check', 'fqdn', 'ipv4', 'applied'),
            show='tree headings', selectmode='browse', height=20)
        self.svc_tree.heading('#0',      text='Category / Service')
        self.svc_tree.heading('check',   text='✓')
        self.svc_tree.heading('fqdn',    text='FQDN')
        self.svc_tree.heading('ipv4',    text='IPv4')
        self.svc_tree.heading('applied', text='State')
        self.svc_tree.column('#0',      width=300, anchor='w')
        self.svc_tree.column('check',   width=36,  stretch=False, anchor='center')
        self.svc_tree.column('fqdn',    width=55,  stretch=False, anchor='e')
        self.svc_tree.column('ipv4',    width=55,  stretch=False, anchor='e')
        self.svc_tree.column('applied', width=110, stretch=False, anchor='center')

        self.svc_tree.tag_configure('category', font=self._tree_font_bold, background='#eef2f7')
        self.svc_tree.tag_configure('applied',  foreground='#1e7e1e')
        self.svc_tree.tag_configure('stripe',   background='#fafafa')

        self.svc_tree.pack(side='left', fill='both', expand=True)
        yscroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.svc_tree.yview)
        yscroll.pack(side='right', fill='y')
        self.svc_tree.configure(yscrollcommand=yscroll.set)

        self.svc_tree.bind('<Button-1>',       self._on_svc_click)
        self.svc_tree.bind('<<TreeviewSelect>>', self._on_svc_select)

        # Right: details panel
        right = ttk.LabelFrame(svc_pane, text=' Details ')
        svc_pane.add(right, weight=2)
        self.svc_details = scrolledtext.ScrolledText(
            right, state='disabled', font=self._label_font, wrap='word',
            relief='flat', padx=8, pady=8)
        self.svc_details.pack(fill='both', expand=True)
        self.svc_details.tag_configure('h1', font=('Segoe UI', 12, 'bold'), spacing3=6)
        self.svc_details.tag_configure('h2', font=('Segoe UI', 9, 'bold'), spacing1=8, spacing3=2)
        self.svc_details.tag_configure('mono', font=self._mono_font)
        self.svc_details.tag_configure('muted', foreground='#888')
        self.svc_details.tag_configure('ok',    foreground='#1e7e1e')
        self.svc_details.tag_configure('warn',  foreground='#a05c00')

        self._populate_services()
        self._set_details_placeholder()

    def _populate_services(self):
        self.svc_tree.delete(*self.svc_tree.get_children())
        by_cat: dict[str, list[dict]] = {}
        for svc in self.catalog.services:
            by_cat.setdefault(svc.get('category', 'Other'), []).append(svc)
        stripe = False
        for cat in sorted(by_cat.keys()):
            icon = CATEGORY_ICON.get(cat, '📦')
            cat_id = f'cat::{cat}'
            self.svc_tree.insert('', 'end', iid=cat_id,
                                  text=f'  {icon}  {cat}',
                                  values=('', '', '', ''),
                                  tags=('category',),
                                  open=True)
            for svc in by_cat[cat]:
                sid = svc['id']
                checked = self.svc_checked.get(sid, False)
                applied_info = self._svc_applied_info(sid)
                tags: tuple = ('stripe',) if stripe else ()
                if applied_info:
                    tags = tags + ('applied',)
                self.svc_tree.insert(cat_id, 'end', iid=f'svc::{sid}',
                                      text=f'      {svc["name"]}',
                                      values=('☑' if checked else '☐',
                                              len(svc.get('fqdn', [])),
                                              len(svc.get('ipv4_cidr', [])),
                                              applied_info or ''),
                                      tags=tags)
                stripe = not stripe

    def _svc_applied_info(self, sid: str) -> str:
        """Return short label 'iface + flags' if this service's group is on router."""
        if sid not in self.state.get('groups', {}):
            return ''
        route = next((r for r in self.state.get('dns_routes', []) if r['group'] == sid), None)
        if not route:
            return '● orphaned'
        flags = []
        if route.get('reject'):
            flags.append('kill')
        label = f'● {route["interface"]}'
        if flags:
            label += f' ({",".join(flags)})'
        return label

    def _on_svc_click(self, event):
        region = self.svc_tree.identify('region', event.x, event.y)
        col = self.svc_tree.identify_column(event.x)
        iid = self.svc_tree.identify_row(event.y)
        if not iid or not iid.startswith('svc::'):
            return
        # Only toggle on clicks in the 'check' column (column #1) OR the name column.
        if col in ('#1',):  # check column
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
        if iid.startswith('svc::'):
            sid = iid.split('::', 1)[1]
            svc = self.catalog.service(sid)
            if svc is not None:
                self._show_service_details(svc)
        elif iid.startswith('cat::'):
            self._set_details_placeholder()

    def _show_service_details(self, svc: dict):
        t = self.svc_details
        t.configure(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', f'{svc["name"]}\n', 'h1')
        t.insert('end', f'{svc.get("category", "Other")} · id = {svc["id"]}\n', 'muted')
        if svc.get('description'):
            t.insert('end', f'\n{svc["description"]}\n')
        applied = self._svc_applied_info(svc['id'])
        if applied:
            t.insert('end', '\nApplied on router: ', 'h2')
            t.insert('end', applied + '\n', 'ok')
            grp = self.state['groups'].get(svc['id'], [])
            if grp and set(grp) != set(svc.get('fqdn', [])):
                extra = set(grp) - set(svc.get('fqdn', []))
                missing = set(svc.get('fqdn', [])) - set(grp)
                if extra or missing:
                    t.insert('end', '\nDrift vs catalog:\n', 'warn')
                    if missing:
                        t.insert('end', f'  missing on router: {", ".join(sorted(missing))}\n', 'mono')
                    if extra:
                        t.insert('end', f'  extra on router:   {", ".join(sorted(extra))}\n', 'mono')
        else:
            t.insert('end', '\nNot applied on router.\n', 'muted')
        t.insert('end', f'\nFQDN ({len(svc.get("fqdn", []))}):\n', 'h2')
        for d in svc.get('fqdn', []):
            t.insert('end', f'  {d}\n', 'mono')
        if svc.get('ipv4_cidr'):
            t.insert('end', f'\nIPv4 ({len(svc["ipv4_cidr"])}):\n', 'h2')
            for c in svc['ipv4_cidr']:
                t.insert('end', f'  {c}\n', 'mono')
        t.configure(state='disabled')

    def _set_details_placeholder(self):
        t = self.svc_details
        t.configure(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', 'Pick a service on the left to see details.\n', 'muted')
        t.configure(state='disabled')

    def _toggle_all_services(self, on: bool):
        for svc in self.catalog.services:
            self.svc_checked[svc['id']] = on
        self._populate_services()

    # ── Current state tab ──────────────────────────────────────────────────
    def _build_state_tab(self):
        f = self.tab_state
        top = ttk.Frame(f, padding=(0, 4))
        top.pack(fill='x', padx=4, pady=(4, 0))
        ttk.Button(top, text='Refresh (F5)',   command=self._on_refresh_state).pack(side='left', padx=2)
        ttk.Button(top, text='Delete selected', command=self._on_delete_selected).pack(side='left', padx=2)
        ttk.Button(top, text='Save config',    command=self._on_save_config).pack(side='left', padx=12)
        self.state_summary_var = tk.StringVar(value='')
        ttk.Label(top, textvariable=self.state_summary_var, foreground='#555',
                  style='Status.TLabel').pack(side='right', padx=4)

        tree_frame = ttk.Frame(f)
        tree_frame.pack(fill='both', expand=True, padx=4, pady=4)
        self.state_tree = ttk.Treeview(
            tree_frame, columns=('details',), show='tree headings', height=20)
        self.state_tree.heading('#0',      text='Item')
        self.state_tree.heading('details', text='Details')
        self.state_tree.column('#0',      width=340, anchor='w')
        self.state_tree.column('details', width=560, anchor='w')
        self.state_tree.tag_configure('section', font=self._tree_font_bold,
                                       background='#eef2f7')
        self.state_tree.tag_configure('exclusive', foreground='#1e7e1e')
        self.state_tree.tag_configure('unprotected', foreground='#a05c00')
        self.state_tree.pack(side='left', fill='both', expand=True)
        yscroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.state_tree.yview)
        yscroll.pack(side='right', fill='y')
        self.state_tree.configure(yscrollcommand=yscroll.set)

    def _refresh_state_view(self):
        self.state_tree.delete(*self.state_tree.get_children())
        groups = self.state['groups']
        dns_routes = self.state['dns_routes']
        ip_routes = self.state['ip_routes']

        g_root = self.state_tree.insert('', 'end', iid='sect::fqdn',
                                         text=f'  📁  FQDN groups ({len(groups)})',
                                         values=('',), open=True, tags=('section',))
        for g, domains in sorted(groups.items()):
            route = next((r for r in dns_routes if r['group'] == g), None)
            if route:
                flags = []
                if route.get('auto'):   flags.append('auto')
                if route.get('reject'): flags.append('exclusive (kill switch)')
                details = f'→ {route["interface"]}  [{", ".join(flags) if flags else "—"}]'
                tag = ('exclusive',) if route.get('reject') else ('unprotected',)
            else:
                details = 'not bound to any route'
                tag = ('unprotected',)
            node = self.state_tree.insert(g_root, 'end', iid=f'group::{g}',
                                           text=f'      {g}  ·  {len(domains)} domains',
                                           values=(details,), tags=tag)
            for d in domains:
                self.state_tree.insert(node, 'end', text=f'            {d}', values=('',))

        r_root = self.state_tree.insert('', 'end', iid='sect::ip',
                                         text=f'  🌐  IP routes ({len(ip_routes)})',
                                         values=('',), open=True, tags=('section',))
        for i, r in enumerate(ip_routes):
            flags = []
            if r.get('auto'):   flags.append('auto')
            if r.get('reject'): flags.append('exclusive (kill switch)')
            tag = ('exclusive',) if r.get('reject') else ('unprotected',)
            self.state_tree.insert(r_root, 'end', iid=f'iproute::{i}',
                                    text=f'      {r["network"]}/{r["mask"]}',
                                    values=(f'→ {r["interface"]}  [{", ".join(flags) if flags else "—"}]',),
                                    tags=tag)

        # Summary
        exc_groups = sum(1 for r in dns_routes if r.get('reject'))
        exc_ips    = sum(1 for r in ip_routes if r.get('reject'))
        self.state_summary_var.set(
            f'{len(groups)} FQDN groups ({exc_groups} exclusive) · '
            f'{len(ip_routes)} IP routes ({exc_ips} exclusive)')

    # ── Catalog tab ────────────────────────────────────────────────────────
    def _build_catalog_tab(self):
        f = self.tab_catalog
        for w in f.winfo_children():
            w.destroy()

        header = ttk.Frame(f, padding=(8, 12, 8, 4))
        header.pack(fill='x')
        ttk.Label(header, text=self.catalog.name,
                  font=('Segoe UI', 11, 'bold')).pack(anchor='w')
        by_cat: dict[str, int] = {}
        for svc in self.catalog.services:
            by_cat[svc.get('category', 'Other')] = by_cat.get(svc.get('category', 'Other'), 0) + 1
        stats = ' · '.join(f'{CATEGORY_ICON.get(c, "📦")} {c}: {n}' for c, n in sorted(by_cat.items()))
        ttk.Label(header,
                  text=f'Version {self.catalog.version} · {len(self.catalog.services)} services',
                  foreground='#555').pack(anchor='w')
        ttk.Label(header, text=stats, foreground='#555').pack(anchor='w', pady=(2, 0))

        url_box = ttk.LabelFrame(f, text=' Import from URL ', padding=8)
        url_box.pack(fill='x', padx=8, pady=10)
        self.url_var = tk.StringVar()
        ttk.Label(url_box, text='URL to services.json (schema_version=1):').pack(anchor='w')
        row = ttk.Frame(url_box)
        row.pack(fill='x', pady=(4, 0))
        ttk.Entry(row, textvariable=self.url_var).pack(side='left', fill='x', expand=True)
        ttk.Button(row, text='Import', command=self._on_import_url).pack(side='left', padx=(6, 0))

        file_box = ttk.LabelFrame(f, text=' Import from file ', padding=8)
        file_box.pack(fill='x', padx=8, pady=4)
        ttk.Button(file_box, text='Load JSON file…', command=self._on_import_file).pack(anchor='w')

        schema_box = ttk.LabelFrame(f, text=' Schema reference ', padding=8)
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
        txt = scrolledtext.ScrolledText(schema_box, height=12, font=self._mono_font,
                                         wrap='none', relief='flat', borderwidth=0)
        txt.pack(fill='both', expand=True)
        txt.insert('1.0', schema_txt)
        txt.configure(state='disabled')

    # ── Hotkeys ────────────────────────────────────────────────────────────
    def _bind_hotkeys(self):
        self.bind('<Control-Return>', lambda e: self._on_apply_services())
        self.bind('<F5>',              lambda e: self._on_refresh_state())
        self.bind('<Escape>',          lambda e: self._on_disconnect() if self.conn_state == ConnState.CONNECTED else None)
        self.pass_entry.bind('<Return>', lambda e: self._on_connect_click())
        self.host_entry.bind('<Return>', lambda e: self.pass_entry.focus_set())
        self.user_entry.bind('<Return>', lambda e: self.pass_entry.focus_set())

    # ── State management ───────────────────────────────────────────────────
    def _set_state(self, s: ConnState, extra: str = ''):
        self.conn_state = s
        self.status_dot.configure(fg=STATE_COLOR[s])
        label = STATE_LABEL[s]
        if extra:
            label += f' — {extra}'
        self.status_label.configure(text=label)
        # Enable/disable inputs
        entry_state = 'normal' if s in (ConnState.DISCONNECTED, ConnState.ERROR) else 'disabled'
        self.host_entry.configure(state=entry_state)
        self.user_entry.configure(state=entry_state)
        self.pass_entry.configure(state=entry_state)
        if s == ConnState.CONNECTED:
            self.btn_connect.configure(text='Disconnect', state='normal')
        elif s == ConnState.CONNECTING:
            self.btn_connect.configure(text='Connecting…', state='disabled')
        else:
            self.btn_connect.configure(text='Connect', state='normal')
        if s != ConnState.CONNECTED:
            self.iface_combo.configure(state='disabled')

    # ── Log ────────────────────────────────────────────────────────────────
    def log(self, msg: str, level: str = 'info'):
        ts = time.strftime('%H:%M:%S')
        self.log_box.configure(state='normal')
        self.log_box.insert('end', f'[{ts}] ', 'ts')
        self.log_box.insert('end', f'{msg}\n', level)
        self.log_box.see('end')
        self.log_box.configure(state='disabled')

    # ── Queue drain ────────────────────────────────────────────────────────
    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
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
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    # ── Connection handlers ────────────────────────────────────────────────
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
            messagebox.showwarning(APP_NAME, 'Enter host, user and password.')
            return
        self._set_state(ConnState.CONNECTING)
        self.log(f'Connecting to {host} as {user}…')

        def connect_and_probe():
            if self.client is not None:
                try: self.client.close()
                except Exception: pass
            c = KeeneticClient(host)
            c.login(user, password)
            ifaces = c.list_interfaces()
            cfg = c.running_config()
            return c, ifaces, cfg

        def done(result, err):
            self.pass_var.set('')  # clear from memory ASAP
            if err is not None:
                self._set_state(ConnState.ERROR)
                self._handle_connect_error(err)
                return
            self.client, self.interfaces, cfg = result
            self.state = parse_running_config(cfg)
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
            self.info_var.set(
                f'{vendor} NDMS {v} · {len(self.interfaces)} interfaces · '
                f'{len(self.state["groups"])} FQDN groups · '
                f'{len(self.state["ip_routes"])} IP routes')
            self._set_state(ConnState.CONNECTED, f'{self.iface_var.get() or "no iface"}')
            self.log(f'Connected. Interface: {self.iface_var.get()}', 'ok')
            self._populate_services()    # to mark applied
            self._refresh_state_view()
            # Persist
            self.ui_cfg['last_host'] = host
            self.ui_cfg['last_user'] = user
            save_ui_config(self.ui_cfg)

        self.worker.run(connect_and_probe, on_done=done)

    def _on_disconnect(self):
        if self.client is not None:
            try: self.client.close()
            except Exception: pass
        self.client = None
        self.interfaces = []
        self.state = {'groups': {}, 'dns_routes': [], 'ip_routes': []}
        self.info_var.set('')
        self.iface_combo.configure(values=[], state='disabled')
        self.iface_var.set('')
        self._set_state(ConnState.DISCONNECTED)
        self._populate_services()
        self._refresh_state_view()
        self.log('Disconnected.', 'info')

    def _handle_connect_error(self, err: Exception):
        cls = type(err).__name__
        msg = str(err)
        if isinstance(err, PermissionError):
            human = f'Login failed — check user/password.\n\n{msg}'
        elif isinstance(err, socket.timeout) or 'timed out' in msg.lower():
            human = f'Timed out connecting to router. Is it reachable on the network?'
        elif isinstance(err, ConnectionRefusedError):
            human = 'Connection refused. Is telnet (port 23) enabled on the router?'
        elif isinstance(err, socket.gaierror):
            human = f'Cannot resolve host "{self.host_var.get()}".'
        elif isinstance(err, ConnectionError):
            human = f'Protocol error: {msg}'
        else:
            human = f'{cls}: {msg}'
        self.log(f'Connect failed: {human}', 'err')
        messagebox.showerror(APP_NAME, human)

    def _ensure_connected(self) -> bool:
        if self.client is None or self.conn_state != ConnState.CONNECTED:
            messagebox.showwarning(APP_NAME, 'Connect to the router first.')
            return False
        return True

    # ── Apply ─────────────────────────────────────────────────────────────
    def _on_apply_services(self):
        if not self._ensure_connected():
            return
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showwarning(APP_NAME, 'Pick an interface.')
            return
        selected = [s for s in self.catalog.services if self.svc_checked.get(s['id'])]
        if not selected:
            messagebox.showinfo(APP_NAME, 'Tick at least one service.')
            return
        exclusive = self.exclusive_var.get()
        kind = 'exclusive (kill switch)' if exclusive else 'non-exclusive'
        if not messagebox.askyesno(
                APP_NAME,
                f'Apply {len(selected)} service(s) via {iface} as {kind}?\n\n'
                'This will recreate the object-groups and dns-proxy routes, '
                'add IP routes if defined, and save configuration.'):
            return

        def do_apply():
            c = self.client
            assert c is not None
            total_doms = total_ips = 0
            for svc in selected:
                group = svc['id']
                if not GROUP_NAME_RE.match(group):
                    self.ui_queue.put(('log', ('warn', f'SKIP {svc["name"]}: invalid group id "{group}"')))
                    continue
                c.delete_fqdn_group(group)
                errs = c.create_fqdn_group(group, svc.get('fqdn', []))
                for e in errs:
                    self.ui_queue.put(('log', ('warn', f'  {group}: {e}')))
                c.bind_fqdn_route(group, iface, auto=True, reject=exclusive)
                total_doms += len(svc.get('fqdn', []))
                self.ui_queue.put(('log', ('ok',
                    f'✓ {svc["name"]}  →  {iface}{" [kill switch]" if exclusive else ""}  '
                    f'({len(svc.get("fqdn", []))} FQDN)')))
                for cidr in svc.get('ipv4_cidr', []):
                    net, mask = cidr_to_mask(cidr)
                    out = c.add_ip_route(net, mask, iface, auto=True, reject=exclusive)
                    if 'dded' in out or 'enewed' in out or 'xists' in out.lower():
                        total_ips += 1
                    else:
                        self.ui_queue.put(('log', ('warn',
                            f'  ip route {cidr}: {out.strip().splitlines()[-1] if out.strip() else "no reply"}')))
            c.save_config()
            cfg = c.running_config()
            return total_doms, total_ips, cfg

        def done(result, err):
            if err is not None:
                self.log(f'Apply failed: {err}', 'err')
                messagebox.showerror(APP_NAME, str(err))
                return
            total_doms, total_ips, cfg = result
            self.state = parse_running_config(cfg)
            self._refresh_state_view()
            self._populate_services()
            self.log(f'Applied: {total_doms} FQDN, {total_ips} IPv4 routes. Config saved.', 'ok')

        self.worker.run(do_apply, on_done=done)

    # ── State / Delete / Save ─────────────────────────────────────────────
    def _on_refresh_state(self):
        if not self._ensure_connected():
            return

        def do(): return self.client.running_config()
        def done(result, err):
            if err is not None:
                self.log(f'Refresh failed: {err}', 'err')
                return
            self.state = parse_running_config(result)
            self._refresh_state_view()
            self._populate_services()
            self.log('State refreshed.', 'ok')

        self.worker.run(do, on_done=done)

    def _on_delete_selected(self):
        if not self._ensure_connected():
            return
        sel = self.state_tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, 'Select an item to delete.')
            return
        iid = sel[0]
        if iid.startswith('group::'):
            name = iid.split('::', 1)[1]
            if not messagebox.askyesno(APP_NAME, f'Delete FQDN group "{name}" and its dns-proxy route?'):
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

        elif iid.startswith('iproute::'):
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

        def do(): return self.client.save_config()
        def done(result, err):
            if err is None:
                self.log('Configuration saved.', 'ok')
            else:
                self.log(f'Save failed: {err}', 'err')

        self.worker.run(do, on_done=done)

    # ── Catalog import ────────────────────────────────────────────────────
    def _on_import_url(self):
        url = self.url_var.get().strip()
        if not url:
            return

        def do(): return Catalog.load_url(url)
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
        path = filedialog.askopenfilename(filetypes=[('JSON', '*.json'), ('All', '*.*')])
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get('schema_version') != 1:
                raise ValueError(f'Unsupported schema_version: {data.get("schema_version")}')
            self.catalog = Catalog(data)
            self.svc_checked.clear()
            self._populate_services()
            self._build_catalog_tab()
            self.log(f'Loaded local "{self.catalog.name}" '
                     f'({len(self.catalog.services)} services).', 'ok')
        except Exception as e:
            messagebox.showerror(APP_NAME, f'Failed to load: {e}')

    # ── Close ──────────────────────────────────────────────────────────────
    def _on_close(self):
        try:
            self.ui_cfg['geometry'] = self.geometry()
            self.ui_cfg['last_interface'] = self.iface_var.get()
            self.ui_cfg['exclusive'] = bool(self.exclusive_var.get())
            save_ui_config(self.ui_cfg)
        except Exception:
            pass
        if self.client is not None:
            try: self.client.close()
            except Exception: pass
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

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
