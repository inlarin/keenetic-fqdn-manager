"""Shared constants: app metadata, TTLs, UI labels, regex, tree iid prefixes."""
from __future__ import annotations

import re
from enum import Enum

APP_NAME = 'Keenetic FQDN Manager'
APP_VERSION = '3.5.1'

DEFAULT_ROUTER = '192.168.32.1'
DEFAULT_USER = 'admin'
DEFAULT_TELNET_PORT = 23

# Tag embedded in the `description` of any SSTP/VPN interface we create.
# It lets us distinguish our managed interfaces from ones the user set up
# in the router web-UI, so the "Delete managed VPN" button only removes
# interfaces we own. Keep the marker short and descriptive-free so it
# doesn't waste the router's 64-char description limit.
MANAGED_INTERFACE_TAG = '[kn-gui]'

# Priority for `ip global <N>` on managed VPN interfaces. In Keenetic's
# connection-priority table, lower = higher priority. 700 places the
# interface above manual routes but below the main ISP link, which is
# the right default for a VPN client.
MANAGED_VPN_IP_GLOBAL_PRIORITY = 700

# Valid object-group / interface identifier characters.
GROUP_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]{0,31}$')

# Category → emoji icon used in the Services tree.
CATEGORY_ICON = {
    'AI': '🤖', 'Video': '📺', 'Music': '🎵', 'Messaging': '💬',
    'Social': '👥', 'Dev': '⚙', 'Productivity': '📝', 'Content': '📰',
    'Gaming': '🎮', 'Payment': '💳', 'Other': '📦',
}

# TTLs for DiskCache entries (seconds).
TTL_VPNGATE      = 5 * 60
TTL_V2FLY        = 6 * 60 * 60
TTL_IP_PROVIDER  = 24 * 60 * 60
TTL_ASN          = 24 * 60 * 60

# Network safety: cap how many bytes HTTP fetchers will read.
MAX_HTTP_BYTES = 20 * 1024 * 1024   # 20 MB — VPN Gate CSV comfortably fits.

# VPN Gate public CSV.
VPNGATE_URL = 'http://www.vpngate.net/api/iphone/'


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
    ConnState.DISCONNECTED: 'Не подключён',
    ConnState.CONNECTING:   'Подключение…',
    ConnState.CONNECTED:    'Подключён',
    ConnState.ERROR:        'Ошибка',
}

# Tree iid namespaces (centralized so UI code doesn't sprinkle magic strings).
IID_CATEGORY = 'cat::'
IID_SERVICE  = 'svc::'
IID_GROUP    = 'group::'
IID_IPROUTE  = 'iproute::'
IID_SECTION  = 'sect::'
IID_BOOT     = 'boot::'
