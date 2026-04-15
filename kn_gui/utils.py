"""Pure helpers with no app-state dependencies."""
from __future__ import annotations

import json
import re

from .paths import CONFIG_DIR, CONFIG_FILE


def strip_ansi(s: str) -> str:
    """Remove ANSI escape sequences (e.g. Keenetic's erase-to-EOL)."""
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', s)


def cidr_to_mask(cidr: str) -> tuple[str, str]:
    """'91.108.4.0/22' → ('91.108.4.0', '255.255.252.0'). Raises ValueError
    on malformed input."""
    if '/' not in cidr:
        raise ValueError(f'missing /prefix in CIDR: {cidr!r}')
    net, prefix_s = cidr.split('/', 1)
    prefix = int(prefix_s)
    if not (0 <= prefix <= 32):
        raise ValueError(f'prefix out of range: {prefix}')
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    mask = '.'.join(str((mask_int >> (24 - 8 * i)) & 0xFF) for i in range(4))
    return net, mask


def is_error_output(text: str) -> bool:
    """Heuristic: Keenetic CLI error lines contain 'error' or 'invalid'.
    Single helper so we don't sprinkle substring checks all over."""
    if not text:
        return False
    lo = text.lower()
    return 'rror' in lo or 'nvalid' in lo


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
