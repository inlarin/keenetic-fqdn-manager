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


# ── FQDN / group-name validation (Keenetic-specific) ────────────────────────

_FQDN_LABEL_RE = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

# Keenetic auto-applies suffix-match: `example.com` covers `*.example.com`.
# Explicit `*.` prefixes are rejected by the CLI.
_WILDCARD_PREFIX = re.compile(r'^\*\.?')

MAX_ENTRIES_PER_GROUP = 300
"""Soft limit for `include` entries in one `object-group fqdn`. Beyond this,
Keenetic's dns-proxy starts to degrade (slow resolve, CPU spikes). Value is
the de-facto standard used by yangirov/keenetic-geosite-sync."""


def is_valid_fqdn(fqdn: str) -> bool:
    """Strict check: RFC 1035 labels, ASCII only, ≥2 labels, no wildcards."""
    if not isinstance(fqdn, str):
        return False
    name = fqdn.strip().rstrip('.')
    if not name or len(name) > 253:
        return False
    labels = name.split('.')
    if len(labels) < 2:
        return False
    return all(_FQDN_LABEL_RE.match(lab) for lab in labels)


def normalize_fqdn(fqdn: str) -> tuple[str, str]:
    """Return (normalized, warning_or_empty).

    - `*.example.com` → `example.com` + warning about auto-suffix-match.
    - Trailing dot stripped.
    - IDN stays as-is (caller must Punycode before).
    - Invalid FQDNs returned unchanged with a warning.
    """
    name = fqdn.strip().rstrip('.')
    warn = ''
    m = _WILDCARD_PREFIX.match(name)
    if m:
        name = name[m.end():]
        warn = (f'wildcard {fqdn!r} → {name!r} '
                '(Keenetic auto-matches all subdomains)')
    if not is_valid_fqdn(name):
        return fqdn.strip(), f'invalid FQDN: {fqdn!r}'
    return name, warn


def validate_fqdns(fqdns: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Split into (valid, warnings, invalid).

    `valid` = ready to `include`.
    `warnings` = normalized FQDNs with notes (wildcards stripped etc.).
    `invalid` = skipped entirely.
    """
    valid: list[str] = []
    warnings: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for raw in fqdns:
        norm, warn = normalize_fqdn(raw)
        if warn and 'invalid' in warn:
            invalid.append(warn)
            continue
        if norm.lower() in seen:
            continue  # dedup silently
        seen.add(norm.lower())
        valid.append(norm)
        if warn:
            warnings.append(warn)
    return valid, warnings, invalid


def validate_group_name(name: str) -> str | None:
    """Return an error message if `name` is not a valid Keenetic object-group
    name, or None if OK. Keenetic requires ^[A-Za-z][A-Za-z0-9_]{0,31}$."""
    from .constants import GROUP_NAME_RE
    if not name:
        return 'group name is empty'
    if len(name) > 32:
        return f'group name too long ({len(name)} > 32 chars)'
    if not GROUP_NAME_RE.match(name):
        return (f'group name {name!r} contains invalid characters; '
                'allowed: letters, digits, underscores; must start with a letter')
    return None


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
