"""Transport-agnostic implementation of FQDN object-group operations.

Both the Telnet (`client.KeeneticClient`) and the RCI (`rci_transport.
KeeneticRCIClient`) transports expose the same FQDN-group API:

    create_fqdn_group(name, entries, description='') -> (created, errs)
    delete_fqdn_group(name)
    bulk_delete_fqdn_groups(names, …)
    list_managed_fqdn_groups() -> list[dict]

Until v3.4.0 each transport carried its own ~70-line copy of these.
This module hosts the single, tested implementation, parameterised by
two CLI callbacks:

    run_expect(cmd, timeout=10.0) -> str        # raises on error
    run(cmd, timeout=10.0) -> tuple[str, bool]  # never raises

Both transports pass bound method references; everything FQDN-group-
related happens here, so a future change (new validation, another
retry, etc.) only has to touch one file.
"""
from __future__ import annotations

import re
from typing import Callable, Iterable, Optional

from .constants import MANAGED_INTERFACE_TAG
from .utils import (MAX_ENTRIES_PER_GROUP,
                     validate_fqdns, validate_group_name)


def _sanitize_cli_value(s: str) -> str:
    """Strip newline/CR/NUL that would break a Telnet or /rci/parse
    command. Mirrors the per-transport helper of the same name."""
    return s.replace('\n', ' ').replace('\r', '').replace('\x00', '')


def create_fqdn_group(name: str, entries: list[str],
                       description: str,
                       run_expect: Callable[..., str],
                       run: Callable[..., tuple[str, bool]],
                       ) -> tuple[list[str], list[str]]:
    """Create (or update) an `object-group fqdn` and `include` each entry.

    Validation:
      * Group name against Keenetic's 32-char regex.
      * Entries normalised (wildcards stripped) and validated.
      * Invalid FQDNs are skipped and returned in errs.
      * Lists longer than MAX_ENTRIES_PER_GROUP (~300) are split into
        `<name>`, `<name>_2`, `<name>_3`, … with name truncation so the
        derived names still fit the 32-char limit.

    The description is always prefixed with MANAGED_INTERFACE_TAG so
    list_managed_fqdn_groups() can later tell app-owned groups from
    user-configured ones.

    Returns ``(created_names, errs)``. The caller MUST bind each name
    in ``created_names`` via bind_fqdn_route — otherwise split-parts
    leak traffic around the VPN.
    """
    errs: list[str] = []
    created: list[str] = []

    name_err = validate_group_name(name)
    if name_err:
        errs.append(f'group name: {name_err}')
        return created, errs

    valid, warnings, invalid = validate_fqdns(entries)
    errs.extend(warnings)
    errs.extend(invalid)

    if not valid:
        errs.append('no valid entries to include')
        return created, errs

    # Split into chunks ≤MAX_ENTRIES_PER_GROUP.
    chunks: list[tuple[str, list[str]]] = []
    if len(valid) <= MAX_ENTRIES_PER_GROUP:
        chunks.append((name, valid))
    else:
        for i in range(0, len(valid), MAX_ENTRIES_PER_GROUP):
            chunk = valid[i:i + MAX_ENTRIES_PER_GROUP]
            suffix = '' if i == 0 else f'_{i // MAX_ENTRIES_PER_GROUP + 1}'
            chunk_name = f'{name}{suffix}'
            if validate_group_name(chunk_name):
                # Derived name exceeded 32 chars — truncate the base.
                max_base = 32 - len(suffix)
                chunk_name = f'{name[:max_base]}{suffix}'
            chunks.append((chunk_name, chunk))
        if len(chunks) > 1:
            errs.append(
                f'split {len(valid)} entries into {len(chunks)} groups '
                f'(Keenetic limit ~{MAX_ENTRIES_PER_GROUP}/group): '
                + ', '.join(f'{n}({len(e)})' for n, e in chunks))

    # Every managed group carries the tag, even if description= was empty.
    # list_managed_fqdn_groups() relies on this being unconditional.
    tagged_desc = (f'{MANAGED_INTERFACE_TAG} {description}'.strip()
                    if description else MANAGED_INTERFACE_TAG)

    for chunk_name, chunk_entries in chunks:
        try:
            run_expect(f'object-group fqdn {chunk_name}')
            safe = _sanitize_cli_value(tagged_desc).replace('"', '').strip()
            if safe:
                try:
                    run_expect(f'description "{safe}"')
                except RuntimeError as e:
                    errs.append(f'{chunk_name} description: {e}')
            for entry in chunk_entries:
                try:
                    run_expect(f'include {entry}')
                except RuntimeError as e:
                    errs.append(f'include {entry}: {e}')
            created.append(chunk_name)
        finally:
            # Always leave the object-group context even on error.
            run('exit')
    return created, errs


_GROUP_DECL_RE  = re.compile(r'^object-group fqdn\s+(\S+)\s*$')
_ROUTE_DECL_RE  = re.compile(r'^\s+route object-group\s+(\S+)\s+')


def _parse_existing_groups_and_routes(running_config: str
                                       ) -> tuple[set[str], set[str]]:
    """Scan a `show running-config` dump and return:
        (set of object-group fqdn names, set of names that have a
         dns-proxy route binding).
    Both sets are used to skip `no …` commands for entities that
    aren't on the router — the dominant cost of bulk delete."""
    groups: set[str] = set()
    routes: set[str] = set()
    for line in running_config.splitlines():
        m = _GROUP_DECL_RE.match(line)
        if m:
            groups.add(m.group(1))
            continue
        m = _ROUTE_DECL_RE.match(line)
        if m:
            routes.add(m.group(1))
    return groups, routes


def delete_fqdn_group(name: str,
                       run: Callable[..., tuple[str, bool]],
                       existing_groups: Optional[set[str]] = None,
                       existing_routes: Optional[set[str]] = None) -> None:
    """Delete the group + its dns-proxy route + any auto-split siblings
    (`_2`..`_50`). Covers groups up to ~15k entries — well past realistic
    service catalogs.

    When ``existing_groups`` / ``existing_routes`` are provided (e.g. by
    :func:`bulk_delete_fqdn_groups`), `no …` commands for entities that
    don't exist are skipped — this turns a 100-command-per-name blind
    sweep into ~2 commands for typical (single-chunk) groups, making
    bulk delete ~50× faster on a router with 30+ groups."""
    candidates = [name] + [f'{name}_{i}' for i in range(2, 51)]
    for sib in candidates:
        if existing_routes is None or sib in existing_routes:
            run(f'no dns-proxy route object-group {sib}')
        if existing_groups is None or sib in existing_groups:
            run(f'no object-group fqdn {sib}')


def bulk_delete_fqdn_groups(names: Iterable[str],
                              run: Callable[..., tuple[str, bool]],
                              running_config_fn: Callable[[], str]) -> None:
    """Delete many groups efficiently — fetches `show running-config` once
    and uses the result to drop the blind ``_2``..``_50`` sibling sweep
    that :func:`delete_fqdn_group` does for each name when called solo.

    Without this helper, a delete of 30 user groups fires 100 commands
    per name = 3000 commands total (≈ 5–15 minutes over RCI when NDM
    is busy). With it: 1 fetch + 2 commands × 30 names ≈ 60 commands
    plus one big read.

    Routes are removed BEFORE the groups they bind to — the reverse
    triggers ``Network::ObjectGroup error: in use`` on the route table.
    """
    cfg = running_config_fn() or ''
    groups, routes = _parse_existing_groups_and_routes(cfg)
    for name in names:
        delete_fqdn_group(name, run,
                            existing_groups=groups,
                            existing_routes=routes)


def list_managed_fqdn_groups(running_config_fn: Callable[[], str]) -> list[dict]:
    """Return groups whose description carries MANAGED_INTERFACE_TAG.

    Each entry: ``{'name', 'description', 'entries'}``.
    """
    # Imported here because state.py itself imports from .utils (no cycle).
    from .state import parse_running_config

    cfg = running_config_fn()
    parsed = parse_running_config(cfg)
    out: list[dict] = []
    for group_name, desc in parsed.get('group_descriptions', {}).items():
        if MANAGED_INTERFACE_TAG in desc:
            out.append({
                'name':        group_name,
                'description': desc,
                'entries':     parsed['groups'].get(group_name, []),
            })
    return out
