"""Auto-discover Keenetic routers on the LAN.

Strategy (stop on first step that finds at least one router):

  Step 0 — last known host from ui.json  (1 probe, ~500 ms)
  Step 1 — default gateways from ipconfig (1-4 probes, ~700 ms)
  Step 2 — /24 sweep of each gateway      (~254 probes × per-GW, ~2-3 s parallel)
  Step 3 — typical home subnets           (~1500 probes, ~5-6 s parallel)

The probe is a single ``GET http://<ip>/auth`` — Keenetic answers with HTTP
401 and two header-only markers that no other vendor emits:

    X-NDM-Realm: <realm>
    X-NDM-Challenge: <hex>

That combination is unique enough to call a positive "this is a Keenetic"
without any false positives from generic Basic-Auth devices (NAS, printers,
IP cameras).

The module is stdlib-only: ``urllib`` + ``socket`` + ``ctypes`` (on Windows).
No new runtime dependency is added to the PyInstaller bundle.
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import logging
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Iterable, Optional

LOGGER = logging.getLogger(__name__)

# Typical home subnets tried when no default gateway is available.
# Ordered roughly by frequency in the wild.
TYPICAL_SUBNETS: tuple[str, ...] = (
    '192.168.1.0/24',
    '192.168.0.0/24',
    '192.168.32.0/24',   # Keenetic cascade (author's default)
    '192.168.100.0/24',
    '10.0.0.0/24',
    '172.16.0.0/24',
)

# Connection / read timeouts for probes. Short because on a reachable IP
# the router answers in tens of milliseconds; on a dead IP we want to
# fail fast.
DEFAULT_PROBE_TIMEOUT = 0.4
GW_PROBE_TIMEOUT = 0.7
LAST_HOST_TIMEOUT = 0.5

# Parallelism for subnet sweep. 128 is comfortable for modern Windows
# (default ephemeral port range is 16k), keeps memory low.
DEFAULT_WORKERS = 128


# ── Single-host probe ────────────────────────────────────────────────────


def probe(host: str, timeout: float = DEFAULT_PROBE_TIMEOUT) -> Optional[dict]:
    """Probe one host. Returns {'host', 'realm', 'rtt_ms'} if it's a
    Keenetic (status 401 + X-NDM-Challenge), else None.

    Never raises — all network errors translate to None so the caller can
    feed results to a ThreadPoolExecutor.map without wrapping.
    """
    if not host:
        return None
    url = f'http://{host}/auth'
    req = urllib.request.Request(
        url, method='GET', headers={'User-Agent': 'kn-gui-discover'})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            headers = dict(resp.headers or {})
    except urllib.error.HTTPError as e:
        status = e.code
        headers = dict(e.headers or {})
    except (urllib.error.URLError, socket.timeout, OSError):
        return None
    except Exception:  # noqa: BLE001 — defensive, never propagate to the pool
        return None

    # Accept both: already-authenticated (200) and fresh-challenge (401).
    # A bare 401 without X-NDM-Challenge means a non-Keenetic Basic-Auth
    # device — reject it so we don't mistake a NAS for a router.
    if status not in (200, 401):
        return None
    challenge = headers.get('X-NDM-Challenge') or headers.get('x-ndm-challenge')
    realm = (headers.get('X-NDM-Realm') or
             headers.get('x-ndm-realm') or '')
    if status == 401 and not challenge:
        return None
    return {
        'host': host,
        'realm': realm,
        'rtt_ms': int((time.monotonic() - t0) * 1000),
    }


# ── Default-gateway enumeration (Windows-first) ──────────────────────────


def _gateways_via_ipconfig() -> list[str]:
    """Parse `ipconfig` output to find "Default Gateway" / «Основной шлюз»
    lines. Works on both English and Russian Windows locales because we
    look for the IPv4 value on the line, not the label."""
    try:
        out = subprocess.run(
            ['ipconfig'],
            capture_output=True, text=True, timeout=3,
            creationflags=subprocess.CREATE_NO_WINDOW
            if sys.platform == 'win32' else 0,
        ).stdout
    except (OSError, subprocess.SubprocessError) as e:
        LOGGER.debug('ipconfig failed: %s', e)
        return []
    gateways: list[str] = []
    # Match the Windows layout: "Default Gateway . . . . . . . . . : 192.168.1.1"
    # Cyrillic label: "Основной шлюз . . . . . . . . . . : 192.168.1.1"
    # Keep it simple — any line whose label contains "ateway" or "шлюз"
    # followed by an IPv4 address.
    import re
    gw_label = re.compile(r'(?i)(gateway|шлюз)')
    ipv4 = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    for line in out.splitlines():
        if not gw_label.search(line):
            continue
        m = ipv4.search(line)
        if not m:
            continue
        gw = m.group(1)
        # Skip the label-without-value line ("Default Gateway . . : ") and
        # the zero address.
        if gw == '0.0.0.0':
            continue
        if gw not in gateways:
            gateways.append(gw)
    return gateways


def list_default_gateways() -> list[str]:
    """Return a de-duplicated list of default gateways on active IPv4
    adapters. Empty list when unavailable (non-Windows, or ipconfig
    blocked by policy)."""
    if sys.platform != 'win32':
        # Non-Windows path — parse `ip route` output.
        try:
            out = subprocess.run(
                ['ip', 'route'], capture_output=True, text=True, timeout=3,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return []
        gws: list[str] = []
        for line in out.splitlines():
            # "default via 192.168.1.1 dev wlan0 ..."
            parts = line.split()
            if len(parts) >= 3 and parts[0] == 'default' and parts[1] == 'via':
                gw = parts[2]
                if gw not in gws:
                    gws.append(gw)
        return gws
    return _gateways_via_ipconfig()


def local_ip_guess() -> Optional[str]:
    """Return our outgoing local IPv4 address. Useful when we can't find
    a gateway but want to infer /24 from our own address.

    This uses the UDP-connect trick: ``connect()`` on a datagram socket
    doesn't actually send anything, but the OS picks the adapter it
    *would* use to reach the target and fills in our side of the
    connection. Works even on offline machines as long as any adapter
    is up."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


# ── Subnet sweep ─────────────────────────────────────────────────────────


def scan_subnet(cidr: str, *,
                timeout: float = DEFAULT_PROBE_TIMEOUT,
                workers: int = DEFAULT_WORKERS,
                cancel: Optional[threading.Event] = None,
                on_progress: Optional[Callable[[int, int], None]] = None,
                ) -> list[dict]:
    """Probe every host in *cidr* in parallel. Returns a list of hits
    sorted by RTT ascending (closest routers first)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if net.prefixlen < 20:
        # Refuse to sweep anything larger than /20 — that's 4096 probes,
        # clearly a caller bug.
        LOGGER.warning('scan_subnet: refusing %s (prefix < /20)', cidr)
        return []

    hosts = [str(h) for h in net.hosts()]
    results: list[dict] = []
    done = 0
    total = len(hosts)
    if on_progress:
        on_progress(0, total)

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe, h, timeout): h for h in hosts}
        try:
            for fut in cf.as_completed(futs):
                if cancel is not None and cancel.is_set():
                    break
                try:
                    r = fut.result()
                except Exception:  # noqa: BLE001
                    r = None
                if r:
                    results.append(r)
                done += 1
                if on_progress and (done % 16 == 0 or done == total):
                    on_progress(done, total)
        finally:
            # cancel all outstanding futures so the pool shuts down fast.
            for f in futs:
                if not f.done():
                    f.cancel()

    results.sort(key=lambda x: x['rtt_ms'])
    return results


# ── High-level API ───────────────────────────────────────────────────────


def find_keenetic(*,
                  last_host: Optional[str] = None,
                  cancel: Optional[threading.Event] = None,
                  on_progress: Optional[Callable[[str], None]] = None,
                  include_typical: bool = True,
                  ) -> list[dict]:
    """Find Keenetic routers on the LAN using a tiered strategy.

    Args:
        last_host:       If given, probe this IP first — almost always a hit
                         for returning users.
        cancel:          Optional Event to abort long sweeps early.
        on_progress:     Called with a human-readable status string between
                         steps (for UI logging).
        include_typical: Whether to fall back to common home subnets
                         (192.168.1/24 etc) when no gateway is found.

    Returns:
        List of {'host', 'realm', 'rtt_ms'} dicts, sorted by RTT. Empty
        when nothing found.
    """
    def note(msg: str) -> None:
        LOGGER.info('discovery: %s', msg)
        if on_progress:
            try:
                on_progress(msg)
            except Exception:  # noqa: BLE001
                pass

    def _cancelled() -> bool:
        return cancel is not None and cancel.is_set()

    # Step 0 — last known host.
    if last_host:
        note(f'Проверка последнего адреса {last_host}…')
        r = probe(last_host, timeout=LAST_HOST_TIMEOUT)
        if r:
            return [r]
        if _cancelled():
            return []

    # Step 1 — default gateways.
    gws = list_default_gateways()
    note(f'Найдено шлюзов: {len(gws)}'
         if gws else 'Шлюзов не обнаружено')
    if gws and not _cancelled():
        hits: list[dict] = []
        with cf.ThreadPoolExecutor(max_workers=max(1, len(gws))) as pool:
            for r in pool.map(lambda g: probe(g, GW_PROBE_TIMEOUT), gws):
                if r:
                    hits.append(r)
        if hits:
            return sorted(hits, key=lambda x: x['rtt_ms'])

    # Step 2 — /24 of every gateway we found (even if GW itself is not
    # a Keenetic — maybe the Keenetic sits at .254 or behind NAT).
    sweep_cidrs: list[str] = []
    for gw in gws:
        try:
            cidr = str(ipaddress.ip_network(f'{gw}/24', strict=False))
        except ValueError:
            continue
        if cidr not in sweep_cidrs:
            sweep_cidrs.append(cidr)

    # Also try our own /24 if we couldn't find a gateway.
    if not sweep_cidrs:
        me = local_ip_guess()
        if me:
            try:
                sweep_cidrs.append(str(ipaddress.ip_network(f'{me}/24', strict=False)))
            except ValueError:
                pass

    aggregate: list[dict] = []
    for cidr in sweep_cidrs:
        if _cancelled():
            break
        note(f'Сканирование подсети {cidr}…')
        aggregate.extend(scan_subnet(cidr, cancel=cancel))

    if aggregate:
        return sorted(aggregate, key=lambda x: x['rtt_ms'])

    # Step 3 — typical subnets (opt-in, slower).
    if not include_typical or _cancelled():
        return []

    for cidr in TYPICAL_SUBNETS:
        if _cancelled():
            break
        if cidr in sweep_cidrs:
            continue   # already tried
        note(f'Сканирование общей подсети {cidr}…')
        aggregate.extend(scan_subnet(cidr, cancel=cancel))

    return sorted(aggregate, key=lambda x: x['rtt_ms'])
