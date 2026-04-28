"""Filesystem paths used by the app.

All `sys._MEIPASS` / PyInstaller hacks live here; rest of the codebase
treats the returned paths as given."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .constants import APP_NAME

CONFIG_DIR: Path = Path(os.environ.get('APPDATA', os.path.expanduser('~'))) / 'KeeneticFqdnManager'
CONFIG_FILE: Path = CONFIG_DIR / 'ui.json'


def _bundle_base() -> Path:
    """Where bundled data files live at runtime."""
    if hasattr(sys, '_MEIPASS'):
        return Path(sys._MEIPASS)
    # dev: repo root is parent of the `kn_gui/` package directory
    return Path(__file__).resolve().parent.parent


def data_path(rel: str) -> Path:
    """Locate a bundled data file (services.json, bootstrap_servers.json)."""
    # Bundled under `data/<rel>` via PyInstaller `--add-data "data;data"`
    return _bundle_base() / 'data' / rel


def _exe_dir() -> Path:
    """Directory containing the .exe (frozen) or the package sources (dev)."""
    if getattr(sys, 'frozen', False) or hasattr(sys, '_MEIPASS'):
        return Path(os.path.dirname(sys.executable))
    return Path(__file__).resolve().parent.parent


def _cache_dir() -> Path:
    """Cache lives under %APPDATA%/KeeneticFqdnManager/cache by default.

    Earlier (≤ v3.6.1) the cache preferred a folder next to the .exe so it
    was easy to spot. Problem: users often redownload the .exe from GitHub
    to a different folder (or OneDrive on Desktop relocates it), and the
    next-to-exe cache turns into a fresh empty folder every run — defeating
    the whole point of caching. %APPDATA% is the canonical Windows location
    for per-user mutable state; it survives every exe move/redownload.

    A legacy `<exe-dir>/cache/cache.json` left over from old versions is
    silently used as a one-time seed when %APPDATA% has no cache yet, so
    upgrading users don't have to re-fetch everything."""
    primary = CONFIG_DIR / 'cache'
    try:
        primary.mkdir(parents=True, exist_ok=True)
        # One-time seed from legacy location if APPDATA cache is empty.
        legacy = _exe_dir() / 'cache' / 'cache.json'
        target = primary / 'cache.json'
        if legacy.exists() and not target.exists():
            try:
                target.write_bytes(legacy.read_bytes())
            except Exception:
                pass
        return primary
    except Exception:
        # Ultra-fallback: directory next to the exe. Almost never reached —
        # APPDATA write fails only on truly broken setups.
        fb = _exe_dir() / 'cache'
        fb.mkdir(parents=True, exist_ok=True)
        return fb


CACHE_DIR: Path = _cache_dir()
CACHE_FILE: Path = CACHE_DIR / 'cache.json'
