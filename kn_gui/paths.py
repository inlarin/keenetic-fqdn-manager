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
    """Prefer folder next to the .exe / package. Fall back to %APPDATA% if
    that folder is read-only (e.g. installed under Program Files)."""
    candidate = _exe_dir() / 'cache'
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        test = candidate / '.wtest'
        test.write_text('')
        test.unlink()
        return candidate
    except Exception:
        fb = CONFIG_DIR / 'cache'
        fb.mkdir(parents=True, exist_ok=True)
        return fb


CACHE_DIR: Path = _cache_dir()
CACHE_FILE: Path = CACHE_DIR / 'cache.json'
