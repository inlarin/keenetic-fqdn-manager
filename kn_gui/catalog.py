"""Service catalog: load, query, import from URL/file with safety caps."""
from __future__ import annotations

import json
from typing import Optional

from .constants import MAX_HTTP_BYTES
from .net import _http_get
from .paths import data_path


class Catalog:
    def __init__(self, data: dict):
        self.data = data

    @property
    def version(self) -> str:
        return self.data.get('catalog_version', '?')

    @property
    def name(self) -> str:
        return self.data.get('catalog_name', 'Unnamed catalog')

    @property
    def services(self) -> list[dict]:
        return self.data.get('services', [])

    def service(self, sid: str) -> Optional[dict]:
        for s in self.services:
            if s.get('id') == sid:
                return s
        return None

    @classmethod
    def load_default(cls) -> 'Catalog':
        with open(data_path('services.json'), 'r', encoding='utf-8') as f:
            return cls(json.load(f))

    @classmethod
    def load_url(cls, url: str, timeout: float = 10.0) -> 'Catalog':
        text = _http_get(url, timeout=timeout, max_bytes=MAX_HTTP_BYTES)
        data = json.loads(text)
        if data.get('schema_version') != 1:
            raise ValueError(f'Unsupported schema_version: {data.get("schema_version")}')
        return cls(data)

    @classmethod
    def load_file(cls, path: str) -> 'Catalog':
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if data.get('schema_version') != 1:
            raise ValueError(f'Unsupported schema_version: {data.get("schema_version")}')
        return cls(data)
