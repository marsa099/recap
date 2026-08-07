"""Config from ~/.config/recap/config.toml, with dotted lookup.

tomllib is stdlib since 3.11. A missing file is fine — every call site passes
a default, so recap runs with zero configuration.
"""
from __future__ import annotations

import os
import tomllib

from .snapshot import CONFIG

PATH = os.path.join(CONFIG, "config.toml")
_cache = None


def _load():
    global _cache
    if _cache is None:
        try:
            with open(PATH, "rb") as f:
                _cache = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError):
            _cache = {}
    return _cache


def get(dotted, default=None):
    node = _load()
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node
