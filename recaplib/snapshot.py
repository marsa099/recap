"""Snapshot + per-item state: what the UI actually reads.

`refresh` writes the snapshot; the overlay only ever reads it. Writes are
atomic (temp file + rename) because the QML side has a FileView watching the
path — a partial write would surface as a parse error mid-render.

Item *state* (read / starred / dismissed) lives in a separate file, not in the
snapshot, so a refresh that rebuilds every item doesn't wipe what you've
already triaged. State is keyed by the stable item id from item.make().
"""
from __future__ import annotations

import json
import os
import time

HOME = os.path.expanduser("~")
CACHE = os.path.join(os.environ.get("XDG_CACHE_HOME", HOME + "/.cache"), "recap")
CONFIG = os.path.join(os.environ.get("XDG_CONFIG_HOME", HOME + "/.config"), "recap")

SNAPSHOT = os.path.join(CACHE, "snapshot.json")
STATE = os.path.join(CACHE, "state.json")
UNDO = os.path.join(CACHE, "undo.json")


def _ensure():
    os.makedirs(CACHE, exist_ok=True)


def write_json(path, obj):
    """Atomic: a reader either sees the old file or the new one, never half."""
    _ensure()
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_state():
    return read_json(STATE, {})


def save_state(state):
    write_json(STATE, state)


def apply_state(items):
    """Overlay persisted triage onto freshly collected items."""
    state = load_state()
    out = []
    for it in items:
        s = state.get(it["id"])
        if s:
            it["state"].update(s)
        # A dismissed item stays gone until its identity changes — for an
        # advisory that means until the version moves, since the version is
        # part of the provider key.
        if it["state"].get("gone"):
            continue
        out.append(it)
    return out


def save_snapshot(items, meta):
    write_json(SNAPSHOT, {"generated": int(time.time()), "meta": meta, "items": items})


def load_snapshot():
    return read_json(SNAPSHOT, {"generated": 0, "meta": {}, "items": []})


def set_item_state(item_id, field, value):
    """Record one triage action and push its inverse onto the undo stack."""
    state = load_state()
    cur = state.setdefault(item_id, {})
    prev = cur.get(field, False)
    cur[field] = value
    save_state(state)
    stack = read_json(UNDO, [])
    stack.append({"id": item_id, "field": field, "prev": prev, "at": int(time.time())})
    write_json(UNDO, stack[-100:])
    return prev


def undo_last():
    stack = read_json(UNDO, [])
    if not stack:
        return None
    last = stack.pop()
    state = load_state()
    state.setdefault(last["id"], {})[last["field"]] = last["prev"]
    save_state(state)
    write_json(UNDO, stack)
    return last
