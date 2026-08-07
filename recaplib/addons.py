"""Addons: any executable in ~/.config/recap/addons/ that prints JSON items.

No plugin API, no base class, no registration — drop a file in, chmod +x, it's
in the digest. Write it in Python, bash, Node, whatever. The built-in providers
use the same item shape, so an addon is not a second-class citizen.

Contract:
  stdout  a JSON array of objects, or {"section": "...", "items": [...]}
  fields  title (required) · summary · who · sub · when · lane · url · score
          · accent · priority
  exit 0  success. Non-zero, a timeout, or unparseable output surfaces as a
          one-line failure row rather than taking the whole refresh down.
"""
from __future__ import annotations

import json
import os
import subprocess

from . import item
from .snapshot import CONFIG

DIR = os.path.join(CONFIG, "addons")
TIMEOUT = 20


def _norm(raw, name, section):
    lane = raw.get("lane")
    if lane not in (item.WORK, item.PRIVATE):
        lane = item.PRIVATE
    url = raw.get("url") or ""
    return item.make(
        source=f"addon:{name}",
        lane=lane,
        section=section,
        key=raw.get("id") or raw.get("title", ""),
        who=raw.get("who") or name,
        sub=raw.get("sub") or "",
        title=raw.get("title") or "(untitled)",
        summary=raw.get("summary") or "",
        when=raw.get("when") or "",
        ts=raw.get("ts") or 0,
        accent=raw.get("accent") or "sage",
        score=raw.get("score", 50),
        priority=bool(raw.get("priority")),
        goto={"kind": "url", "url": url} if url else {"kind": "nothing"},
        actions=["read", "trash", "star"],
    )


def collect():
    if not os.path.isdir(DIR):
        return [], "none installed"
    out = []
    names = []
    for name in sorted(os.listdir(DIR)):
        path = os.path.join(DIR, name)
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        names.append(name)
        section = name.replace("-", " ").replace("_", " ").title()
        try:
            r = subprocess.run([path], capture_output=True, text=True, timeout=TIMEOUT)
            if r.returncode != 0:
                raise RuntimeError((r.stderr or "").strip()[:200] or f"exit {r.returncode}")
            data = json.loads(r.stdout or "[]")
        except Exception as e:
            out.append(item.stale_notice(
                f"addon:{name}", section, item.PRIVATE,
                f"addon `{name}` failed",
                f"{e.__class__.__name__}: {e}",
                when="failed",
            ))
            continue
        if isinstance(data, dict):
            section = data.get("section") or section
            data = data.get("items") or []
        for raw in data:
            if isinstance(raw, dict):
                out.append(_norm(raw, name, section))
    return out, (", ".join(names) if names else "none installed")
