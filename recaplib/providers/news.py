"""Hacker News, filtered down to what actually touches you.

Two passes, cheap first:
  1. keyword/domain match against ~/.config/recap/config.toml `news.interests`
  2. anything above `news.big_points` regardless of topic — the "generally big
     news worth knowing" case that no keyword list expresses

Stories already shown on a previous run are suppressed via seen.json, so a
story that camps on the front page for two days doesn't reappear every refresh.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import os
import re
import time
import urllib.request

from .. import item
from ..config import get
from ..snapshot import CACHE, read_json, write_json

API = "https://hacker-news.firebaseio.com/v0"
SEEN = os.path.join(CACHE, "seen.json")


def _get(url, timeout=8):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _story(sid):
    try:
        return _get(f"{API}/item/{sid}.json")
    except Exception:
        return None


def collect():
    scan = int(get("news.scan", 60))
    keep = int(get("news.keep", 6))
    big = int(get("news.big_points", 400))
    interests = [s.lower() for s in get("news.interests", [
        "nix", "nixos", "wayland", "niri", "quickshell", "hyprland",
        ".net", "asp.net", "dotnet", "azure", "postgres", "neon",
        "next.js", "nextjs", "vercel", "react", "typescript",
        "swift", "swiftui", "ios", "claude", "anthropic", "llm", "agent",
        "self-host", "selfhost", "rust", "sqlite", "vim", "neovim",
    ])]
    work_terms = [s.lower() for s in get("news.work_interests",
                                         [".net", "asp.net", "dotnet", "azure", "postgres"])]

    try:
        ids = _get(f"{API}/topstories.json")[:scan]
    except Exception as e:
        return [item.stale_notice(
            "news", "News", item.PRIVATE, "Hacker News unreachable",
            f"{e.__class__.__name__}: {e}. Showing no headlines rather than none-found.",
        )], "offline"

    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        stories = [s for s in ex.map(_story, ids) if s and s.get("title")]

    seen = set(read_json(SEEN, []))
    scored = []
    for s in stories:
        title = s.get("title", "")
        url = s.get("url") or f"https://news.ycombinator.com/item?id={s['id']}"
        hay = f"{title} {url}".lower()
        hits = [w for w in interests if w in hay]
        pts = int(s.get("score") or 0)
        if not hits and pts < big:
            continue
        # Interest matches outrank raw popularity: a 90-point post about niri
        # matters more to you than a 900-point post about something else.
        score = min(100, (60 + 8 * len(hits) if hits else 30) + min(pts // 40, 25))
        lane = item.WORK if any(w in hay for w in work_terms) else item.PRIVATE
        scored.append((score, s, url, hits, pts, lane))

    scored.sort(key=lambda t: -t[0])
    fresh = [t for t in scored if str(t[1]["id"]) not in seen]
    chosen = (fresh or scored)[:keep]

    out = []
    for score, s, url, hits, pts, lane in chosen:
        why = ("matches " + ", ".join(hits[:3])) if hits else f"front-page at {pts} points"
        host = re.sub(r"^www\.", "", (re.search(r"https?://([^/]+)", url) or [None, ""])[1])
        out.append(item.make(
            source="news",
            lane=lane,
            section="News",
            key=str(s["id"]),
            who=f"HN · {pts} ▲",
            sub=f"{s.get('descendants', 0)} comments",
            title=s["title"],
            summary=f"{host} — {why}.",
            when=_age(s.get("time")),
            ts=s.get("time") or 0,
            accent="orange",
            score=score,
            goto={"kind": "url", "url": url},
            actions=["read", "star"],
        ))

    write_json(SEEN, sorted(seen | {str(t[1]["id"]) for t in chosen})[-500:])
    return out, f"{len(stories)} scanned, {len(out)} kept"


def _age(ts):
    if not ts:
        return ""
    d = time.time() - ts
    if d < 3600:
        return f"{int(d // 60)}m"
    if d < 86400:
        return f"{int(d // 3600)}h"
    return f"{int(d // 86400)}d"
