"""The one shape every provider emits and the UI consumes.

Providers know about Slack/IMAP/OSV; nothing downstream of this module does.
Keep it a plain dict on the wire — the snapshot is JSON the QML reads directly,
so a dataclass here would only be ceremony around `asdict`.
"""
from __future__ import annotations

import hashlib

# Lanes. Every item must pick one — an "unknown" lane would defeat the whole
# point of the work/private split, which is that you can trust it.
WORK = "work"
PRIVATE = "private"

# Section order in the UI. Providers name a section; this fixes the order so
# two providers feeding the same section can't fight over it.
SECTION_ORDER = ["Mail", "Chat", "Security", "News"]


def make(
    *,
    source,
    lane,
    section,
    title,
    key,
    who="",
    sub="",
    summary="",
    when="",
    ts=0,
    accent="blue",
    score=50,
    goto=None,
    actions=(),
    sev="",
    stale=False,
    priority=False,
):
    """Build one item.

    `key` is the provider-local identity (a message id, a channel name, a
    GHSA id + repo). It is hashed with the source into a stable `id` so undo
    and dismissal survive a refresh that reorders everything.
    """
    ident = hashlib.sha1(f"{source}:{key}".encode()).hexdigest()[:16]
    return {
        "id": ident,
        "source": source,
        "lane": lane,
        "section": section,
        "who": who,
        "sub": sub,
        "title": title,
        "summary": summary,
        "when": when,
        "ts": int(ts or 0),
        "accent": accent,
        "score": int(score),
        "goto": goto or {"kind": "nothing"},
        "actions": list(actions),
        "sev": sev,
        "stale": bool(stale),
        "priority": bool(priority),
        "state": {"read": False, "starred": False, "gone": False},
    }


def stale_notice(source, section, lane, title, summary, when="stale"):
    """A provider that failed still has to say so.

    Silently reporting zero is the failure mode that makes people stop
    trusting a digest — an absent section looks identical to a quiet one.
    """
    return make(
        source=source,
        lane=lane,
        section=section,
        key=f"__stale__:{source}",
        who=source,
        sub="provider down",
        title=title,
        summary=summary,
        when=when,
        accent="yellow",
        score=100,
        stale=True,
    )


def sort_key(item):
    """Within a section: priority first, then score, then newest."""
    return (not item["priority"], -item["score"], -item["ts"])
