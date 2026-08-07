"""Unread mail, read straight out of mlqs's SQLite cache.

Deliberately does NOT talk to the mlqs daemon to collect. The cache
(~/.local/share/mlqs/cache.db) opens read-only with ?mode=ro even while mlqs
is down, so the digest survives a dead daemon and degrades to "stale" rather
than "empty". The daemon is only needed to *apply* actions (see act()).
"""
from __future__ import annotations

import json
import os
import sqlite3
import time

from .. import item

DB = os.path.expanduser("~/.local/share/mlqs/cache.db")
ACCOUNTS = os.path.expanduser("~/.config/mlqs/accounts.json")


def _lane_map():
    """Which accounts are work. Everything unlisted is private.

    Kept in recap's own config rather than mlqs's, because mlqs has no notion
    of a lane and shouldn't grow one just for us.
    """
    from ..config import get

    work = set(get("mail.work_accounts", []))
    return work


def _fmt_when(ts):
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return ""
    now = time.time()
    d = now - ts
    if d < 3600:
        return f"{int(d // 60)}m"
    if d < 86400:
        return f"{int(d // 3600)}h"
    if d < 86400 * 6:
        return time.strftime("%a %H:%M", time.localtime(ts))
    return time.strftime("%b %-d", time.localtime(ts))


def _senders(raw):
    try:
        s = json.loads(raw or "[]")
        if s:
            return s[0].get("name") or s[0].get("email") or ""
    except (ValueError, AttributeError, IndexError):
        pass
    return ""


def collect():
    if not os.path.exists(DB):
        return [item.stale_notice(
            "mail", "Mail", item.PRIVATE,
            "No mlqs cache found",
            f"Expected {DB}. Install/run mlqs at least once so it builds its cache.",
        )]

    work = _lane_map()
    try:
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=3)
        rows = con.execute(
            "SELECT account, id, subject, snippet, senders_json, date "
            "FROM conversations WHERE unread = 1 ORDER BY date DESC LIMIT 40"
        ).fetchall()
        total = con.execute("SELECT count(*) FROM conversations").fetchone()[0]
        con.close()
    except sqlite3.Error as e:
        return [item.stale_notice(
            "mail", "Mail", item.PRIVATE,
            "mlqs cache unreadable",
            f"sqlite: {e}. The digest is showing no mail rather than claiming zero unread.",
        )]

    out = []
    for account, cid, subject, snippet, senders, date in rows:
        sender = _senders(senders)
        lane = item.WORK if account in work else item.PRIVATE
        summary = (snippet or "").strip().replace("\n", " ")
        if summary == (subject or "").strip():
            summary = ""
        out.append(item.make(
            source="mail",
            lane=lane,
            section="Mail",
            key=f"{account}:{cid}",
            who=account,
            sub=sender,
            title=(subject or "(no subject)").strip(),
            summary=summary[:400],
            when=_fmt_when(date),
            ts=date or 0,
            accent="blue" if lane == item.WORK else "green",
            score=60,
            goto={"kind": "app", "cmd": ["mlqs-open", account, str(cid)]},
            actions=["read", "archive", "trash", "star"],
        ))

    meta = f"{total} conversations cached"
    if not out:
        meta += " · nothing unread"
    return out, meta


def act(it, action):
    """Apply an action through the mlqs daemon socket.

    Collect works without the daemon; mutating does not. If the socket is
    down we say so rather than silently dropping the action — the UI's
    optimistic update is rolled back by the caller on failure.
    """
    import socket

    sock = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "mlqs.sock")
    verb = {"read": "markread", "archive": "archive", "trash": "trash",
            "star": "star", "unarchive": "unarchive", "untrash": "untrash"}.get(action)
    if not verb:
        return False, f"mail: no such action {action}"
    account, _, cid = it["id"], None, None
    # The provider key is account:conv_id; recover it from the goto command,
    # which carries both without needing to re-hash the id.
    cmd = (it.get("goto") or {}).get("cmd") or []
    if len(cmd) == 3:
        account, cid = cmd[1], cmd[2]
    else:
        return False, "mail: item is missing its account/conversation reference"
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect(sock)
        s.sendall(json.dumps({"type": verb, "account": account, "id": cid}).encode() + b"\n")
        s.close()
        return True, f"mail: {verb}"
    except OSError as e:
        return False, f"mail: mlqs daemon unreachable ({e})"
