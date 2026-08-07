"""Unread chat across dsqrd / slqs / tmqs / msqs.

All four daemons speak the same protocol: newline-delimited JSON over a unix
socket in $XDG_RUNTIME_DIR. We only ever read the channel list, which every
daemon pushes on connect — no "recent"/"focus" command, because those clobber
the owning UI's active-channel and notification-suppression state.

A daemon that isn't running produces a stale row, not silence.
"""
from __future__ import annotations

import json
import os
import socket

from .. import item

CLIENTS = [
    # (source, socket name, display, lane, accent)
    ("dsqrd", "dsqrd.sock", "Discord", item.PRIVATE, "purple"),
    ("msqs", "msqs.sock", "Messenger", item.PRIVATE, "purple"),
    ("tmqs", "tmqs.sock", "Teams", item.WORK, "blue"),
    ("slqs", "slqs.sock", "Slack", item.WORK, "blue"),
]


def _channels(sock_name, timeout=4.0):
    """Read the first `channels` frame the daemon sends after connecting."""
    path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), sock_name)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    try:
        f = s.makefile("r")
        for _ in range(400):
            line = f.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("type") == "channels":
                return msg.get("channels") or []
    finally:
        s.close()
    return []


def collect():
    out = []
    up = 0
    for source, sock_name, display, lane, accent in CLIENTS:
        try:
            chans = _channels(sock_name)
        except OSError as e:
            out.append(item.stale_notice(
                source, "Chat", lane,
                f"{display} provider down",
                f"{sock_name} unreachable ({e.__class__.__name__}). "
                f"{display} is unrepresented in this digest — not silently reported as zero.",
                when="down",
            ))
            continue
        up += 1
        for c in chans:
            unread = int(c.get("unread") or 0)
            mention = bool(c.get("mention"))
            if not unread and not mention:
                continue
            name = c.get("name") or "(unnamed)"
            bits = [f"{unread} new"] if unread else []
            if mention:
                bits.append("mention")
            out.append(item.make(
                source=source,
                lane=lane,
                section="Chat",
                key=f"{c.get('id') or name}",
                who=source,
                sub=name,
                title=f"{name} — {', '.join(bits)}",
                summary="",
                when=", ".join(bits),
                ts=0,
                accent="orange" if mention else accent,
                score=90 if mention else 55 + min(unread, 30),
                priority=mention,
                goto={"kind": "app", "cmd": [f"{source}-open", name]},
                actions=["read"],
            ))
    return out, f"{up}/{len(CLIENTS)} daemons up"


def act(it, action):
    """Mark a channel read via the daemon's markread verb."""
    if action != "read":
        return False, f"chat: no such action {action}"
    source = it["source"]
    sock_name = {c[0]: c[1] for c in CLIENTS}.get(source)
    if not sock_name:
        return False, f"chat: unknown source {source}"
    path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), sock_name)
    cmd = (it.get("goto") or {}).get("cmd") or []
    channel = cmd[1] if len(cmd) > 1 else it.get("sub")
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect(path)
        s.sendall(json.dumps({"type": "markread", "channel": channel}).encode() + b"\n")
        s.close()
        return True, f"{source}: marked {channel} read"
    except OSError as e:
        return False, f"{source}: daemon unreachable ({e})"
