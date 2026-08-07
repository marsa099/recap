"""`recap watch` — keep the snapshot in step with the clients, live.

The problem this solves: you press ⏎ on a mail row, recap deep-links you into
mlqs, you read it — and recap still lists it as unread until the next timed
refresh.

**What we react to.** mlqs broadcasts `readmarked` only from its notification
callback, so listening for that alone would miss the ordinary case (opening a
conversation in the UI). But *every* read-state change goes through
`db.SetConvFlags`, which writes the SQLite cache. Watching the cache therefore
catches strictly more than the broadcast does — read, unread, archive, trash,
and new mail arriving — with no protocol dependency at all.

For chat there is no cache we own, so we hold each daemon's socket open and
re-derive when it pushes a fresh `channels` frame (which is what carries unread
counts). Both paths converge on the same thing: re-run only the cheap providers
and rewrite the snapshot, which the overlay's FileView picks up immediately.

Deliberately never re-runs `security` or `news` — a mail read must not trigger a
two-minute `npm audit` sweep.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time

from .providers import chat, mail

BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "recap")
DEBOUNCE = 1.2      # seconds of quiet before acting on a burst of writes
POLL = 1.0          # cache stat interval


def _log(msg):
    print(f"recap watch: {msg}", file=sys.stderr, flush=True)


class Debounced:
    """Collapse a burst of signals into one refresh.

    mlqs writes cache.db-wal several times per read; without this we would
    re-run the mail provider four or five times for one click.
    """

    def __init__(self, only, delay=DEBOUNCE):
        self.only = only
        self.delay = delay
        self._timer = None
        self._lock = threading.Lock()

    def poke(self):
        with self._lock:
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(self.delay, self._fire)
            self._timer.daemon = True
            self._timer.start()

    def _fire(self):
        try:
            subprocess.run([BIN, "refresh", "--quiet", "--only", self.only],
                           capture_output=True, timeout=90)
            _log(f"refreshed {self.only}")
        except Exception as e:
            _log(f"refresh {self.only} failed: {e}")


def watch_mail_cache(deb):
    """Poll the mlqs cache's mtime. Cheap enough to do every second, and it
    needs no inotify dependency."""
    paths = [mail.DB, mail.DB + "-wal"]
    last = {}
    while True:
        changed = False
        for p in paths:
            try:
                m = os.stat(p).st_mtime_ns
            except OSError:
                continue
            if p in last and m != last[p]:
                changed = True
            last[p] = m
        if changed:
            deb.poke()
        time.sleep(POLL)


def watch_chat_socket(source, sock_name, deb):
    """Hold a daemon's socket open and re-derive when it pushes channels.

    Read-only by construction: we send nothing, so the daemon's active-channel
    and notification-suppression state is never touched.
    """
    while True:
        try:
            path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), sock_name)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(None)
            s.connect(path)
            _log(f"attached to {source}")
            f = s.makefile("r")
            first = True
            for line in f:
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                # `channels` carries unread counts; `unread`/`open` mean the
                # user just engaged with something, so counts are about to move.
                if msg.get("type") in ("channels", "unread", "open"):
                    if first and msg.get("type") == "channels":
                        first = False          # the bootstrap frame is not news
                        continue
                    deb.poke()
        except OSError:
            pass
        time.sleep(5)   # daemon down or restarting — retry


def run():
    mail_deb = Debounced("mail")
    chat_deb = Debounced("chat")

    threads = [threading.Thread(target=watch_mail_cache, args=(mail_deb,), daemon=True)]
    for source, sock_name, _, _, _ in chat.CLIENTS:
        threads.append(threading.Thread(target=watch_chat_socket,
                                        args=(source, sock_name, chat_deb), daemon=True))
    for t in threads:
        t.start()
    _log(f"watching mlqs cache + {len(chat.CLIENTS)} chat sockets")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0
    return 0
