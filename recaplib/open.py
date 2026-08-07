"""`recap open <id>` — take me to the thing this row is about.

Every row's `goto` is one of:
  url      hand to $BROWSER (the helium router)
  app      run `recap open <id>`, which lands here and does the source-specific
           thing — raise the owning client, focused on the right conversation
           where the client's protocol allows it

Deliberately honest about what it can't do. Raising mlqs without landing on the
exact thread is reported as such, not silently passed off as a deep-link.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time

HOME = os.path.expanduser("~")
NIRI_JUMP = f"{HOME}/.config/niri/scripts/niri-jump-or-exec"

# source -> (niri window-title matcher, launch script)
CHAT_WINDOWS = {
    "dsqrd": ("title:^dsqrd$", f"{HOME}/.config/niri/scripts/launch-discord-client"),
    "tmqs": ("title:teams-client", f"{HOME}/.config/niri/scripts/launch-teams-client"),
    "slqs": ("title:^slqs$", f"{HOME}/.config/niri/scripts/launch-slack-client"),
    "msqs": ("title:messenger-client", f"{HOME}/.config/niri/scripts/launch-messenger-client"),
}


def _sock_send(name, payloads, timeout=4):
    path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), name)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    try:
        for p in payloads:
            s.sendall(json.dumps(p).encode() + b"\n")
    finally:
        s.close()


def _summon_and_count(timeout=4):
    """Send summonui and return how many OTHER clients the daemon has.

    mlqs acks summonui with {"type":"summonack","clients":N} precisely so a
    caller can tell a live UI from a zombie. Zero means nothing is listening,
    so a broadcast would be lost.
    """
    path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "mlqs.sock")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    try:
        s.sendall(json.dumps({"type": "summonui"}).encode() + b"\n")
        f = s.makefile("r")
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = f.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("type") == "summonack":
                return int(msg.get("clients") or 0)
    finally:
        s.close()
    return 0


def _wait_for_client(timeout=12, poll=0.4):
    """Block until an mlqs UI has attached to the daemon."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll)
        try:
            if _summon_and_count(timeout=2) > 0:
                # It is connected, but QML bindings settle a beat later; the
                # openconv handler needs the conversation model in place.
                time.sleep(0.6)
                return True
        except OSError:
            continue
    return False


def _niri_window_matches(title_re):
    """True when a window whose title matches `title_re` is already open.

    The chat daemons have no equivalent of mlqs's summonack, so the window
    list is how we tell "UI is up, navigate now" from "launch it first".
    """
    try:
        out = subprocess.run(["niri", "msg", "--json", "windows"],
                             capture_output=True, text=True, timeout=4).stdout
        wins = json.loads(out or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    pat = re.compile(title_re)
    return any(pat.search(w.get("title") or "") for w in wins)


def _wait_for_window(title_re, timeout=15, poll=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll)
        if _niri_window_matches(title_re):
            time.sleep(0.8)   # let the QML model settle before navigating
            return True
    return False


def _spawn(cmd):
    subprocess.Popen(cmd, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def open_item(it, dry_run=False):
    """Returns (ok, message). The UI shows the message verbatim."""
    g = it.get("goto") or {}
    kind = g.get("kind")

    if kind == "url":
        url = g.get("url")
        if not url:
            return False, "no url on this row"
        if dry_run:
            return True, "[dry] browser " + url[:60]
        _spawn([f"{HOME}/.scripts/helium-router", url])
        return True, "opening " + url.replace("https://", "")[:60]

    if kind != "app":
        return False, "nothing to open for this row"

    source = it.get("source", "").split(":")[0]

    if source == "mail":
        cmd = g.get("cmd") or []
        account = cmd[1] if len(cmd) > 2 else ""
        conv = cmd[2] if len(cmd) > 2 else ""
        if dry_run:
            return True, f"[dry] openconv mlqs {account}/{conv[:12]} (+launch if no UI)"
        # `openconv` is a broadcast — it only reaches a UI that is *already*
        # connected. Sending it before launching would drop it on the floor,
        # so ask the daemon how many other clients it has (summonui's ack
        # carries the count), and if there are none, launch first and wait for
        # the UI to attach before deep-linking.
        payload = {"type": "openconv", "account": account, "id": conv}
        try:
            clients = _summon_and_count()
        except OSError:
            return False, "mlqs daemon is not running"
        if clients > 0:
            _sock_send("mlqs.sock", [payload])
            _spawn([NIRI_JUMP, "title:^mlqs$", "mlqs-client"])
            return True, f"opening mlqs → {account}"
        _spawn([NIRI_JUMP, "title:^mlqs$", "mlqs-client"])
        if _wait_for_client(timeout=12):
            _sock_send("mlqs.sock", [payload])
            return True, f"starting mlqs → {account}"
        return True, f"started mlqs ({account}) — UI took too long, landed in the inbox"

    if source in CHAT_WINDOWS:
        matcher, launcher = CHAT_WINDOWS[source]
        if not os.path.exists(launcher):
            return False, f"{os.path.basename(launcher)} missing"
        cmd = g.get("cmd") or ["", ""]
        chan = cmd[1] if len(cmd) > 1 else ""
        chan_id = cmd[2] if len(cmd) > 2 else ""
        if dry_run:
            return True, f"[dry] open {source}/{chan or chan_id} + jump ({matcher})"
        # `open` navigates the running UI to the channel — the same broadcast a
        # clicked notification produces. Added to dsqrd/slqs/tmqs by us; a
        # daemon that predates it ignores the unknown verb, so this degrades to
        # "raise the window" rather than failing.
        #
        # Being a broadcast, it only reaches a UI that is already attached, so
        # the order matters: navigate first if the window is up, otherwise
        # launch and wait for it before navigating.
        title_re = matcher.split(":", 1)[1] if ":" in matcher else matcher
        already = _niri_window_matches(title_re)
        if not chan_id:
            _spawn([NIRI_JUMP, matcher, launcher])
            return True, f"opening {source}"
        if already:
            try:
                _sock_send(f"{source}.sock", [{"type": "open", "channel": chan_id}])
            except OSError:
                return False, f"{source} daemon unreachable"
            _spawn([NIRI_JUMP, matcher, launcher])
            return True, f"opening {source} → {chan}"
        _spawn([NIRI_JUMP, matcher, launcher])
        if _wait_for_window(title_re, timeout=15):
            try:
                _sock_send(f"{source}.sock", [{"type": "open", "channel": chan_id}])
                return True, f"starting {source} → {chan}"
            except OSError:
                pass
        return True, f"started {source} — select {chan} yourself"

    return False, f"don't know how to open a {source} row"
