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
import socket
import subprocess

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
        # `openconv` is what the mlqs UI acts on for a notification deep-link,
        # but the daemon only broadcasts it from its own notification callback
        # — there is no client command for it yet. Sending it is a no-op on
        # today's daemon and starts working the moment the fork gains one
        # (see README). Raising the window is what actually happens now.
        deep = False
        try:
            _sock_send("mlqs.sock", [
                {"type": "openconv", "account": account, "id": conv},
                {"type": "summonui"},
            ])
            deep = True
        except OSError:
            pass
        if dry_run:
            return True, f"[dry] jump mlqs + openconv {account}/{conv[:12]}"
        _spawn([NIRI_JUMP, "title:^mlqs$", "mlqs-client"])
        return True, (f"opening mlqs ({account}) — lands in the inbox, not the thread"
                      if deep else
                      f"opening mlqs ({account}) — daemon was down, inbox only")

    if source in CHAT_WINDOWS:
        matcher, launcher = CHAT_WINDOWS[source]
        if not os.path.exists(launcher):
            return False, f"{os.path.basename(launcher)} missing"
        chan = (g.get("cmd") or ["", ""])[1] if len(g.get("cmd") or []) > 1 else ""
        if dry_run:
            return True, f"[dry] jump {source} ({matcher}) for {chan}"
        _spawn([NIRI_JUMP, matcher, launcher])
        return True, f"opening {source}" + (f" — select {chan} yourself" if chan else "")

    return False, f"don't know how to open a {source} row"
