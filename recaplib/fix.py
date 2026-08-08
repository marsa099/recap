"""`recap fix <id>` — apply the dependency bump a security row is asking for.

Scope is deliberately narrow, because this edits your repos:

* **Lockfile only.** npm runs with `--package-lock-only`, so `node_modules` is
  untouched and the change is a lockfile diff you can read.
* **Never `--force`.** `npm audit fix --force` takes major-version bumps and
  breaks builds. Advisories that need one are reported as needing a manual
  decision rather than silently taken.
* **Never commits.** The bump lands in your working tree; committing it is your
  call, and blindly committing across 20 repos is not something a keypress
  should do.
* **Refuses on a dirty manifest.** If `package.json` or the lockfile already has
  uncommitted changes, we stop — otherwise a fix gets tangled with dependency
  work you were in the middle of.

After a successful fix the repo is re-audited immediately, so the row either
disappears (fixed) or updates to what is left.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess

from .providers import security
from .snapshot import CACHE, read_json, write_json


def _repo_of(it):
    """(path, name) for a security row, or (None, reason)."""
    name = it.get("who") or ""
    cache = read_json(security.CACHE_FILE, {})
    entry = cache.get(name) or {}
    path = entry.get("path")
    if not path:
        # Older cache entries predate `path`; fall back to the layout.
        for base in (security.SIS, security.REPOS):
            cand = os.path.join(base, name)
            if os.path.isdir(cand):
                path = cand
                break
    if not path or not os.path.isdir(path):
        return None, f"can't locate a repo for '{name}'"
    return path, name


# Files a fix can legitimately touch. pnpm 11 moved settings out of
# package.json into pnpm-workspace.yaml (and writes minimumReleaseAgeExclude
# there when it bumps), so leaving it out under-reported what changed.
MANIFESTS = ["package.json", "package-lock.json", "pnpm-lock.yaml",
             "pnpm-workspace.yaml"]


def _dirty_manifest(path):
    """Names of manifest/lock files with uncommitted changes."""
    try:
        r = subprocess.run(
            ["git", "-C", path, "status", "--porcelain", "--"] + MANIFESTS,
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return []
    return [ln[3:].strip() for ln in (r.stdout or "").splitlines() if ln.strip()]


def fix_in_terminal(it, dry_run=False):
    """Run the fix in a kitty window instead of headlessly.

    The headless path can only report a one-line verdict, and the interesting
    case — "nothing changed, these need a major bump" — is exactly the one
    where you want npm's actual output, the advisory list, and a shell already
    sitting in the right directory to do something about it.

    Still never commits, and still shows you the resulting diff.
    """
    if it.get("source", "").split(":")[0] != "security":
        return False, "fix only applies to security rows"
    if (it.get("who") or "").startswith("+"):
        return False, "that is the collapsed summary row — open a specific advisory"

    path, name = _repo_of(it)
    if path is None:
        return False, name
    lock, tool = security._lockfile(path)
    if not lock:
        return False, f"{name}: no npm/pnpm lockfile"

    # pnpm 11 requires a method: bare `--fix` errors with
    # ERR_PNPM_INVALID_FIX_OPTION. "update" is the analogue of npm's audit fix
    # (bump to a non-vulnerable version); "override" pins transitive deps via a
    # package.json overrides block and is the heavier escalation.
    cmd = ("pnpm audit --fix=update" if tool == "pnpm"
           else "npm audit fix --package-lock-only")
    pkg = it.get("sub") or ""
    dirty = _dirty_manifest(path)
    warn = (f'echo "!! uncommitted {", ".join(dirty)} — the fix will mix with it"; echo;'
            if dirty else "")

    scope = ("updates package.json + lockfile and installs"
             if tool == "pnpm" else "lockfile only, no install")
    escalate = ("pnpm audit --fix=override   # pins transitive deps"
                if tool == "pnpm" else
                "npm audit fix --force        # takes major bumps, can break the build")
    audit = "pnpm audit" if tool == "pnpm" else "npm audit"
    script = (
        f'cd {shlex.quote(path)} || exit 1; '
        f'echo "recap fix · {name}  ({pkg})"; '
        f'echo advisory: {shlex.quote(it.get("title", "")[:120])}; '
        f'echo "scope:    {scope} · nothing is committed"; echo; '
        f'{warn}'
        f'echo "$ {cmd}"; {cmd}; echo; '
        f'echo "--- manifest changes ---"; '
        f'git status --short -- {" ".join(MANIFESTS)} || echo "(none)"; echo; '
        f'echo "--- advisories left ---"; '
        f'{audit} 2>&1 | grep -E "vulnerabilit|Severity" | tail -3; echo; '
        f'echo "still vulnerable? next step:"; echo "  {escalate}"; echo; '
        f'echo "[enter] to close"; read _'
    )
    term = os.environ.get("TERMINAL") or "kitty"
    argv = ([term, "--working-directory", path, "bash", "-lc", script]
            if os.path.basename(term) == "kitty" else [term, "-e", "bash", "-lc", script])
    if dry_run:
        return True, f"[dry] {term}: {cmd} in {name}"
    subprocess.Popen(argv, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True, f"fixing {name} in a terminal"


def fix_item(it, dry_run=False):
    """Returns (ok, message)."""
    if it.get("source", "").split(":")[0] != "security":
        return False, "fix only applies to security rows"
    if (it.get("who") or "").startswith("+"):
        return False, "that is the collapsed summary row — open a specific advisory"

    path, name = _repo_of(it)
    if path is None:
        return False, name

    lock, tool = security._lockfile(path)
    if not lock:
        return False, f"{name}: no npm/pnpm lockfile"

    dirty = _dirty_manifest(path)
    if dirty:
        return False, f"{name}: uncommitted {', '.join(dirty)} — commit or stash first"

    cmd = (["pnpm", "audit", "--fix=update"] if tool == "pnpm"
           else ["npm", "audit", "fix", "--package-lock-only"])
    if dry_run:
        return True, f"[dry] {name}: {' '.join(cmd)}"

    before = len(security._audit(path, tool, 150) or [])
    try:
        r = subprocess.run(cmd, cwd=path, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return False, f"{name}: {cmd[0]} timed out"
    except FileNotFoundError:
        return False, f"{name}: {cmd[0]} not on PATH"

    after_findings = security._audit(path, tool, 150)
    after = len(after_findings or [])

    changed = _dirty_manifest(path)
    if not changed:
        tail = (r.stdout or r.stderr or "").strip().splitlines()[-1:] or [""]
        return False, (f"{name}: nothing changed — {before} advisories remain. "
                       f"They likely need a major bump ({tail[0][:80]})")

    # Re-audit landed: refresh this repo's cache entry so the snapshot updates.
    cache = read_json(security.CACHE_FILE, {})
    if name in cache and after_findings is not None:
        cache[name]["findings"] = after_findings
        cache[name]["mtime"] = os.path.getmtime(lock)
        cache[name]["at"] = 0          # force a real re-audit on the next sweep
        write_json(security.CACHE_FILE, cache)

    fixed = max(0, before - after)
    note = f"{name}: fixed {fixed} of {before} — {', '.join(changed)} changed, uncommitted"
    if after:
        note += f" · {after} left, likely needing a major bump"
    return True, note
