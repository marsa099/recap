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
import shutil
import subprocess

from .config import get
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


def _render_prompt(path, name, tool, pkg, title, count, scope="row"):
    """Fill in prompts/fix-vulnerabilities.md for this repo."""
    here = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    tpl_path = os.path.join(here, "prompts", "fix-vulnerabilities.md")
    with open(tpl_path) as f:
        tpl = f.read()
    if tool == "pnpm":
        audit_cmd, fix_cmd = "pnpm audit", "pnpm audit --fix=update"
        note = ("Note: on pnpm this edits `package.json` and installs — it is not "
                "lockfile-only the way npm's is.")
    else:
        audit_cmd, fix_cmd = "npm audit", "npm audit fix --package-lock-only"
        note = ("`--package-lock-only` keeps `node_modules` untouched, so the change "
                "is a readable lockfile diff.")
    if scope == "repo":
        scope_line = "every advisory in this repository"
        goal = ("Clear as many of this repo's advisories as you safely can — not just "
                "the selected row. Work through them by severity, highest first, and "
                "group anything that shares a required bump so you ask once rather "
                "than five times.")
    else:
        scope_line = f"the advisory on **{pkg}** (fix anything else that falls out for free)"
        goal = ("Clear the selected row with the smallest change that does it. If other "
                "advisories are resolved by the same bump, good — but do not go hunting "
                "the rest of the repo; the user has `fr` for that.")
    for k, v in {
        "{{SCOPE}}": scope_line, "{{GOAL}}": goal,
        "{{REPO}}": path, "{{REPO_NAME}}": name, "{{TOOL}}": tool,
        "{{PACKAGE}}": pkg or "(unspecified)", "{{ADVISORY}}": title or "(none recorded)",
        "{{COUNT}}": str(count), "{{AUDIT_CMD}}": audit_cmd,
        "{{FIX_CMD}}": fix_cmd, "{{TOOL_NOTE}}": note,
    }.items():
        tpl = tpl.replace(k, v)
    return tpl


def fix_in_terminal(it, dry_run=False, scope="row"):
    """Hand the job to a coding agent in a kitty window.

    A shell script can only offer a fixed menu, and the interesting cases are
    exactly the ones a menu handles badly: an advisory that needs a framework
    major, a bump that breaks the build, a repo where the right answer is "drop
    this dependency". So recap renders `prompts/fix-vulnerabilities.md` with
    this row's context and starts an agent on it. The prompt is what encodes
    the policy — ask before anything breaking, verify afterwards, never commit
    unasked — so it is editable without touching any code.
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

    agent = get("security.fix_agent", "claude")
    if not shutil.which(agent):
        return False, f"{agent} not on PATH — set security.fix_agent in config.toml"

    cached = (read_json(security.CACHE_FILE, {}).get(name) or {})
    count = len(cached.get("findings") or [])
    prompt = _render_prompt(path, name, tool, it.get("sub") or "",
                            it.get("title", "")[:200],
                            f"{count} ({it.get('sev') or 'unknown'} on this row)",
                            scope=scope)
    if dry_run:
        return True, f"[dry] {agent} in {name}, scope={scope} ({len(prompt)} chars)"

    term = os.environ.get("TERMINAL") or "kitty"
    argv = ([term, "--working-directory", path, agent, prompt]
            if os.path.basename(term) == "kitty" else [term, "-e", agent, prompt])
    subprocess.Popen(argv, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True, (f"{agent} is on all of {name}" if scope == "repo"
                  else f"{agent} is on {name}")


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
