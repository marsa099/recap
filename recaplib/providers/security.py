"""Vulnerabilities across work (~/repos/sis) and private (~/repos/*) code.

Runs `npm audit` / `pnpm audit` against lockfiles. Slow (tens of seconds per
repo), so results are cached in vulns.json and only recomputed when a lockfile's
mtime moves or the cache ages past `security.max_age_hours`. That's what makes
it safe to hang off the refresh timer.

Noise control matters more here than anywhere else: a security section that
cries wolf gets ignored inside a week. Low-severity and dev-only findings are
collapsed into one row instead of getting their own.
"""
from __future__ import annotations

import json
import os
import subprocess
import time

from .. import item
from ..config import get
from ..snapshot import CACHE, read_json, write_json

REPOS = os.path.expanduser("~/repos")
SIS = os.path.join(REPOS, "sis")
CACHE_FILE = os.path.join(CACHE, "vulns.json")

RANK = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "info": 4}


def _last_commit(path):
    """Unix ts of the repo's most recent commit, 0 if unknown.

    Used as the secondary sort: among equally severe findings, the repo you
    touched yesterday matters more than one you last built in 2023.
    """
    try:
        r = subprocess.run(["git", "-C", path, "log", "-1", "--format=%ct"],
                           capture_output=True, text=True, timeout=8)
        return int((r.stdout or "0").strip() or 0)
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


def _lockfile(path):
    for name in ("pnpm-lock.yaml", "package-lock.json"):
        p = os.path.join(path, name)
        if os.path.exists(p):
            return p, ("pnpm" if name.startswith("pnpm") else "npm")
    return None, None


def _audit(path, tool, timeout):
    """Return [(severity, package, title, url)] or None if the audit failed."""
    cmd = (["pnpm", "audit", "--json"] if tool == "pnpm"
           else ["npm", "audit", "--package-lock-only", "--json"])
    try:
        r = subprocess.run(cmd, cwd=path, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    try:
        data = json.loads(r.stdout or "{}")
    except ValueError:
        return None

    found = []
    # npm 7+ shape
    for name, v in (data.get("vulnerabilities") or {}).items():
        if not isinstance(v, dict):
            continue
        sev = v.get("severity", "info")
        via = v.get("via") or []
        first = next((x for x in via if isinstance(x, dict)), {})
        found.append((sev, name, first.get("title") or f"advisory in {name}",
                      first.get("url") or ""))
    # pnpm / npm 6 shape
    for _, a in (data.get("advisories") or {}).items():
        found.append((a.get("severity", "info"), a.get("module_name", "?"),
                      a.get("title", ""), a.get("url", "")))
    return found


def _repos():
    """(path, name, lane) for every JS repo worth auditing."""
    out = []
    if os.path.isdir(SIS):
        for n in sorted(os.listdir(SIS)):
            p = os.path.join(SIS, n)
            if os.path.isdir(p) and _lockfile(p)[0]:
                out.append((p, n, item.WORK))
    if os.path.isdir(REPOS):
        for n in sorted(os.listdir(REPOS)):
            p = os.path.join(REPOS, n)
            if n == "sis" or not os.path.isdir(p):
                continue
            if _lockfile(p)[0]:
                out.append((p, n, item.PRIVATE))
    return out


def collect(force=False):
    max_age = float(get("security.max_age_hours", 12)) * 3600
    timeout = int(get("security.audit_timeout", 150))
    cache = read_json(CACHE_FILE, {})
    now = time.time()

    results = {}
    audited = 0
    for path, name, lane in _repos():
        lock, tool = _lockfile(path)
        mtime = os.path.getmtime(lock)
        prev = cache.get(name)
        if (not force and prev and prev.get("mtime") == mtime
                and now - prev.get("at", 0) < max_age):
            results[name] = prev
            continue
        found = _audit(path, tool, timeout)
        if found is None:
            # Keep the last good result rather than dropping the repo.
            if prev:
                prev["stale"] = True
                results[name] = prev
            continue
        results[name] = {"lane": lane, "mtime": mtime, "at": now, "path": path,
                         "findings": found, "stale": False}
        audited += 1

    # last_commit is a *current* fact, not an audit-time one — a repo you
    # committed to an hour ago should rise even if its advisories are cached.
    # One cheap git call per repo, so it runs on every sweep.
    for path, name, _ in _repos():
        if name in results:
            results[name]["path"] = path
            results[name]["last_commit"] = _last_commit(path)

    write_json(CACHE_FILE, results)

    # --- noise control -------------------------------------------------
    # A raw audit of ~/repos yields 160+ (repo, package) pairs. A section that
    # long is a section you scroll past, so: collapse per package, rank by
    # severity, show only the worst `max_rows`, and roll the tail into one
    # honest "N more" row. Never silently truncate.
    max_rows = int(get("security.max_rows", 10))
    ignore = set(get("security.ignore_repos", []))

    rows, low_count, ignored = [], 0, 0
    for name, r in results.items():
        if name in ignore:
            ignored += 1
            continue
        by_pkg = {}
        for sev, pkg, title, url in r["findings"]:
            if RANK.get(sev, 4) >= 3:
                low_count += 1
                continue
            e = by_pkg.setdefault(pkg, {"sev": sev, "titles": [], "url": url})
            if RANK.get(sev, 4) < RANK.get(e["sev"], 4):
                e["sev"] = sev
            e["titles"].append(title)
            e["url"] = e["url"] or url
        for pkg, e in by_pkg.items():
            rows.append((RANK.get(e["sev"], 4), name, pkg, e, r))

    # 1. severity  2. last commit, newest first  3. stable tiebreak
    rows.sort(key=lambda t: (t[0], -(t[4].get("last_commit") or 0), t[1], t[2]))
    shown, hidden = rows[:max_rows], rows[max_rows:]

    out = []
    for _, name, pkg, e, r in shown:
        n = len(e["titles"])
        title = e["titles"][0] if n == 1 else f"{n} advisories in {pkg}"
        out.append(item.make(
            source="security",
            lane=r["lane"],
            section="Security",
            key=f"{name}:{pkg}:{e['sev']}:{n}",
            who=name,
            sub=pkg,
            title=title,
            summary=("; ".join(t for t in e["titles"][:3]) if n > 1 else "")
                    + (" · stale, last good scan" if r.get("stale") else ""),
            when=e["sev"].capitalize(),
            ts=r.get("last_commit") or 0,
            accent="red" if e["sev"] in ("critical", "high") else "yellow",
            sev=e["sev"],
            score=100 - RANK.get(e["sev"], 4) * 15,
            priority=e["sev"] == "critical",
            goto={"kind": "url", "url": e["url"] or
                  f"https://github.com/advisories?query={pkg}"},
            actions=["read", "trash", "star", "fix"],
        ))

    if hidden:
        repos = sorted({t[1] for t in hidden})
        worst = min(t[0] for t in hidden)
        sev_name = next(k for k, v in RANK.items() if v == worst)
        out.append(item.make(
            source="security",
            lane=item.PRIVATE,
            section="Security",
            key=f"__more__:{len(hidden)}",
            who="+ more",
            sub=f"{len(repos)} repos",
            title=f"{len(hidden)} further advisories, worst is {sev_name}",
            summary="Not shown individually to keep this section readable: "
                    + ", ".join(repos[:8])
                    + (f" and {len(repos) - 8} more" if len(repos) > 8 else "")
                    + ". Run `recap show` or raise security.max_rows to see them all.",
            when="collapsed",
            accent="yellow",
            score=1,
            goto={"kind": "nothing"},
            actions=["read"],
        ))

    meta = f"{len(results)} repos, {audited} rescanned"
    if low_count:
        meta += f" · {low_count} low suppressed"
    if ignored:
        meta += f" · {ignored} ignored"
    dotnet = sum(1 for _ in _dotnet_repos())
    if dotnet:
        meta += f" · {dotnet} .NET repos not covered"
    return out, meta


def _dotnet_repos():
    """.NET repos need `dotnet list package --vulnerable`, which isn't wired
    yet. Counted so the UI can say so rather than implying full coverage."""
    if not os.path.isdir(SIS):
        return
    for n in sorted(os.listdir(SIS)):
        p = os.path.join(SIS, n)
        if not os.path.isdir(p) or _lockfile(p)[0]:
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in (".git", "bin", "obj", "node_modules")]
            if any(f.endswith(".csproj") for f in files):
                yield n
                break


def act(it, action):
    if action == "trash":
        return True, "advisory dismissed until its version changes"
    return True, action
