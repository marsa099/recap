"""Vulnerabilities across work (~/repos/sis) and private (~/repos/*) code.

Runs `npm audit` / `pnpm audit` against lockfiles. Slow (tens of seconds per
repo), so results are cached in vulns.json and only recomputed when a lockfile's
mtime moves or the cache ages past `security.max_age_hours`. That's what makes
it safe to hang off the refresh timer.

Noise control matters more here than anywhere else: a security section that
cries wolf gets ignored inside a week. Low-severity and dev-only findings are
collapsed into one row instead of getting their own, and findings you cannot
act on — no fix published, or a `fixAvailable` that points at an older version
than the one installed — rank below the ones you can. Demoted, never dropped:
they stay in the collapsed tail, because "unfixable" is itself worth knowing.
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


def _lock_versions(path):
    """package name -> installed version, from package-lock.json.

    Read from the lockfile, not node_modules: the audit runs with
    --package-lock-only, so node_modules need not exist at all.
    """
    try:
        with open(os.path.join(path, "package-lock.json")) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    out = {}
    for p, meta in (data.get("packages") or {}).items():
        if not p.startswith("node_modules/") or "/node_modules/" in p:
            continue                      # top-level copies only
        v = meta.get("version") if isinstance(meta, dict) else None
        if v:
            out[p.split("node_modules/", 1)[1]] = v
    return out


def _older(a, b):
    """True if version a is strictly older than b. Best effort, never raises."""
    def parts(v):
        try:
            return [int(x) for x in str(v).split("+")[0].split("-")[0].split(".")]
        except (TypeError, ValueError):
            return None
    pa, pb = parts(a), parts(b)
    if pa is None or pb is None:
        return False
    return pa < pb


def _actionable(fix, versions):
    """Can this advisory be resolved by moving *forward*?

    npm answers "what fixes this" with `fixAvailable`. When the version it names
    is older than what is installed, that "fix" is a downgrade — a regression in
    a remedy's clothing (expo 56 -> 53, react-native 0.85 -> 0.72). Those, and
    advisories with no fix at all, are not things you can act on, and they should
    not outrank one you could clear this afternoon.

    Anything unrecognised counts as actionable: demoting on a guess is exactly
    how a real advisory goes unread.

    npm is not consistent here — the same repo can report `fixAvailable: true`
    on a warm run and a downgrade target on a cold one, and `true` does not
    guarantee `npm audit fix` changes anything. That only ever costs an extra
    visible row, never a hidden one, which is the direction to err in.
    """
    if fix is None:                       # older cache, or pnpm — unknown
        return True
    if isinstance(fix, bool):
        return fix
    if isinstance(fix, dict):
        cur, tgt = versions.get(fix.get("name")), fix.get("version")
        if not cur or not tgt:
            return True
        return not _older(tgt, cur)
    return True


def _ghsa(url, fallback=""):
    """The advisory id from its URL — the only stable identity an advisory has.

    Package name, severity and advisory *count* all churn for reasons that have
    nothing to do with which bug is being reported, so none of them can carry a
    dismissal. A GHSA id can.
    """
    tail = (url or "").rstrip("/").rsplit("/", 1)[-1]
    if tail.startswith(("GHSA-", "CVE-")):
        return tail
    return fallback or url or ""


def _fields(f):
    """(severity, package, title, url, [ghsa, ...], actionable) from a finding.

    Findings cached by an older recap are 4- or 5-tuples; pad them rather than
    forcing every repo to be re-audited on upgrade. A package flagged only
    because a *dependency* is vulnerable has no id of its own, so it falls back
    to its own name — still stable, unlike a count.
    """
    f = list(f) + [None] * (6 - len(f))
    sev, pkg, title, url, ids, act = f[:6]
    if isinstance(ids, str):
        ids = [ids]
    ids = [i for i in (ids or []) if i]
    return (sev, pkg, title, url or "", ids or [_ghsa(url or "", pkg)],
            True if act is None else bool(act))


def _audit(path, tool, timeout):
    """Return [(severity, package, title, url, ghsa)] or None if the audit failed."""
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
    versions = _lock_versions(path) if tool == "npm" else {}
    # npm 7+ shape
    for name, v in (data.get("vulnerabilities") or {}).items():
        if not isinstance(v, dict):
            continue
        sev = v.get("severity", "info")
        via = v.get("via") or []
        dicts = [x for x in via if isinstance(x, dict)]
        first = dicts[0] if dicts else {}
        url = first.get("url") or ""
        # Every advisory on this package, not just the first — two bugs in one
        # package must not collapse to one identity.
        ids = [i for i in (_ghsa(x.get("url") or "", "") for x in dicts) if i]
        found.append((sev, name, first.get("title") or f"advisory in {name}",
                      url, ids or [name],
                      _actionable(v.get("fixAvailable"), versions)))
    # pnpm / npm 6 shape — no fixAvailable, so actionability is unknown (None)
    for _, a in (data.get("advisories") or {}).items():
        url = a.get("url", "")
        mod = a.get("module_name", "?")
        found.append((a.get("severity", "info"), mod, a.get("title", ""), url,
                      [_ghsa(url, mod)], None))
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
    # Everything at or above this severity gets its own row; the rest is
    # counted into one line. "moderate" reproduces the long-standing default.
    min_sev = str(get("security.min_severity", "moderate")).lower()
    if min_sev not in RANK:          # an unreadable value must not mislabel itself
        min_sev = "moderate"
    floor = RANK[min_sev]

    rows, low_count, ignored = [], 0, 0
    for name, r in results.items():
        if name in ignore:
            ignored += 1
            continue
        by_pkg = {}
        for sev, pkg, title, url, ids, act in (_fields(f) for f in r["findings"]):
            if RANK.get(sev, 4) > floor:
                low_count += 1
                continue
            e = by_pkg.setdefault(pkg, {"sev": sev, "titles": [], "url": url,
                                        "ids": set(), "act": False})
            if RANK.get(sev, 4) < RANK.get(e["sev"], 4):
                e["sev"] = sev
            e["titles"].append(title)
            e["url"] = e["url"] or url
            e["ids"].update(ids)
            # One fixable advisory is enough to make the row worth acting on.
            e["act"] = e["act"] or act
        for pkg, e in by_pkg.items():
            rows.append((RANK.get(e["sev"], 4), name, pkg, e, r))

    # 1. can you act on it  2. severity  3. last commit, newest first  4. stable
    #
    # Actionability outranks severity deliberately. A high you can clear in a
    # minute deserves the slot more than a high whose only "fix" is a downgrade
    # you will never apply — those are demoted, not dropped, so they still show
    # up in the "+ more" line rather than vanishing.
    rows.sort(key=lambda t: (not t[3]["act"], t[0],
                             -(t[4].get("last_commit") or 0), t[1], t[2]))
    unactionable = sum(1 for t in rows if not t[3]["act"])
    shown, hidden = rows[:max_rows], rows[max_rows:]

    out = []
    for _, name, pkg, e, r in shown:
        n = len(e["titles"])
        title = e["titles"][0] if n == 1 else f"{n} advisories in {pkg}"
        out.append(item.make(
            source="security",
            lane=r["lane"],
            section="Security",
            # Identity is the set of advisories, not how many there are. Keying
            # on the count let a *replacement* advisory (one fixed, one new,
            # count unchanged) silently inherit an earlier dismissal.
            key=f"{name}:{pkg}:" + (",".join(sorted(e["ids"]))
                                    or f"{e['sev']}:{n}"),
            who=name,
            sub=pkg,
            title=title,
            summary=("; ".join(t for t in e["titles"][:3]) if n > 1 else "")
                    + (" · stale, last good scan" if r.get("stale") else ""),
            when=e["sev"].capitalize() + ("" if e["act"] else " · no fix"),
            ts=r.get("last_commit") or 0,
            accent="red" if e["sev"] in ("critical", "high") else "yellow",
            sev=e["sev"],
            score=100 - RANK.get(e["sev"], 4) * 15,
            priority=e["sev"] == "critical",
            goto={"kind": "url", "url": e["url"] or
                  f"https://github.com/advisories?query={pkg}"},
            # No `fix` offered when the only bump on record goes backwards —
            # the action would either no-op or propose a downgrade.
            actions=["read", "trash", "star"] + (["fix"] if e["act"] else []),
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
        meta += f" · {low_count} below {min_sev} suppressed"
    if unactionable:
        meta += f" · {unactionable} unactionable"
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
        return True, "advisory dismissed until a different one is reported"
    return True, action
