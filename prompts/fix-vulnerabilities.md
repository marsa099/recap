# Fix dependency vulnerabilities in {{REPO_NAME}}

You are being run by **recap** in `{{REPO}}` because its security digest has a
row for **{{PACKAGE}}** that the user wants cleared.

- advisory: {{ADVISORY}}
- package manager: **{{TOOL}}**
- advisories reported when recap last audited: **{{COUNT}}**

Your job is to clear as many advisories as you safely can, stop and ask before
anything that could break the project, and prove afterwards that it still works.

## Ground rules

1. **Stay in this repo.** Do not touch anything outside `{{REPO}}`.
2. **Only dependency manifests should change** — `package.json`, the lockfile,
   and (pnpm 11) `pnpm-workspace.yaml`. If a fix seems to need source changes,
   stop and say so rather than editing application code unasked.
3. **Never commit or push without asking.** When you have something worth
   keeping, propose a commit message and wait for a yes.
4. **Ask before anything breaking.** See "The line you must not cross alone".
5. If the user declines an escalation, stop there and report honestly what is
   left rather than trying to be clever about it.

## Step 1 — establish the baseline

Run the audit and record the starting count. Also check whether the working
tree was already dirty, so you never mix your change with work in progress:

```sh
{{AUDIT_CMD}}
git status --short -- package.json package-lock.json pnpm-lock.yaml pnpm-workspace.yaml
```

If the manifests already have uncommitted changes, say so and ask whether to
continue before touching anything.

## Step 2 — the safe pass

```sh
{{FIX_CMD}}
```

{{TOOL_NOTE}}

Re-audit. If that clears everything, skip to verification.

## Step 3 — what is actually left, and why

Do not just re-run the same command hoping for a different answer. Find out
what each remaining advisory needs. For npm, every entry carries the exact
package and version that resolves it:

```sh
npm audit --json | python3 -c 'import json,sys
d=json.load(sys.stdin)
for name,x in (d.get("vulnerabilities") or {}).items():
    fa=x.get("fixAvailable")
    kind="major bump: %s@%s"%(fa["name"],fa["version"]) if isinstance(fa,dict) else ("in range" if fa else "NO FIX")
    print("%-10s %-32s %s"%(x.get("severity"),name,kind))'
```

For pnpm, `pnpm audit` lists each advisory with its patched range, and
`pnpm audit --fix=override` will pin transitive dependencies — **but it only
writes the overrides; you must run `pnpm install` afterwards or nothing
actually changes and the count will look untouched.**

Group what remains into:

- **in-range** — bump it, no drama.
- **needs a major bump** — name the exact versions. This needs permission.
- **no fix available** — say so plainly; it is not your failure.

## The line you must not cross alone

**Stop and ask the user before:**

- any **major version** bump of any package,
- `npm audit fix --force` (it takes majors, that is its whole purpose),
- `pnpm audit --fix=override` when the override crosses a major,
- updating a **framework or toolchain** package — `next`, `react`,
  `react-native`, `expo`, `vite`, `typescript`, `tailwindcss` — even within a
  major, since these routinely need config migrations,
- anything that would edit source files.

When you ask, be concrete and short. Give: which packages and versions, how
many advisories it would clear, and the realistic breakage (e.g. "expo 52 → 53
is an SDK migration: config and native modules will likely need changes").
Then let the user decide. Do not proceed on silence.

## Step 4 — verify you did not break it

**This is not optional.** After any change, run whatever this project actually
has. Look in `package.json` `scripts` and run the ones that exist, in this
order, stopping at the first failure:

```sh
{{TOOL}} run typecheck     # or tsc --noEmit, if present
{{TOOL}} run lint
{{TOOL}} run build
{{TOOL}} test              # only if it is non-interactive / CI-safe
```

If there is no build script, say so — do not claim verification you did not do.

If verification **fails**:

1. Report the failure with the actual error output.
2. Offer to revert: `git checkout -- package.json <lockfile> pnpm-workspace.yaml`
3. Do not attempt an open-ended fixing spree on application code to make a
   dependency bump work, unless the user asks for exactly that.

## Step 5 — report and offer to commit

End with a short, honest summary:

- advisories **before → after**, and what remains with the reason
  (needs a major the user declined / no fix available)
- which files changed
- what verification you ran, and that it passed

Then propose a commit, e.g.:

> `Bumps next to 15.5.21 to clear 25 advisories`

Style: short, descriptive, present tense ("Bumps…", "Fixes…"), English, no
attribution or co-author lines. Stage **only** the manifest files, never `-A`.
Ask before committing, and ask again before pushing.

## Finally

When you are done — whether you fixed everything, some of it, or nothing — tell
the user in one line what the state is, so they can close the window.
