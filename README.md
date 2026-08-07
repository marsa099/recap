# recap

One digest of everything that happened while you weren't looking: unread mail,
active chats, dependency advisories and the handful of Hacker News stories that
actually touch your work. Collected on a timer, read instantly.

Two pieces:

- **`recap`** (this repo) — Python collector + CLI. Runs providers, normalises
  everything into one item shape, writes a snapshot, applies actions back to
  the source.
- **`Recap.qml`** in [qs-picker](https://github.com/marsa099/qs-picker) — the
  overlay, bound to `Mod+Shift+Space`. It only reads the snapshot and shells
  out to `recap act`, so every row is reproducible from a terminal.

## Use

```sh
recap refresh          # run every provider, write the snapshot
recap show             # print the digest as text
recap show --lane work # work only
recap show --ids       # with item ids, for `recap act`
recap act <id> read    # read | archive | trash | star
recap undo             # undo the last action
recap providers        # what's wired up, and whether it's reachable
```

A systemd user timer (`recap-refresh.timer`, every 15 min) keeps the snapshot
warm so the overlay never shows a spinner, and `recap-watch.service` keeps it
in step with the clients in between:

```sh
recap watch                       # react to mlqs/chat state changes, live
recap refresh --only mail,chat    # re-run a subset, keep the rest
```

Read an email in mlqs and it leaves the digest within a couple of seconds —
no waiting for the timer. The watcher keys off mlqs's **SQLite cache**, not its
`readmarked` broadcast: that broadcast only fires from the notification
callback, whereas every read/unread/archive/trash goes through
`db.SetConvFlags` and lands in the cache. Watching the cache therefore catches
strictly more, with no protocol dependency. Chat sockets are held open read-only
and re-derive on a fresh `channels` frame. `security` and `news` are never
re-run by the watcher — reading one mail must not trigger an `npm audit` sweep.

## Providers

| | Source | Needs |
|---|---|---|
| **mail** | mlqs SQLite cache, read-only | nothing to read; the mlqs daemon only to *act* |
| **chat** | dsqrd / slqs / tmqs / msqs unix sockets | the respective daemon running |
| **security** | `npm audit` / `pnpm audit` over `~/repos` | node/pnpm on PATH |
| **news** | Hacker News API | network |

Design notes worth knowing:

- **Collecting never mutates.** Mail is read straight out of
  `~/.local/share/mlqs/cache.db` with `?mode=ro`, so the digest works while
  mlqs is down. Chat reads only the channel list frame the daemons push on
  connect — never `recent`/`focus`, which would clobber the owning UI's
  active-channel and notification state.
- **A dead provider says so.** It emits a stale row rather than contributing
  nothing. Silently reporting zero is what makes people stop trusting a digest.
- **Security is aggressively de-noised.** A raw audit of `~/repos` yields 160+
  findings. Advisories collapse per package, rank by severity, and only the
  worst `security.max_rows` get a row — the tail becomes one honest "N further
  advisories" line. Nothing is ever silently truncated.
- **State survives refresh.** Read/starred/dismissed live in `state.json`,
  keyed by a stable hash of `source:key`, so rebuilding every item doesn't wipe
  your triage. A dismissed advisory stays dismissed until its version moves,
  because the version is part of the key.

## Config

`~/.config/recap/config.toml`, all optional:

```toml
[mail]
work_accounts = ["work1", "work2"]     # mlqs account names that are work

[news]
scan = 60
keep = 6
big_points = 400                       # keep anything this popular, on-topic or not
interests = ["nix", "wayland", "dotnet", "claude"]
work_interests = ["dotnet", "azure"]

[security]
max_rows = 10
max_age_hours = 12
ignore_repos = ["teams-for-linux"]
```

## Addons

Any executable in `~/.config/recap/addons/` that prints a JSON array to stdout.
No plugin API, no base class, any language:

```json
[{ "title": "Villa, 168 m², 11 950 000 kr",
   "who": "Nockeby", "sub": "6 rok",
   "summary": "15% under the area median. Viewing Sunday 12:00.",
   "when": "new", "lane": "private", "url": "https://…" }]
```

Fields: `title` (required), `summary`, `who`, `sub`, `when`, `lane`, `url`,
`score`, `accent`, `priority`, `id`. The section name comes from the filename.
A crash or timeout surfaces as a one-line failure row instead of taking the
refresh down. The built-in providers use the same item shape, so an addon is
not a second-class citizen.

## Gotchas

- **An IpcHandler function named `show` is silently unreachable** in quickshell
  0.3.0 — `qs ipc call recap show` prints the handler's function list and exits
  0 without dispatching. `toggle` and `hide` work; the summon verb is spelled
  `summon`.
- `npm audit` needs the network and takes ~10–90s per repo. Results are cached
  by lockfile mtime, so only the timer pays that cost.
