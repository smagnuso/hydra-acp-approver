# AGENTS.md

Brief for AI agents working in this repo.

## What this is

`hydra-acp-approver` — a headless permission auto-responder **extension** for
Hydra. Attaches to every live hydra session and answers
`session/request_permission` based on a user-provided JavaScript rule at
`~/.hydra-acp/approver.config.js`. When the rule returns an `optionId` it
wins the race and dismisses the prompt before any human client sees it; when
it returns `null` the prompt stays open for interactive clients.

## How it fits into Hydra

Hydra is a multi-client ACP session daemon. Full docs and the wire protocol
this repo depends on live at
[`smagnuso/hydra-acp`](https://github.com/smagnuso/hydra-acp) — see
`cli/PROTOCOL.md` for the WSS surface and permission-broadcast semantics
(RFD #533).

This is a **client extension**: it connects to the daemon's `/acp`
WebSocket using the per-process token in `HYDRA_ACP_TOKEN`, discovers
sessions via REST + WSS, `session/attach`es to each one with
`historyPolicy: "none"`, and races to answer permission requests.

## Layout

- `src/index.ts` — entry point, wires everything together
- `src/discovery.ts` — session discovery + attach loop
- `src/bridge.ts` — per-session WS bridge
- `src/permission.ts` — permission-request handler (the race-to-respond)
- `src/rule.ts` — loads and evaluates the user's `approver.config.js`;
  holds `DEFAULT_RULE` and its `DANGEROUS_PATTERNS` list
- `src/util/watch.ts` — config-file watcher that reloads the rule on save
- `src/config.ts` — env + config-file resolution
- `src/acp/`, `src/util/` — shared plumbing

## Build & test

```
npm install
npm run build     # tsup → dist/
npm test          # node:test via tsx (test/*.test.ts)
npm run lint
```

Ships as `hydra-acp-approver` on PATH. Registered via
`hydra-acp extension add hydra-acp-approver`.

## Conventions

- TypeScript, ESM, tsup, node:test.
- No new ACP methods here — protocol changes go in `hydra-acp/cli`.
- The rule file is *user* JavaScript; sandbox assumptions are minimal.
  Errors in the rule must never crash the extension — abstain and log.

## Gotchas

- Abstaining (rule returns `null`) means *do nothing* — do not send a
  response. Sending anything wins the race.
- The rule runs on every permission request across every session; keep it
  cheap. Rules that block on I/O will lose races to human clients.
- Discovery must handle sessions appearing mid-run and disappearing on
  daemon restart. Reconnect with backoff.
- **Silence-on-non-target is protocol, not laziness** (`bridge.ts`). Every
  broadcast permission request lands here; if this isn't our decision,
  we must send nothing. Returning `-32601 MethodNotFound` would poison
  the daemon-side race and settle the vote incorrectly.
- **Rule module reload uses `?v=...` cache-busting on the file URL**
  (`rule.ts`). Node's ESM loader otherwise pins the first load forever.
  Refactoring the URL construction (e.g. to plain `pathToFileURL`)
  silently breaks SIGHUP reload and the file-save reload alike.
- **The reload on save is the only reload path on Windows** (`util/watch.ts`).
  There is no `SIGHUP` there. The watcher watches the parent directory and
  filters by name, compares names case-insensitively on Windows, and is
  non-persistent: a test waiting on it must hold a live timer, or the
  process can exit first and node:test reports the test as cancelled.
- **Broken rule ≠ missing rule**: missing file falls through to
  `DEFAULT_RULE`; a broken/throwing rule falls through to `ABSTAIN_RULE`.
  Do not conflate — a syntax error in the user's config must never
  become auto-approve.
- **`DANGEROUS_PATTERNS` run on `JSON.stringify(toolCall)`, not on the
  command** (`rule.ts`). A Windows path arrives with doubled backslashes
  (`C:\` is `C:\\`) and an embedded quote as `\"`, so a pattern written
  against the raw command misses it. Write and test patterns against the
  serialized form (`test/rule.test.ts` builds real tool calls). The POSIX and
  Windows sets both apply on every platform: an agent can drive a Windows
  shell from anywhere. A pattern change needs a dangerous case that must
  abstain *and* a benign look-alike that must still be approved
  (`rd /s /q build`, `Format-Table`), or it will either miss or over-block.
- Open prompts stashed at rule-reload time keep their *original*
  responders (`permission.ts`); the new rule does not get to re-decide
  in-flight prompts.

## Updating this file

If you discover a durable, non-obvious invariant while working here — the
kind of thing you wish had been in this file when you started — flag it
in your final turn summary so the human can decide whether to add it. Do
not silently edit AGENTS.md mid-task. Prefer additions to `## Gotchas`
over reworking existing sections; never delete a gotcha without checking
that the underlying invariant is actually gone.
