# hydra-acp-approver

Headless permission auto-responder extension for [hydra-acp](https://github.com/smagnuso/hydra-acp).

Attaches to every live hydra session and answers `session/request_permission` based on a JavaScript rule function you provide. When the rule matches, the approver wins the race and dismisses the permission prompt before any human client sees it. When the rule abstains, the request stays open so your interactive clients (slack, TUI, browser) can still answer it normally.

## Install

From npm (recommended once published):

```sh
npm install -g @hydra-acp/approver
```

This drops a `hydra-acp-approver` binary on your PATH.

Or from source:

```sh
git clone git@github.com:smagnuso/hydra-acp-approver.git ~/dev/hydra-acp-approver
cd ~/dev/hydra-acp-approver
npm install
npm run build
```

Register the extension with hydra. If installed via npm:

```sh
hydra-acp extensions add hydra-acp-approver --command hydra-acp-approver
```

Or pointed at a local build:

```sh
hydra-acp extensions add hydra-acp-approver \
  --command node \
  --args ~/dev/hydra-acp-approver/dist/index.js
```

That writes the equivalent entry into `~/.hydra-acp/config.json`:

```json
{
  "extensions": {
    "hydra-acp-approver": {
      "command": ["node"],
      "args": ["/home/you/dev/hydra-acp-approver/dist/index.js"],
      "enabled": true
    }
  }
}
```

On `hydra-acp daemon start`, hydra spawns hydra-acp-approver as a managed
process with these env vars set: `HYDRA_ACP_DAEMON_URL`, `HYDRA_ACP_TOKEN`,
`HYDRA_ACP_WS_URL`. Stdout/stderr land in
`~/.hydra-acp/extensions/hydra-acp-approver.log`. Lifecycle is managed with
`hydra-acp extensions start|stop|restart hydra-acp-approver` and
`hydra-acp extensions logs hydra-acp-approver -f` to tail.

## Configure

Drop a JS module at `~/.hydra-acp/approver.config.js` (override with `HYDRA_ACP_APPROVER_CONFIG`). Default-export a function that decides per request:

```js
// ~/.hydra-acp/approver.config.js
export default function approve(req) {
  // req.toolCall.kind is one of: "read", "edit", "execute", "search",
  // "delete", "move", "fetch", "switch_mode", "think", "other".
  const kind = req.toolCall?.kind;
  if (["read", "search", "other", "execute"].includes(kind)) {
    return req.options.find((o) => o.kind === "allow_once")?.optionId ?? null;
  }
  // Return null/undefined to abstain — the request stays open and a
  // human client handles it as usual.
  return null;
}
```

> Prefer `allow_once` — agents typically cache `allow_always` choices locally and bypass the approver on subsequent identical calls.

### Recommended starting point

Blanket-allow-everything-execute is convenient but a foot-gun. The rule below mirrors that ergonomics for `read`/`search`/`other` but guards `execute` with a danger list — any tool call whose serialized shape mentions `rm -rf /`, `dd of=/dev/...`, fork bombs, piping `curl` into `sh`, system-state changes (`shutdown`, `reboot`), and friends abstains instead, so an interactive client (Slack, TUI, browser) gets the prompt and a human decides.

Patterns are matched against `JSON.stringify(toolCall)`, so they catch whichever field the agent put the command in (`rawInput.command`, terminal blocks in `content`, the title, etc.). Abstaining is safe — the request stays open — so the list errs on the side of being broad.

```js
// ~/.hydra-acp/approver.config.js
const SAFE_KINDS = new Set(["read", "search", "other"]);

const DANGEROUS_PATTERNS = [
  // rm with recursive + force flags hitting /, /*, ~, $HOME, or a bare glob
  /\brm\b[^\n]*\s-[a-zA-Z]*(rf|fr)[a-zA-Z]*\b[^\n]*(\s|=)(\/(?!\w)|\/\*|~|\$HOME|\*)(\s|"|'|\\|$)/,
  /\brm\b[^\n]*--recursive\b[^\n]*--force\b[^\n]*(\s|=)(\/(?!\w)|\/\*|~|\$HOME|\*)/,
  /\brm\b[^\n]*--force\b[^\n]*--recursive\b[^\n]*(\s|=)(\/(?!\w)|\/\*|~|\$HOME|\*)/,
  /\bdd\b[^\n]*\bof=\/dev\/(sd|nvme|disk|hd|mmcblk|xvd|vd)\w*/i,
  /\bmkfs(\.\w+)?\s+\/dev\//i,
  /\bfdisk\s+\/dev\//i,
  /\bparted\s+\/dev\//i,
  /\bshred\b[^\n]*\/dev\//i,
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,            // fork bomb
  />\s*\/dev\/(sd|nvme|disk|hd|mmcblk|xvd|vd)\w*/i,
  />\s*\/etc\/(passwd|shadow|sudoers|hosts)\b/i,
  /\b(shutdown|reboot|halt|poweroff)\b/i,
  /\binit\s+[06]\b/,
  /\bkill\s+-(?:9|KILL|SIGKILL)\s+1\b/,
  /\b(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|fish)\b/i,
  /\bchmod\s+-R\b[^\n]*\s\/(\s|$|"|')/,
  /\bchown\s+-R\b[^\n]*\s\/(\s|$|"|')/,
  /\bsudo\s+(rm|dd|mkfs|fdisk|parted|shred|chmod|chown|shutdown|reboot|halt|poweroff|init|userdel|groupdel)\b/i,
];

function looksDangerous(toolCall) {
  let blob;
  try {
    blob = JSON.stringify(toolCall);
  } catch {
    return true;
  }
  return DANGEROUS_PATTERNS.some((p) => p.test(blob));
}

function pickAllowOnce(options) {
  return options.find((o) => o.kind === "allow_once")?.optionId ?? null;
}

export default function approve(req) {
  const kind = req.toolCall?.kind;
  if (SAFE_KINDS.has(kind)) {
    return pickAllowOnce(req.options);
  }
  if (kind === "execute") {
    if (looksDangerous(req.toolCall)) {
      return null;
    }
    return pickAllowOnce(req.options);
  }
  return null;
}
```

Treat this as a starting point, not a security boundary — pattern-based detection inevitably misses things, and an agent that can craft commands can probably evade any list you write. The win is "no permission prompts for the 99% case, human-in-the-loop for the obviously-irreversible 1%."

### Request shape

```ts
interface PermissionRequest {
  sessionId: string;
  toolCall: {
    toolCallId: string;
    name?: string;
    title?: string;
    kind?: string;
    [k: string]: unknown;
  };
  options: ReadonlyArray<{
    optionId: string;
    name: string;
    kind?: "allow_once" | "allow_always" | "reject_once" | "reject_always" | string;
  }>;
  cwd?: string;
  agentId?: string;
}
```

### Return value

| Return       | Behavior                                                                                             |
|--------------|------------------------------------------------------------------------------------------------------|
| `string`     | An `optionId` from `req.options`. Approver responds with `{ outcome: { outcome: "selected", optionId } }` and wins the race against other attached clients. |
| `null` / `undefined` | Abstain. Approver doesn't respond; other attached clients (humans) see the prompt. |
| `Promise<...>` | Awaited. Same semantics on resolve. |
| Throw        | Caught + logged + treated as abstain — safe-by-default if your rule has a bug. |

If `optionId` doesn't appear in `req.options` (typo, agent-specific renaming), the approver abstains and logs a warning.

### Reload

Edits to `approver.config.js` are picked up automatically — the approver watches the file and re-imports it (with cache-busting) on every save. The next permission request after the reload completes uses the fresh rule.

If `fs.watch` is unreliable on your filesystem (NFS, some network mounts, certain container layouts), trigger a reload manually:

```sh
hydra-acp extensions restart hydra-acp-approver
# or, lighter, just re-import the rule without bouncing the WS attaches:
kill -HUP $(cat ~/.hydra-acp/extensions/hydra-acp-approver.pid)
```

Pending (already-abstained) requests are unaffected; new requests use the fresh rule.

### Missing config

If `approver.config.js` doesn't exist, the approver defaults to **abstain on every request**. Installing the extension without writing a config has zero behavioral effect — the daemon broadcasts permission prompts to every attached client as before.

## Environment

| Env var | Default | Purpose |
|---|---|---|
| `HYDRA_ACP_DAEMON_URL` | `http://127.0.0.1:8765` | Daemon HTTP endpoint (injected by hydra when run as an extension) |
| `HYDRA_ACP_TOKEN` | *(required)* | Daemon auth token (injected by hydra) |
| `HYDRA_ACP_WS_URL` | derived from daemon URL | Override WS endpoint |
| `HYDRA_ACP_APPROVER_CONFIG` | `~/.hydra-acp/approver.config.js` | Path to the rule module |
| `HYDRA_ACP_APPROVER_POLL_MS` | `2000` | Session-discovery poll interval |
| `DEBUG` | `false` | Verbose logging |

## How it works

The hydra-acp daemon broadcasts each `session/request_permission` to every attached client simultaneously and resolves the original agent request on the first response (see `hydra-acp/src/core/session.ts` `handlePermissionRequest`). Losers receive a `session/permission_resolved` notification with the winning outcome.

The approver attaches as one more client. When the rule fn returns an `optionId`, it replies immediately and wins. When it abstains, it stashes the JSON-RPC `respond` callback keyed by `toolCallId`; when `permission_resolved` arrives for that id, it replies with `{ outcome: { outcome: "cancelled" } }` to close out its own pending promise (no side effect — the daemon already settled the original request).

This means: install the approver and any per-client approve lambdas can go. Centralize the policy in one place.

