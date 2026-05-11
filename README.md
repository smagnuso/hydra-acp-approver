# hydra-acp-approver

Headless permission auto-responder extension for [hydra-acp](https://github.com/smagnuso/hydra-acp).

Attaches as a controller to every live hydra session and answers `session/request_permission` based on a JavaScript rule function you provide. When the rule matches, the approver wins the race and dismisses the permission prompt before any human client sees it. When the rule abstains, the request stays open so your interactive clients (slack, TUI, browser) can still answer it normally.

## Install

```sh
git clone git@github.com:smagnuso/hydra-acp-approver.git ~/dev/hydra-acp-approver
cd ~/dev/hydra-acp-approver
npm install
npm run build
npm link
```

Then register it as a hydra-acp extension in `~/.hydra-acp/config.json`:

```json
{
  "extensions": {
    "hydra-acp-approver": {}
  }
}
```

Restart the daemon (`hydra-acp daemon restart`). Hydra spawns it as a managed process; logs land in `~/.hydra-acp/extensions/hydra-acp-approver.log`.

## Configure

Drop a JS module at `~/.hydra-acp/approver.config.js` (override with `HYDRA_ACP_APPROVER_CONFIG`). Default-export a function that decides per request:

```js
// ~/.hydra-acp/approver.config.js
export default function approve(req) {
  // req.toolCall.kind is one of: "read", "edit", "execute", "search",
  // "delete", "move", "fetch", "switch_mode", "think", "other".
  const kind = req.toolCall?.kind;
  if (["read", "search", "other", "execute"].includes(kind)) {
    return req.options.find((o) => o.kind === "allow_always")?.optionId ?? null;
  }
  // Return null/undefined to abstain — the request stays open and a
  // human client handles it as usual.
  return null;
}
```

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
| `string`     | An `optionId` from `req.options`. Approver responds with `{ outcome: { outcome: "selected", optionId } }` and wins the race against other controllers. |
| `null` / `undefined` | Abstain. Approver doesn't respond; other controllers (humans) see the prompt. |
| `Promise<...>` | Awaited. Same semantics on resolve. |
| Throw        | Caught + logged + treated as abstain — safe-by-default if your rule has a bug. |

If `optionId` doesn't appear in `req.options` (typo, agent-specific renaming), the approver abstains and logs a warning.

### Reload

Edit `approver.config.js`, then:

```sh
kill -HUP $(cat ~/.hydra-acp/extensions/hydra-acp-approver.pid)
```

Pending (already-abstained) requests are unaffected; new requests use the fresh rule.

### Missing config

If `approver.config.js` doesn't exist, the approver defaults to **abstain on every request**. Installing the extension without writing a config has zero behavioral effect — the daemon broadcasts permission prompts to all controllers as before.

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

The hydra-acp daemon broadcasts each `session/request_permission` to all attached controllers simultaneously and resolves the original agent request on the first response (see `hydra-acp/src/core/session.ts` `handlePermissionRequest`). Losers receive a `session/permission_resolved` notification with the winning outcome.

The approver attaches as one more controller. When the rule fn returns an `optionId`, it replies immediately and wins. When it abstains, it stashes the JSON-RPC `respond` callback keyed by `toolCallId`; when `permission_resolved` arrives for that id, it replies with `{ outcome: { outcome: "cancelled" } }` to close out its own pending promise (no side effect — the daemon already settled the original request).

This means: install the approver and any per-client approve lambdas can go. Centralize the policy in one place.

## Tests

```sh
npm test
```

Covers approve / abstain / throw / unknown-optionId / async-rule / reload paths in `PermissionRouter` and `loadRule`.
