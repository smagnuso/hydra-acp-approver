import { strict as assert } from "node:assert";
import { test } from "node:test";
import { PermissionRouter } from "../src/permission.js";
import type { Logger } from "../src/util/log.js";
import type { PermissionRequestParams } from "../src/acp/protocol.js";

function silentLogger(): Logger {
  return {
    debug() {},
    info() {},
    warn() {},
    error() {},
  };
}

function makeParams(overrides?: Partial<PermissionRequestParams>): PermissionRequestParams {
  return {
    sessionId: "hydra_session_abc",
    toolCall: {
      toolCallId: "tc1",
      name: "Read",
      kind: "read",
    },
    options: [
      { optionId: "opt-always", name: "Always Allow", kind: "allow_always" },
      { optionId: "opt-once", name: "Allow", kind: "allow_once" },
      { optionId: "opt-no", name: "Reject", kind: "reject_once" },
    ],
    ...overrides,
  };
}

test("approves when rule returns an optionId", async () => {
  const router = new PermissionRouter(
    (req) =>
      req.toolCall.kind === "read"
        ? req.options.find((o) => o.kind === "allow_always")?.optionId ?? null
        : null,
    { sessionId: "hydra_session_abc" },
    silentLogger(),
  );
  let responded: unknown;
  await router.onRequestPermission(1, makeParams(), (r) => {
    responded = r;
  });
  assert.deepEqual(responded, {
    outcome: { outcome: "selected", optionId: "opt-always" },
  });
});

test("abstains and stashes responder when rule returns null", async () => {
  const router = new PermissionRouter(
    () => null,
    { sessionId: "hydra_session_abc" },
    silentLogger(),
  );
  let responded: unknown;
  await router.onRequestPermission(1, makeParams(), (r) => {
    responded = r;
  });
  assert.equal(responded, undefined);
  router.onPermissionResolved({ toolCall: { toolCallId: "tc1" } });
  assert.deepEqual(responded, { outcome: { outcome: "cancelled" } });
});

test("abstains on rule throw without crashing", async () => {
  const router = new PermissionRouter(
    () => {
      throw new Error("boom");
    },
    { sessionId: "hydra_session_abc" },
    silentLogger(),
  );
  let responded: unknown;
  await router.onRequestPermission(1, makeParams(), (r) => {
    responded = r;
  });
  assert.equal(responded, undefined);
  router.onPermissionResolved({ toolCall: { toolCallId: "tc1" } });
  assert.deepEqual(responded, { outcome: { outcome: "cancelled" } });
});

test("abstains when rule returns an unknown optionId", async () => {
  const router = new PermissionRouter(
    () => "opt-does-not-exist",
    { sessionId: "hydra_session_abc" },
    silentLogger(),
  );
  let responded: unknown;
  await router.onRequestPermission(1, makeParams(), (r) => {
    responded = r;
  });
  assert.equal(responded, undefined);
});

test("supports async rule fn", async () => {
  const router = new PermissionRouter(
    async (req) => {
      await new Promise<void>((r) => setImmediate(r));
      return req.options[0]?.optionId ?? null;
    },
    { sessionId: "hydra_session_abc" },
    silentLogger(),
  );
  let responded: unknown;
  await router.onRequestPermission(1, makeParams(), (r) => {
    responded = r;
  });
  assert.deepEqual(responded, {
    outcome: { outcome: "selected", optionId: "opt-always" },
  });
});

test("permission_resolved for unknown toolCallId is a no-op", () => {
  const router = new PermissionRouter(
    () => null,
    { sessionId: "hydra_session_abc" },
    silentLogger(),
  );
  // Should not throw.
  router.onPermissionResolved({ toolCall: { toolCallId: "nope" } });
});

test("shutdown clears stashed responders silently", async () => {
  const router = new PermissionRouter(
    () => null,
    { sessionId: "hydra_session_abc" },
    silentLogger(),
  );
  let responded: unknown;
  await router.onRequestPermission(1, makeParams(), (r) => {
    responded = r;
  });
  router.shutdown();
  // After shutdown, further permission_resolved doesn't fire the
  // (now-discarded) responder.
  router.onPermissionResolved({ toolCall: { toolCallId: "tc1" } });
  assert.equal(responded, undefined);
});

test("setRule swaps the rule for subsequent requests", async () => {
  let firstResponded: unknown;
  let secondResponded: unknown;
  const router = new PermissionRouter(
    () => null,
    { sessionId: "hydra_session_abc" },
    silentLogger(),
  );
  await router.onRequestPermission(1, makeParams(), (r) => {
    firstResponded = r;
  });
  router.setRule(() => "opt-always");
  await router.onRequestPermission(
    2,
    makeParams({ toolCall: { toolCallId: "tc2", kind: "read" } }),
    (r) => {
      secondResponded = r;
    },
  );
  assert.equal(firstResponded, undefined);
  assert.deepEqual(secondResponded, {
    outcome: { outcome: "selected", optionId: "opt-always" },
  });
});

test("emacs-style rule (read/search/other/execute -> allow_always)", async () => {
  // Mirror the user's emacs lambda exactly so we have a regression
  // anchor for the policy we're porting.
  const rule = (req: {
    toolCall: { kind?: string };
    options: Array<{ optionId: string; kind?: string }>;
  }): string | null => {
    const kind = req.toolCall.kind;
    if (
      kind === "read" ||
      kind === "search" ||
      kind === "other" ||
      kind === "execute"
    ) {
      return (
        req.options.find((o) => o.kind === "allow_always")?.optionId ?? null
      );
    }
    return null;
  };
  const router = new PermissionRouter(
    rule,
    { sessionId: "hydra_session_abc" },
    silentLogger(),
  );
  let responded: unknown;
  // edit -> abstain
  await router.onRequestPermission(
    1,
    makeParams({ toolCall: { toolCallId: "tc-edit", kind: "edit" } }),
    (r) => {
      responded = r;
    },
  );
  assert.equal(responded, undefined);
  // execute -> allow_always
  responded = undefined;
  await router.onRequestPermission(
    2,
    makeParams({ toolCall: { toolCallId: "tc-exec", kind: "execute" } }),
    (r) => {
      responded = r;
    },
  );
  assert.deepEqual(responded, {
    outcome: { outcome: "selected", optionId: "opt-always" },
  });
});
