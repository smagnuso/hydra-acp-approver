import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadRule,
  ABSTAIN_RULE,
  ALLOW_ALL_RULE,
  DEFAULT_RULE,
} from "../src/rule.js";

test("loadRule returns DEFAULT_RULE when the file is missing", async () => {
  const fn = await loadRule("/does/not/exist.js");
  assert.equal(fn, DEFAULT_RULE);
});

test("DEFAULT_RULE auto-approves safe kinds with allow_once", async () => {
  const result = await DEFAULT_RULE({
    sessionId: "s",
    toolCall: { toolCallId: "t", kind: "read" },
    options: [
      { optionId: "ao", name: "Always", kind: "allow_always" },
      { optionId: "o1", name: "Once", kind: "allow_once" },
    ],
  });
  assert.equal(result, "o1");
});

test("DEFAULT_RULE auto-approves safe execute commands", async () => {
  const result = await DEFAULT_RULE({
    sessionId: "s",
    toolCall: {
      toolCallId: "t",
      kind: "execute",
      rawInput: { command: "ls -la" },
    },
    options: [{ optionId: "o1", name: "Once", kind: "allow_once" }],
  });
  assert.equal(result, "o1");
});

test("DEFAULT_RULE abstains on dangerous execute commands", async () => {
  const result = await DEFAULT_RULE({
    sessionId: "s",
    toolCall: {
      toolCallId: "t",
      kind: "execute",
      rawInput: { command: "rm -rf /" },
    },
    options: [{ optionId: "o1", name: "Once", kind: "allow_once" }],
  });
  assert.equal(result, null);
});

test("DEFAULT_RULE abstains on unknown kinds", async () => {
  const result = await DEFAULT_RULE({
    sessionId: "s",
    toolCall: { toolCallId: "t", kind: "delete" },
    options: [{ optionId: "o1", name: "Once", kind: "allow_once" }],
  });
  assert.equal(result, null);
});

test("ALLOW_ALL_RULE picks allow_once for any kind, including dangerous", async () => {
  const result = await ALLOW_ALL_RULE({
    sessionId: "s",
    toolCall: {
      toolCallId: "t",
      kind: "execute",
      rawInput: { command: "rm -rf /" },
    },
    options: [
      { optionId: "always", name: "Always", kind: "allow_always" },
      { optionId: "once", name: "Once", kind: "allow_once" },
      { optionId: "deny", name: "Deny", kind: "reject_once" },
    ],
  });
  assert.equal(result, "once");
});

test("ALLOW_ALL_RULE falls back to allow_always when allow_once is missing", async () => {
  const result = await ALLOW_ALL_RULE({
    sessionId: "s",
    toolCall: { toolCallId: "t", kind: "delete" },
    options: [
      { optionId: "always", name: "Always", kind: "allow_always" },
      { optionId: "deny", name: "Deny", kind: "reject_once" },
    ],
  });
  assert.equal(result, "always");
});

test("ALLOW_ALL_RULE abstains when no allow option is offered", async () => {
  const result = await ALLOW_ALL_RULE({
    sessionId: "s",
    toolCall: { toolCallId: "t", kind: "execute" },
    options: [{ optionId: "deny", name: "Deny", kind: "reject_once" }],
  });
  assert.equal(result, null);
});

test("loadRule imports a JS module's default export", async () => {
  const dir = mkdtempSync(join(tmpdir(), "approver-rule-"));
  try {
    const p = join(dir, "rule.js");
    writeFileSync(
      p,
      'export default function approve(req) { return req.toolCall?.kind === "read" ? "opt-always" : null; }\n',
      "utf8",
    );
    const fn = await loadRule(p);
    assert.notEqual(fn, ABSTAIN_RULE);
    const result = await fn({
      sessionId: "s",
      toolCall: { toolCallId: "t", kind: "read" },
      options: [{ optionId: "opt-always", name: "Always" }],
    });
    assert.equal(result, "opt-always");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadRule falls back to ABSTAIN_RULE when module has no default export", async () => {
  const dir = mkdtempSync(join(tmpdir(), "approver-rule-"));
  try {
    const p = join(dir, "rule.js");
    writeFileSync(p, "export const foo = 1;\n", "utf8");
    const fn = await loadRule(p);
    assert.equal(fn, ABSTAIN_RULE);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Cache-bust re-import behavior is verified manually under plain `node`
// (Node's ESM loader keys on the full URL including query string). The
// `tsx` dev runner used by `npm test` intercepts dynamic imports and
// ignores the cache-busting query param, so the assertion would fail
// here despite working at runtime. The compiled extension runs under
// plain node and reloads correctly on SIGHUP.
