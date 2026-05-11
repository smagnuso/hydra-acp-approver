import { stat } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { logger } from "./util/log.js";

const log = logger("rule");

export interface PermissionRequest {
  sessionId: string;
  toolCall: {
    toolCallId: string;
    name?: string;
    title?: string;
    kind?: string;
    [key: string]: unknown;
  };
  options: ReadonlyArray<{
    optionId: string;
    name: string;
    kind?: string;
  }>;
  cwd?: string;
  agentId?: string;
}

export type RuleFunction = (
  req: PermissionRequest,
) => string | null | undefined | Promise<string | null | undefined>;

// The default rule when no config file is present (or when it fails to
// load): abstain on every request. Safe-by-default so a freshly
// installed extension never silently auto-approves anything.
export const ABSTAIN_RULE: RuleFunction = () => null;

let loadCounter = 0;

// Loads (or reloads) the user's rule function from `path`. Each call
// re-imports with a fresh cache-busting query param so SIGHUP-driven
// reloads pick up edits without restarting the process.
//
// Returns ABSTAIN_RULE when the file is missing or fails to import;
// the caller stays running and human clients keep working as before.
export async function loadRule(path: string): Promise<RuleFunction> {
  try {
    await stat(path);
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === "ENOENT") {
      log.info(
        `no rule config at ${path} — abstaining on every request (drop a JS file at that path to enable auto-approval)`,
      );
      return ABSTAIN_RULE;
    }
    log.warn(`stat ${path} failed: ${e.message}; abstaining`);
    return ABSTAIN_RULE;
  }
  // Cache-bust the dynamic import so reloads see fresh source. Without
  // the query param, Node's ESM loader returns the cached module
  // forever and SIGHUP becomes a no-op.
  loadCounter += 1;
  const url = `${pathToFileURL(path).href}?v=${Date.now()}-${loadCounter}`;
  try {
    const mod = (await import(url)) as { default?: unknown };
    const fn = mod.default;
    if (typeof fn !== "function") {
      log.warn(`${path} did not export a default function; abstaining`);
      return ABSTAIN_RULE;
    }
    log.info(`loaded rule function from ${path}`);
    return fn as RuleFunction;
  } catch (err) {
    log.warn(`import ${path} failed: ${(err as Error).message}; abstaining`);
    return ABSTAIN_RULE;
  }
}
