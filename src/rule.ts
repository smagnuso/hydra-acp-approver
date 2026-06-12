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

// Fallback when a config file exists but fails to load (bad syntax,
// no default export, etc.): abstain on every request. We don't guess
// at the user's intent when their config is broken.
export const ABSTAIN_RULE: RuleFunction = () => null;

// Engaged by HYDRA_ACP_APPROVER_DANGEROUSLY_ALLOW_ALL=1. Approves
// every request by picking an allow_once option (allow_always as a
// fallback). Mirrors Claude Code's --dangerously-skip-permissions:
// no prompts, no danger-list guarding, no human in the loop.
export const ALLOW_ALL_RULE: RuleFunction = (req) => {
  const allowOnce = req.options.find((o) => o.kind === "allow_once");
  if (allowOnce) {
    return allowOnce.optionId;
  }
  const allowAlways = req.options.find((o) => o.kind === "allow_always");
  if (allowAlways) {
    return allowAlways.optionId;
  }
  return null;
};

const SAFE_KINDS = new Set(["read", "search", "other"]);

// Tool calls whose serialized JSON matches one of these patterns
// abstain instead of auto-approving, so a human client gets the
// prompt.
const DANGEROUS_PATTERNS: RegExp[] = [
  /\brm\b[^\n]*\s-[a-zA-Z]*(rf|fr)[a-zA-Z]*\b[^\n]*(\s|=)(\/(?!\w)|\/\*|~|\$HOME|\*)(\s|"|'|\\|$)/,
  /\brm\b[^\n]*--recursive\b[^\n]*--force\b[^\n]*(\s|=)(\/(?!\w)|\/\*|~|\$HOME|\*)/,
  /\brm\b[^\n]*--force\b[^\n]*--recursive\b[^\n]*(\s|=)(\/(?!\w)|\/\*|~|\$HOME|\*)/,
  /\bdd\b[^\n]*\bof=\/dev\/(sd|nvme|disk|hd|mmcblk|xvd|vd)\w*/i,
  /\bmkfs(\.\w+)?\s+\/dev\//i,
  /\bfdisk\s+\/dev\//i,
  /\bparted\s+\/dev\//i,
  /\bshred\b[^\n]*\/dev\//i,
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
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

function looksDangerous(toolCall: PermissionRequest["toolCall"]): boolean {
  let blob: string;
  try {
    blob = JSON.stringify(toolCall);
  } catch {
    return true;
  }
  return DANGEROUS_PATTERNS.some((p) => p.test(blob));
}

function pickAllowOnce(
  options: PermissionRequest["options"],
): string | null {
  return options.find((o) => o.kind === "allow_once")?.optionId ?? null;
}

// The default rule when no config file is present. Matches the
// "Recommended starting point" shown in README.md: auto-approve
// read/search/other, auto-approve execute unless it matches a
// danger pattern, abstain otherwise. Users override this by
// dropping a JS module at the configured path.
export const DEFAULT_RULE: RuleFunction = (req) => {
  const kind = req.toolCall?.kind;
  // Agents emit a permission request with title/name "external_directory"
  // when they want to touch a path outside the session cwd. These are
  // benign by default (the agent still goes through its normal read/edit
  // permission flow for the actual operation), so auto-approve.
  const label = req.toolCall?.title ?? req.toolCall?.name;
  if (label === "external_directory") {
    return pickAllowOnce(req.options);
  }
  if (kind !== undefined && SAFE_KINDS.has(kind)) {
    return pickAllowOnce(req.options);
  }
  if (kind === "execute") {
    if (looksDangerous(req.toolCall)) {
      return null;
    }
    return pickAllowOnce(req.options);
  }
  return null;
};

let loadCounter = 0;

// Loads (or reloads) the user's rule function from `path`. Each call
// re-imports with a fresh cache-busting query param so SIGHUP-driven
// reloads pick up edits without restarting the process.
//
// Returns DEFAULT_RULE when the file is missing (the recommended
// starting point — auto-approve safe kinds, guard execute against a
// danger list, abstain otherwise). Returns ABSTAIN_RULE when the
// file exists but fails to import, so a broken user config doesn't
// silently fall back to auto-approval.
export async function loadRule(path: string): Promise<RuleFunction> {
  try {
    await stat(path);
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === "ENOENT") {
      log.info(
        `no rule config at ${path} — using built-in default rule (drop a JS file at that path to override)`,
      );
      return DEFAULT_RULE;
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
