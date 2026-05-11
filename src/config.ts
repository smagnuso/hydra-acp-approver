import { homedir } from "node:os";
import { resolve } from "node:path";

export interface Config {
  hydraDaemonUrl: string;
  hydraWsUrl: string;
  hydraToken: string;
  hydraPollIntervalMs: number;
  // Absolute path to the user's rule-function module
  // (~/.hydra-acp/approver.config.js by default). When missing, the
  // approver defaults to abstain-on-everything, so installing the
  // extension without writing a config has zero behavioral effect.
  ruleConfigPath: string;
  debug: boolean;
}

function deriveWsUrl(httpUrl: string): string {
  if (httpUrl.startsWith("https://")) {
    return "wss://" + httpUrl.slice("https://".length).replace(/\/$/, "") + "/acp";
  }
  if (httpUrl.startsWith("http://")) {
    return "ws://" + httpUrl.slice("http://".length).replace(/\/$/, "") + "/acp";
  }
  throw new Error(`hydraDaemonUrl must start with http:// or https://: ${httpUrl}`);
}

function intEnv(name: string, fallback: number): number {
  const v = process.env[name];
  if (!v) {
    return fallback;
  }
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

const TRUTHY = new Set(["1", "true", "yes", "on", "t"]);

function boolEnv(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined) {
    return fallback;
  }
  return TRUTHY.has(v.toLowerCase());
}

export function loadConfig(): Config {
  const hydraDaemonUrl =
    process.env.HYDRA_ACP_DAEMON_URL ?? "http://127.0.0.1:8765";
  const hydraToken = process.env.HYDRA_ACP_TOKEN ?? "";
  if (!hydraToken) {
    throw new Error(
      "Missing HYDRA_ACP_TOKEN env var. When run as a hydra extension, hydra injects this automatically.",
    );
  }
  const hydraWsUrl =
    process.env.HYDRA_ACP_WS_URL ?? deriveWsUrl(hydraDaemonUrl);
  const ruleConfigPath =
    process.env.HYDRA_ACP_APPROVER_CONFIG ??
    resolve(homedir(), ".hydra-acp", "approver.config.js");

  return {
    hydraDaemonUrl,
    hydraWsUrl,
    hydraToken,
    hydraPollIntervalMs: intEnv("HYDRA_ACP_APPROVER_POLL_MS", 2000),
    ruleConfigPath,
    debug: boolEnv("DEBUG", false),
  };
}
