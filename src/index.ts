#!/usr/bin/env node
import { loadConfig } from "./config.js";
import { HydraDiscovery } from "./discovery.js";
import { ApproverBridge } from "./bridge.js";
import { ABSTAIN_RULE, loadRule, type RuleFunction } from "./rule.js";
import { logger, setDebug } from "./util/log.js";
import { watchConfigPath } from "./util/watch.js";

const log = logger("main");

async function main(): Promise<void> {
  const config = loadConfig();
  setDebug(config.debug);

  // The current rule function. SIGHUP-triggered reloads mutate this
  // box; bridges re-read it on each request via a thunk so they always
  // see the latest version.
  let currentRule: RuleFunction = ABSTAIN_RULE;
  currentRule = await loadRule(config.ruleConfigPath);

  const bridges = new Map<string, ApproverBridge>();

  const discovery = new HydraDiscovery({
    daemonUrl: config.hydraDaemonUrl,
    token: config.hydraToken,
    pollIntervalMs: config.hydraPollIntervalMs,
    onAdd: (session) => {
      if (bridges.has(session.sessionId)) {
        return;
      }
      log.info(
        `attaching to ${session.sessionId} agent=${session.agentId ?? "?"} cwd=${session.cwd}`,
      );
      const bridge = new ApproverBridge({
        daemonWsUrl: config.hydraWsUrl,
        token: config.hydraToken,
        meta: {
          sessionId: session.sessionId,
          cwd: session.cwd,
          ...(session.agentId !== undefined
            ? { agentId: session.agentId }
            : {}),
        },
        getRule: () => currentRule,
      });
      bridges.set(session.sessionId, bridge);
      bridge.start();
    },
    onRemove: (sessionId) => {
      const bridge = bridges.get(sessionId);
      if (!bridge) {
        return;
      }
      log.info(`detaching from ${sessionId}`);
      bridges.delete(sessionId);
      bridge.stop();
    },
  });
  discovery.start();

  // Reloads the rule function. Bridges call getRule() on every
  // permission request, so they pick up the new function for the next
  // request after reload completes. In-flight (stashed) responders
  // keep their original abstain behavior and get closed out normally
  // by permission_resolved when a human resolves them.
  const reloadRule = (origin: string): void => {
    log.info(`${origin} — reloading rule from ${config.ruleConfigPath}`);
    loadRule(config.ruleConfigPath)
      .then((rule) => {
        currentRule = rule;
        for (const bridge of bridges.values()) {
          bridge.refreshRule();
        }
        log.info("rule reload complete");
      })
      .catch((err: unknown) => {
        log.warn(`rule reload failed: ${(err as Error).message}`);
      });
  };

  process.on("SIGHUP", () => reloadRule("SIGHUP"));

  // Auto-reload when the config file is edited. Watches the parent
  // directory so it survives editor temp-file-then-rename and picks up
  // the file even if it didn't exist at startup. SIGHUP stays as a
  // manual fallback for setups where fs.watch is unreliable (NFS,
  // network mounts, etc.).
  const configWatcher = watchConfigPath({
    path: config.ruleConfigPath,
    onChange: () => reloadRule("config file changed"),
    onError: (err) => log.warn(`config watcher error: ${err.message}`),
  });

  const shutdown = (sig: string): void => {
    log.info(`${sig} received — shutting down`);
    configWatcher.stop();
    discovery.stop();
    for (const bridge of bridges.values()) {
      bridge.stop();
    }
    // Give the WS closes a beat to flush, then exit.
    setTimeout(() => process.exit(0), 200).unref();
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  log.info(
    `hydra-acp-approver up; daemon=${config.hydraDaemonUrl} rule=${config.ruleConfigPath}`,
  );
}

main().catch((err) => {
  process.stderr.write(`hydra-acp-approver: ${(err as Error).message}\n`);
  process.exit(1);
});
