import { AcpAttach } from "./acp/attach.js";
import type {
  JsonRpcRequest,
  JsonRpcNotification,
  PermissionRequestParams,
  PermissionResolvedParams,
} from "./acp/protocol.js";
import { PermissionRouter, type SessionMeta } from "./permission.js";
import type { RuleFunction } from "./rule.js";
import { logger } from "./util/log.js";

const log = logger("bridge");

export interface BridgeOptions {
  daemonWsUrl: string;
  token: string;
  meta: SessionMeta;
  getRule: () => RuleFunction;
}

// One bridge per discovered session. Opens a WS, attaches as a
// controller, hooks session/request_permission requests + the
// session/permission_resolved notification through PermissionRouter.
//
// `getRule` is a thunk rather than a baked-in value so SIGHUP reloads
// (which mutate the rule on the entry point's loader) are picked up
// without rebuilding every bridge. The router itself also has a
// setRule path, used when a reload happens after a bridge is live.
export class ApproverBridge {
  private readonly attach: AcpAttach;
  private readonly router: PermissionRouter;
  private stopped = false;

  constructor(private readonly opts: BridgeOptions) {
    this.attach = new AcpAttach({
      sessionId: opts.meta.sessionId,
      daemonWsUrl: opts.daemonWsUrl,
      token: opts.token,
    });
    this.router = new PermissionRouter(opts.getRule(), opts.meta, log);
  }

  start(): void {
    this.attach.on("request", (r) => this.onRequest(r));
    this.attach.on("notification", (n) => this.onNotification(n));
    this.attach.on("close", () => {
      this.router.shutdown();
    });
    this.attach.on("error", (err) => {
      log.warn(
        `attach error ${this.opts.meta.sessionId}: ${err.message}`,
      );
    });
    this.attach.start();
  }

  stop(): void {
    if (this.stopped) {
      return;
    }
    this.stopped = true;
    this.router.shutdown();
    this.attach.stop();
  }

  // Pull a fresh rule from the loader after a SIGHUP reload.
  refreshRule(): void {
    this.router.setRule(this.opts.getRule());
  }

  private onRequest(r: JsonRpcRequest): void {
    if (r.method !== "session/request_permission") {
      // Anything else aimed at us is unexpected — reply with a JSON-RPC
      // method-not-found so the daemon doesn't hold a pending promise.
      this.attach.replyError(r.id, -32601, `method not implemented: ${r.method}`);
      return;
    }
    const params = (r.params ?? {}) as PermissionRequestParams;
    void this.router.onRequestPermission(r.id, params, (result) => {
      this.attach.reply(r.id, result);
    });
  }

  private onNotification(n: JsonRpcNotification): void {
    if (n.method !== "session/permission_resolved") {
      return;
    }
    const params = (n.params ?? {}) as PermissionResolvedParams;
    this.router.onPermissionResolved(params);
  }
}
