import type { Logger } from "./util/log.js";
import type {
  PermissionRequestParams,
  PermissionResolvedParams,
  JsonRpcId,
} from "./acp/protocol.js";
import type { PermissionRequest, RuleFunction } from "./rule.js";

export type RespondFn = (result: unknown) => void;

interface PendingResponder {
  toolCallId: string;
  respond: RespondFn;
}

export interface SessionMeta {
  sessionId: string;
  cwd?: string;
  agentId?: string;
}

// Per-bridge router: decodes session/request_permission, calls the user
// rule fn, and either responds immediately (rule returned an optionId)
// or stashes the responder until session/permission_resolved arrives
// from the daemon.
//
// Rules can change at runtime via setRule (SIGHUP-driven reload from
// the entry point). Pending responders are unaffected by a reload —
// they remain stashed and get closed out when permission_resolved
// arrives or the WS drops.
export class PermissionRouter {
  private pending = new Map<string, PendingResponder>();
  private rule: RuleFunction;

  constructor(
    rule: RuleFunction,
    private readonly meta: SessionMeta,
    private readonly log: Logger,
  ) {
    this.rule = rule;
  }

  setRule(rule: RuleFunction): void {
    this.rule = rule;
  }

  async onRequestPermission(
    id: JsonRpcId,
    params: PermissionRequestParams,
    respond: RespondFn,
  ): Promise<void> {
    const req = buildRequest(params, this.meta);
    let result: string | null | undefined;
    try {
      result = await this.rule(req);
    } catch (err) {
      this.log.warn(
        `rule threw on toolCallId=${req.toolCall.toolCallId}: ${(err as Error).message}; abstaining`,
      );
      result = null;
    }
    if (result == null) {
      this.stash(req.toolCall.toolCallId, respond);
      this.log.info(
        `abstain id=${id} toolCallId=${req.toolCall.toolCallId} kind=${
          req.toolCall.kind ?? "?"
        }`,
      );
      return;
    }
    const opt = req.options.find((o) => o.optionId === result);
    if (!opt) {
      this.log.warn(
        `rule returned unknown optionId=${result} for toolCallId=${req.toolCall.toolCallId}; abstaining`,
      );
      this.stash(req.toolCall.toolCallId, respond);
      return;
    }
    respond({ outcome: { outcome: "selected", optionId: result } });
    this.log.info(
      `approved toolCallId=${req.toolCall.toolCallId} kind=${
        req.toolCall.kind ?? "?"
      } optionId=${result} (${opt.kind ?? "?"})`,
    );
  }

  // Another controller answered the request first. Close out our stashed
  // promise (if any) with a cancelled outcome so the JSON-RPC layer
  // doesn't leak a pending request on the daemon side.
  onPermissionResolved(params: PermissionResolvedParams): void {
    const toolCallId = params.toolCall?.toolCallId;
    if (!toolCallId) {
      return;
    }
    const entry = this.pending.get(toolCallId);
    if (!entry) {
      return;
    }
    this.pending.delete(toolCallId);
    entry.respond({ outcome: { outcome: "cancelled" } });
    this.log.debug(`closed out abstained toolCallId=${toolCallId}`);
  }

  // Drop any stashed responders — called on WS close so we don't hold
  // dangling JSON-RPC promises against a connection that's gone.
  shutdown(): void {
    if (this.pending.size > 0) {
      this.log.debug(
        `dropping ${this.pending.size} pending responder(s) on shutdown`,
      );
    }
    this.pending.clear();
  }

  private stash(toolCallId: string, respond: RespondFn): void {
    this.pending.set(toolCallId, { toolCallId, respond });
  }
}

function buildRequest(
  params: PermissionRequestParams,
  meta: SessionMeta,
): PermissionRequest {
  const toolCall = (params.toolCall ?? {}) as PermissionRequest["toolCall"];
  const options = Array.isArray(params.options) ? params.options : [];
  return {
    sessionId: meta.sessionId,
    toolCall,
    options,
    ...(meta.cwd !== undefined ? { cwd: meta.cwd } : {}),
    ...(meta.agentId !== undefined ? { agentId: meta.agentId } : {}),
  };
}
