// ACP wire protocol version this extension speaks. Single source of
// truth for the initialize handshake; never a literal at the callsite.
export const ACP_PROTOCOL_VERSION = 1;

export type JsonRpcId = number | string;

export interface JsonRpcRequest<P = unknown> {
  jsonrpc: "2.0";
  id: JsonRpcId;
  method: string;
  params?: P;
}

export interface JsonRpcResponse<R = unknown> {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result?: R;
  error?: { code: number; message: string; data?: unknown };
}

export interface JsonRpcNotification<P = unknown> {
  jsonrpc: "2.0";
  method: string;
  params?: P;
}

export type JsonRpcMessage =
  | JsonRpcRequest
  | JsonRpcResponse
  | JsonRpcNotification;

export function isRequest(m: JsonRpcMessage): m is JsonRpcRequest {
  return "method" in m && "id" in m;
}

export function isNotification(m: JsonRpcMessage): m is JsonRpcNotification {
  return "method" in m && !("id" in m);
}

export function isResponse(m: JsonRpcMessage): m is JsonRpcResponse {
  return !("method" in m) && "id" in m;
}

export interface PermissionRequestParams {
  sessionId: string;
  toolCall: {
    toolCallId: string;
    name?: string;
    title?: string;
    kind?: string;
    [key: string]: unknown;
  };
  options: Array<{
    optionId: string;
    name: string;
    kind?: "allow_once" | "allow_always" | "reject_once" | "reject_always" | string;
  }>;
}

export interface PermissionResolvedParams {
  sessionId?: string;
  requestId?: JsonRpcId;
  toolCall?: { toolCallId?: string };
  result?: unknown;
}

export interface PermissionResponseResult {
  outcome:
    | { outcome: "selected"; optionId: string }
    | { outcome: "cancelled" };
}
