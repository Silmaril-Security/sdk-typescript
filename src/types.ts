// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type { FirewallHook, HookLabel } from "./hooks.js";
import type { HarmfulOutcome, PrimaryOutcome } from "./outcomes.js";

export type Prediction = "BENIGN" | "MALICIOUS";
export type FirewallMode = "shadow" | "warn" | "block";
export type GovernanceAction = "allow" | "block";
export type GovernanceResourceKind =
  | "agent"
  | "tool"
  | "mcp_server"
  | "mcp_tool"
  | "plugin"
  | "skill"
  | "extension";

/** Legacy governance selector shape retained for GovernanceContext compatibility. */
export interface GovernanceResource {
  readonly kind: GovernanceResourceKind;
  readonly id?: string;
  readonly parentId?: string;
}

/** A concrete runtime resource reference; wildcard identities are not permitted. */
export type ConcreteGovernanceResource =
  | {
      readonly kind: "mcp_tool";
      readonly id: string;
      readonly parentId: string;
    }
  | {
      readonly kind: Exclude<GovernanceResourceKind, "mcp_tool">;
      readonly id: string;
      readonly parentId?: never;
    };

export interface GovernanceContext {
  readonly agent?: string;
  /** @deprecated Pass resource directly in ClassifyOptions.resource. */
  readonly resource?: GovernanceResource;
}

export type GovernanceReason = "identity_unresolved";

export interface GovernanceDecision {
  readonly action: GovernanceAction;
  readonly ruleId?: string;
  readonly policyVersion: string;
  readonly resource?: ConcreteGovernanceResource;
  readonly identityRevision?: string;
  readonly reason?: GovernanceReason;
}

export interface BlockResult {
  readonly prediction: Prediction;
  readonly score: number;
  readonly threshold: number;
  /** Omitted only when a legacy backend did not return mode and no override was requested. */
  readonly mode?: FirewallMode;
  readonly primaryOutcome?: PrimaryOutcome;
  readonly outcomeScores?: Readonly<Partial<Record<HarmfulOutcome, number>>>;
  readonly detectorScores?: Readonly<Partial<Record<HarmfulOutcome, number>>>;
  readonly detectorCounts?: Readonly<Partial<Record<HarmfulOutcome, number>>>;
  readonly governance?: GovernanceDecision;
}

export interface FirewallOptions {
  apiKey: string;
  apiUrl: string;
  timeoutMs?: number;
  mode?: FirewallMode;
  /** @deprecated Use mode: "shadow" or mode: "block". */
  shadowMode?: boolean;
}

export type ClassificationMetadata = Readonly<Record<string, unknown>>;

export interface ClassifyOptions {
  mode?: FirewallMode;
  hook?: HookLabel;
  toolName?: string;
  resource?: ConcreteGovernanceResource;
  identityRevision?: string;
  governance?: GovernanceContext;
  metadata?: ClassificationMetadata;
  requestId?: string;
  /**
   * Cancels this call only. Aborting stops the in-flight request or retry wait
   * and rejects with the signal's reason; sibling calls are unaffected.
   */
  signal?: AbortSignal;
}

export interface ClassifyBatchOptions {
  mode?: FirewallMode;
  hooks?: readonly HookLabel[];
  toolNames?: readonly (string | undefined)[];
  resources?: readonly (ConcreteGovernanceResource | null | undefined)[];
  identityRevision?: string;
  governance?: readonly (GovernanceContext | undefined)[];
  metadata?: readonly (ClassificationMetadata | undefined)[];
  requestId?: string;
  /**
   * Cancels this batch call only. Aborting stops the in-flight request or retry
   * wait and rejects with the signal's reason; sibling calls are unaffected.
   */
  signal?: AbortSignal;
}

export interface LangChainAdapterOptions {
  hooks?: ReadonlySet<FirewallHook>;
  includeSystem?: boolean;
  includeTool?: boolean;
  failOpen?: boolean;
  logger?: (message: string, error: unknown) => void;
  mode?: FirewallMode;
  /** @deprecated Use mode: "shadow" or mode: "block". */
  shadowMode?: boolean;
  onClassify?: (event: ClassifyEvent) => void;
}

export interface LangChainFirewallHandler {
  readonly name: string;
  readonly raiseError: boolean;
  readonly awaitHandlers: boolean;
  handleChatModelStart?: (...args: unknown[]) => unknown;
  handleLLMStart?: (...args: unknown[]) => unknown;
  handleToolStart?: (...args: unknown[]) => unknown;
  handleRetrieverStart?: (...args: unknown[]) => unknown;
  handleLLMEnd?: (...args: unknown[]) => unknown;
  handleToolEnd?: (...args: unknown[]) => unknown;
  handleRetrieverEnd?: (...args: unknown[]) => unknown;
}

export interface ClassifyEvent {
  readonly hook: HookLabel;
  readonly toolName?: string;
  readonly toolCallId?: string;
  readonly runId?: string;
  readonly text: string;
  readonly result: BlockResult;
  readonly blocked: boolean;
  readonly mode: FirewallMode;
  readonly shadowMode: boolean;
}

export interface MiddlewareOptions {
  scanInput?: boolean;
  scanOutput?: boolean;
  scanToolCalls?: boolean;
  mode?: FirewallMode;
  /** @deprecated Use mode: "shadow" or mode: "block". */
  shadowMode?: boolean;
  onBlocked?: (err: Error) => void;
  onClassify?: (event: ClassifyEvent) => void;
}

export type McpToolResourceResolution =
  | {
      readonly status: "resolved";
      readonly resource: ConcreteGovernanceResource & {
        readonly kind: "mcp_tool";
        readonly parentId: string;
      };
    }
  | {
      readonly status: "unresolved";
      readonly reason: "unrecognized_tool_name" | "unknown_server";
    }
  | {
      readonly status: "ambiguous";
      readonly serverIds: readonly string[];
    };
