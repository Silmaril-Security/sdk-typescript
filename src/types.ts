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

export type GovernanceResource =
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
  readonly resource?: GovernanceResource;
}

export interface GovernanceDecision {
  readonly action: GovernanceAction;
  readonly ruleId?: string;
  readonly policyVersion: string;
  readonly resource?: GovernanceResource;
  readonly identityRevision?: string;
  readonly reason?: string;
}

export interface BlockResult {
  readonly prediction: Prediction;
  readonly score: number;
  readonly threshold: number;
  /** Omitted when neither an explicit local override nor the response supplies a mode. */
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
  /** Explicit local client default; a per-call or per-adapter mode takes precedence. */
  mode?: FirewallMode;
  /** @deprecated Use mode: "shadow" or mode: "block". */
  shadowMode?: boolean;
}

export type ClassificationMetadata = Readonly<Record<string, unknown>>;

export interface ClassifyOptions {
  /** Explicit local per-call override; authoritative over any response mode. */
  mode?: FirewallMode;
  hook?: HookLabel;
  toolName?: string;
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
  /** Explicit local per-call override; authoritative over every response mode. */
  mode?: FirewallMode;
  hooks?: readonly HookLabel[];
  toolNames?: readonly (string | undefined)[];
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
  /** Caller-provided backend sequence identity. Never inferred from runId. */
  conversationId?: string;
  includeSystem?: boolean;
  includeTool?: boolean;
  failOpen?: boolean;
  logger?: (message: string, error: unknown) => void;
  /** Explicit local adapter override; takes precedence over the client and response modes. */
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
  /** Explicit local adapter override; takes precedence over the client and response modes. */
  mode?: FirewallMode;
  /** @deprecated Use mode: "shadow" or mode: "block". */
  shadowMode?: boolean;
  onBlocked?: (err: Error) => void;
  onClassify?: (event: ClassifyEvent) => void;
}
