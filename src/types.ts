// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type { FirewallHook, HookLabel } from "./hooks.js";
import type { HarmfulOutcome, PrimaryOutcome } from "./outcomes.js";

export type Prediction = "BENIGN" | "MALICIOUS";
export type FirewallMode = "shadow" | "warn" | "block";

export interface BlockResult {
  readonly prediction: Prediction;
  readonly score: number;
  readonly threshold: number;
  readonly mode: FirewallMode;
  readonly primaryOutcome?: PrimaryOutcome;
  readonly outcomeScores?: Readonly<Partial<Record<HarmfulOutcome, number>>>;
  readonly detectorScores?: Readonly<Partial<Record<HarmfulOutcome, number>>>;
  readonly detectorCounts?: Readonly<Partial<Record<HarmfulOutcome, number>>>;
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
  metadata?: ClassificationMetadata;
  requestId?: string;
}

export interface ClassifyBatchOptions {
  mode?: FirewallMode;
  hooks?: readonly HookLabel[];
  toolNames?: readonly (string | undefined)[];
  metadata?: readonly (ClassificationMetadata | undefined)[];
  requestId?: string;
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
