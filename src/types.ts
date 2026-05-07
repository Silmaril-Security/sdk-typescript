// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type { FirewallHook, HookLabel } from "./hooks.js";

export type Prediction = "BENIGN" | "MALICIOUS";

export interface BlockResult {
  readonly prediction: Prediction;
  readonly score: number;
  readonly threshold: number;
  readonly primaryOutcome?: string;
  readonly outcomeScores?: Readonly<Record<string, number>>;
  readonly detectorScores?: Readonly<Record<string, number>>;
  readonly detectorCounts?: Readonly<Record<string, number>>;
}

export interface FirewallOptions {
  apiKey: string;
  apiUrl: string;
  timeoutMs?: number;
  chunkConcurrency?: number;
  shadowMode?: boolean;
}

export type ClassificationMetadata = Readonly<Record<string, unknown>>;

export interface ClassifyOptions {
  hook?: HookLabel;
  toolName?: string;
  metadata?: ClassificationMetadata;
}

export interface ClassifyBatchOptions {
  hooks?: readonly HookLabel[];
  toolNames?: readonly (string | undefined)[];
  metadata?: readonly (ClassificationMetadata | undefined)[];
}

export interface LangChainAdapterOptions {
  hooks?: ReadonlySet<FirewallHook>;
  includeSystem?: boolean;
  includeTool?: boolean;
  failOpen?: boolean;
  logger?: (message: string, error: unknown) => void;
  shadowMode?: boolean;
  onClassify?: (event: ClassifyEvent) => void;
}

export interface ClassifyEvent {
  readonly hook: HookLabel;
  readonly toolName?: string;
  readonly text: string;
  readonly result: BlockResult;
  readonly blocked: boolean;
  readonly shadowMode: boolean;
}

export interface MiddlewareOptions {
  scanInput?: boolean;
  scanOutput?: boolean;
  scanToolCalls?: boolean;
  shadowMode?: boolean;
  onBlocked?: (err: Error) => void;
  onClassify?: (event: ClassifyEvent) => void;
}
