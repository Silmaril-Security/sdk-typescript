// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type { BaseCallbackHandler } from "@langchain/core/callbacks/base";

import { createMiddleware, type FirewallMiddleware } from "./adapters/vercel.js";
import { chunkText, sanitizeText } from "./chunking.js";
import { SilmarilApiError } from "./exceptions.js";
import type { HookLabel } from "./hooks.js";
import type {
  BlockResult,
  ClassifyBatchOptions,
  ClassifyOptions,
  ClassificationMetadata,
  FirewallOptions,
  LangChainAdapterOptions,
  MiddlewareOptions,
  Prediction,
} from "./types.js";

export const DEFAULT_THRESHOLD = 0.5;
export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_CHUNK_CONCURRENCY = 8;
const DEFAULT_MAX_RETRIES = 5;
const MAX_BACKOFF_SECONDS = 30;

interface SingleClassifyPayload {
  text: string;
  hook?: string;
  tool_name?: string;
  metadata?: ClassificationMetadata;
}

interface BatchClassifyPayload {
  texts: readonly string[];
  hooks?: readonly string[];
  tool_names?: readonly (string | null)[];
  metadata?: readonly (ClassificationMetadata | null)[];
}

interface SingleClassifyResponse {
  prediction: Prediction;
  score: number;
  primary_outcome?: string;
  outcome_scores?: Record<string, number>;
  detector_scores?: Record<string, number>;
  detector_counts?: Record<string, number>;
}

interface BatchClassifyResponse {
  predictions: readonly SingleClassifyResponse[];
}

function blockResultFromResponse(data: SingleClassifyResponse): BlockResult {
  const result: {
    prediction: Prediction;
    score: number;
    primaryOutcome?: string;
    outcomeScores?: Readonly<Record<string, number>>;
    detectorScores?: Readonly<Record<string, number>>;
    detectorCounts?: Readonly<Record<string, number>>;
  } = {
    prediction: data.prediction,
    score: Number(data.score),
  };
  if (data.primary_outcome !== undefined) {
    result.primaryOutcome = data.primary_outcome;
  }
  if (data.outcome_scores !== undefined) {
    result.outcomeScores = Object.freeze(
      Object.fromEntries(Object.entries(data.outcome_scores).map(([k, v]) => [k, Number(v)])),
    );
  }
  if (data.detector_scores !== undefined) {
    result.detectorScores = Object.freeze(
      Object.fromEntries(Object.entries(data.detector_scores).map(([k, v]) => [k, Number(v)])),
    );
  }
  if (data.detector_counts !== undefined) {
    result.detectorCounts = Object.freeze(
      Object.fromEntries(Object.entries(data.detector_counts).map(([k, v]) => [k, Number(v)])),
    );
  }
  return Object.freeze(result);
}

async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  task: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let nextIndex = 0;
  let firstError: unknown;
  const workerCount = Math.min(concurrency, items.length);

  async function worker(): Promise<void> {
    for (;;) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) {
        return;
      }
      try {
        results[index] = await task(items[index]!, index);
      } catch (err) {
        firstError ??= err;
      }
    }
  }

  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  if (firstError !== undefined) {
    throw firstError;
  }
  return results;
}

export class Firewall {
  readonly apiKey: string;
  readonly apiUrl: string;
  readonly threshold: number;
  readonly timeoutMs: number;
  readonly chunkConcurrency: number;
  readonly hookThresholds: Readonly<Partial<Record<HookLabel, number>>>;
  readonly shadowMode: boolean;

  private readonly headers: Readonly<Record<string, string>>;

  constructor(options: FirewallOptions) {
    if (!options.apiKey) {
      throw new Error("Firewall: apiKey is required");
    }
    if (!options.apiUrl) {
      throw new Error("Firewall: apiUrl is required");
    }
    this.apiKey = options.apiKey;
    this.apiUrl = options.apiUrl;
    this.threshold = options.threshold ?? DEFAULT_THRESHOLD;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.chunkConcurrency = options.chunkConcurrency ?? DEFAULT_CHUNK_CONCURRENCY;
    if (!Number.isInteger(this.chunkConcurrency) || this.chunkConcurrency < 1) {
      throw new Error(
        `Firewall: chunkConcurrency must be an integer >= 1, got ${this.chunkConcurrency}`,
      );
    }
    this.hookThresholds = Object.freeze({ ...(options.hookThresholds ?? {}) });
    this.shadowMode = options.shadowMode ?? false;
    this.headers = Object.freeze({
      "x-api-key": this.apiKey,
      "content-type": "application/json",
    });
  }

  async classify(text: string, options: ClassifyOptions = {}): Promise<BlockResult> {
    const chunks = chunkText(text);
    if (chunks.length === 1) {
      return this.classifySingleChunk(chunks[0]!, options);
    }
    const results = await mapWithConcurrency(chunks, this.chunkConcurrency, (chunk) =>
      this.classifySingleChunk(chunk, options),
    );
    return results.reduce((best, r) => (r.score > best.score ? r : best));
  }

  async classifyBatch(
    texts: readonly string[],
    options: ClassifyBatchOptions = {},
  ): Promise<BlockResult[]> {
    if (options.hooks !== undefined && options.hooks.length !== texts.length) {
      throw new Error(
        `Firewall: hooks length ${options.hooks.length} does not match texts length ${texts.length}`,
      );
    }
    if (options.toolNames !== undefined && options.toolNames.length !== texts.length) {
      throw new Error(
        `Firewall: toolNames length ${options.toolNames.length} does not match texts length ${texts.length}`,
      );
    }
    if (options.metadata !== undefined && options.metadata.length !== texts.length) {
      throw new Error(
        `Firewall: metadata length ${options.metadata.length} does not match texts length ${texts.length}`,
      );
    }

    const payload: BatchClassifyPayload = { texts: texts.map((text) => sanitizeText(text)) };
    if (options.hooks && options.hooks.length > 0) {
      payload.hooks = options.hooks.map((h) => String(h));
    }
    if (options.toolNames && options.toolNames.length > 0) {
      payload.tool_names = options.toolNames.map((t) => (t === undefined ? null : t));
    }
    if (options.metadata && options.metadata.length > 0) {
      payload.metadata = options.metadata.map((m) => (m === undefined ? null : m));
    }
    const data = await this.postWithRetry<BatchClassifyResponse>(payload);
    return data.predictions.map((p) => blockResultFromResponse(p));
  }

  asLangChainHandler(options: LangChainAdapterOptions = {}): Promise<BaseCallbackHandler> {
    return import("./adapters/langchain.js").then((m) => m.createLangChainHandler(this, options));
  }

  asMiddleware(options: MiddlewareOptions = {}): FirewallMiddleware {
    return createMiddleware(this, options);
  }

  effectiveThreshold(hook: HookLabel | undefined): number {
    if (hook === undefined) {
      return this.threshold;
    }
    return this.hookThresholds[hook] ?? this.threshold;
  }

  private async postWithRetry<T>(
    payload: SingleClassifyPayload | BatchClassifyPayload,
    maxRetries: number = DEFAULT_MAX_RETRIES,
  ): Promise<T> {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const response = await fetch(this.apiUrl, {
        method: "POST",
        headers: this.headers,
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (response.status !== 429 || attempt === maxRetries) {
        if (!response.ok) {
          const body = await response.text().catch(() => "");
          throw new SilmarilApiError({
            status: response.status,
            statusText: response.statusText,
            body,
          });
        }
        return (await response.json()) as T;
      }
      const waitSeconds = Math.min(2 ** attempt, MAX_BACKOFF_SECONDS);
      await new Promise<void>((resolve) => setTimeout(resolve, waitSeconds * 1000));
    }
    throw new Error("Firewall: exhausted retries (unreachable)");
  }

  private async classifySingleChunk(
    text: string,
    options: ClassifyOptions,
  ): Promise<BlockResult> {
    const payload: SingleClassifyPayload = { text };
    if (options.hook !== undefined) {
      payload.hook = options.hook;
    }
    if (options.toolName !== undefined) {
      payload.tool_name = options.toolName;
    }
    if (options.metadata !== undefined) {
      payload.metadata = options.metadata;
    }
    const data = await this.postWithRetry<SingleClassifyResponse>(payload);
    return blockResultFromResponse(data);
  }
}
