// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import { randomUUID } from "node:crypto";

import { createMiddleware, type FirewallMiddleware } from "./adapters/vercel.js";
import { chunkText, sanitizeText } from "./chunking.js";
import { SilmarilApiError } from "./exceptions.js";
import type {
  BlockResult,
  ClassifyBatchOptions,
  ClassifyOptions,
  ClassificationMetadata,
  FirewallOptions,
  LangChainAdapterOptions,
  LangChainFirewallHandler,
  MiddlewareOptions,
  Prediction,
} from "./types.js";

export const BASE_THRESHOLD = 0.5;
export const TARGET_SEQUENCE_FPR = 0.01;
export const MAX_ADAPTIVE_THRESHOLD = 0.9;
export const SDK_VERSION = "0.4.1";
export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_CHUNK_CONCURRENCY = 8;
const DEFAULT_MAX_RETRIES = 5;
const MAX_BACKOFF_SECONDS = 30;
const MAX_ERROR_BODY_BYTES = 1 << 16;

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
  threshold: number;
  primary_outcome?: string;
  outcome_scores?: Record<string, number>;
  detector_scores?: Record<string, number>;
  detector_counts?: Record<string, number>;
}

interface BatchClassifyResponse {
  predictions: readonly SingleClassifyResponse[];
}

/** @deprecated Thresholds are tenant-owned by the Firewall backend. */
export function adaptiveThreshold(scoringOpportunityCount: number): number {
  if (!Number.isInteger(scoringOpportunityCount) || scoringOpportunityCount < 1) {
    throw new Error(
      `Firewall: scoringOpportunityCount must be an integer >= 1, got ${scoringOpportunityCount}`,
    );
  }
  if (scoringOpportunityCount === 1) {
    return BASE_THRESHOLD;
  }
  const targetChunkFpr = 1 - Math.pow(1 - TARGET_SEQUENCE_FPR, 1 / scoringOpportunityCount);
  const oddsRatio = TARGET_SEQUENCE_FPR / targetChunkFpr;
  const rawThreshold = oddsRatio / (1 + oddsRatio);
  return Math.min(rawThreshold, MAX_ADAPTIVE_THRESHOLD);
}

function blockResultFromResponse(data: SingleClassifyResponse): BlockResult {
  const result: {
    prediction: Prediction;
    score: number;
    threshold: number;
    primaryOutcome?: string;
    outcomeScores?: Readonly<Record<string, number>>;
    detectorScores?: Readonly<Record<string, number>>;
    detectorCounts?: Readonly<Record<string, number>>;
  } = {
    prediction: data.prediction,
    score: Number(data.score),
    threshold: Number(data.threshold),
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function withSdkMetadata(
  metadata: ClassificationMetadata | undefined,
  info: {
    requestId: string;
    inputIndex: number;
    chunkIndex: number;
    chunkCount: number;
  },
): ClassificationMetadata {
  const payload: Record<string, unknown> = { ...(metadata ?? {}) };
  const existing = payload.silmaril;
  if (existing !== undefined && !isRecord(existing)) {
    throw new Error("Firewall: metadata.silmaril must be an object when provided");
  }
  payload.silmaril = {
    ...(isRecord(existing) ? existing : {}),
    sdk_language: "typescript",
    sdk_version: SDK_VERSION,
    request_id: info.requestId,
    input_index: info.inputIndex,
    chunk_index: info.chunkIndex,
    chunk_count: info.chunkCount,
  };
  return payload;
}

async function readCappedErrorBody(response: Response): Promise<string> {
  if (!response.body) {
    return response.text().then((body) => body.slice(0, MAX_ERROR_BODY_BYTES)).catch(() => "");
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let remaining = MAX_ERROR_BODY_BYTES;
  try {
    while (remaining > 0) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }
      const chunk = value.byteLength > remaining ? value.slice(0, remaining) : value;
      chunks.push(chunk);
      remaining -= chunk.byteLength;
      if (chunk.byteLength < value.byteLength) {
        break;
      }
    }
  } catch {
    return "";
  } finally {
    await reader.cancel().catch(() => undefined);
  }

  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
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
  readonly timeoutMs: number;
  readonly chunkConcurrency: number;
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
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (typeof this.timeoutMs !== "number" || !Number.isFinite(this.timeoutMs) || this.timeoutMs < 0) {
      throw new Error(`Firewall: timeoutMs must be a finite non-negative number, got ${this.timeoutMs}`);
    }
    this.chunkConcurrency = options.chunkConcurrency ?? DEFAULT_CHUNK_CONCURRENCY;
    if (!Number.isInteger(this.chunkConcurrency) || this.chunkConcurrency < 1) {
      throw new Error(
        `Firewall: chunkConcurrency must be an integer >= 1, got ${this.chunkConcurrency}`,
      );
    }
    this.shadowMode = options.shadowMode ?? false;
    this.headers = Object.freeze({
      "x-api-key": this.apiKey,
      "content-type": "application/json",
    });
  }

  async classify(text: string, options: ClassifyOptions = {}): Promise<BlockResult> {
    const chunks = chunkText(text);
    const requestId = options.requestId ?? randomUUID();
    if (chunks.length === 1) {
      return this.classifySingleChunk(chunks[0]!, options, {
        requestId,
        inputIndex: 0,
        chunkIndex: 0,
        chunkCount: 1,
      });
    }
    const results = await mapWithConcurrency(chunks, this.chunkConcurrency, (chunk, index) =>
      this.classifySingleChunk(chunk, options, {
        requestId,
        inputIndex: 0,
        chunkIndex: index,
        chunkCount: chunks.length,
      }),
    );
    return results.reduce((best, r) => (r.score > best.score ? r : best));
  }

  async classifyBatch(
    texts: readonly string[],
    options: ClassifyBatchOptions = {},
  ): Promise<BlockResult[]> {
    if (texts.length === 0) {
      throw new Error("Firewall: texts must not be empty");
    }
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

    const requestId = options.requestId ?? randomUUID();
    const payload: BatchClassifyPayload = {
      texts: texts.map((text) => sanitizeText(text)),
    };
    if (options.hooks && options.hooks.length > 0) {
      payload.hooks = options.hooks.map((h) => String(h));
    }
    if (options.toolNames && options.toolNames.length > 0) {
      payload.tool_names = options.toolNames.map((t) => (t === undefined ? null : t));
    }
    payload.metadata = texts.map((_, index) =>
      withSdkMetadata(options.metadata?.[index], {
        requestId,
        inputIndex: index,
        chunkIndex: 0,
        chunkCount: 1,
      }),
    );
    const data = await this.postWithRetry<BatchClassifyResponse>(payload);
    return data.predictions.map((p) => blockResultFromResponse(p));
  }

  asLangChainHandler<THandler = LangChainFirewallHandler>(
    options: LangChainAdapterOptions = {},
  ): Promise<THandler> {
    return import("./adapters/langchain.js").then((m) =>
      m.createLangChainHandler(this, options) as Promise<THandler>,
    );
  }

  asMiddleware(options: MiddlewareOptions = {}): FirewallMiddleware {
    return createMiddleware(this, options);
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
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (response.status !== 429 || attempt === maxRetries) {
        if (!response.ok) {
          const body = await readCappedErrorBody(response);
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
    metadataInfo: {
      requestId: string;
      inputIndex: number;
      chunkIndex: number;
      chunkCount: number;
    },
  ): Promise<BlockResult> {
    const payload: SingleClassifyPayload = { text };
    if (options.hook !== undefined) {
      payload.hook = options.hook;
    }
    if (options.toolName !== undefined) {
      payload.tool_name = options.toolName;
    }
    payload.metadata = withSdkMetadata(options.metadata, metadataInfo);
    const data = await this.postWithRetry<SingleClassifyResponse>(payload);
    return blockResultFromResponse(data);
  }
}
