// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import { randomUUID } from "node:crypto";

import { createMiddleware, type FirewallMiddleware } from "./adapters/vercel.js";
import { SilmarilApiError } from "./exceptions.js";
import { normalizeHarmfulOutcomeMap, normalizePrimaryOutcome } from "./outcomes.js";
import { sanitizeText } from "./sanitization.js";
import type {
  BlockResult,
  ClassifyBatchOptions,
  ClassifyOptions,
  ClassificationMetadata,
  FirewallOptions,
  FirewallMode,
  LangChainAdapterOptions,
  LangChainFirewallHandler,
  MiddlewareOptions,
  Prediction,
} from "./types.js";

export const SDK_VERSION = "0.6.0";
export const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RETRIES = 5;
const MAX_BACKOFF_SECONDS = 30;
const MAX_ERROR_BODY_BYTES = 1 << 16;

interface SingleClassifyPayload {
  text: string;
  mode?: FirewallMode;
  hook?: string;
  tool_name?: string;
  metadata?: ClassificationMetadata;
}

interface BatchClassifyPayload {
  texts: readonly string[];
  mode?: FirewallMode;
  hooks?: readonly string[];
  tool_names?: readonly (string | null)[];
  metadata?: readonly (ClassificationMetadata | null)[];
}

interface SingleClassifyResponse {
  prediction: Prediction;
  score: number;
  threshold: number;
  mode?: unknown;
  primary_outcome?: unknown;
  outcome_scores?: unknown;
  detector_scores?: unknown;
  detector_counts?: unknown;
}

interface BatchClassifyResponse {
  predictions: readonly SingleClassifyResponse[];
}

function normalizeMode(value: unknown, fallback?: FirewallMode): FirewallMode {
  if (value === undefined) {
    if (fallback !== undefined) {
      return fallback;
    }
    throw new Error("Firewall: response mode must be shadow, warn, or block");
  }
  if (value === "shadow" || value === "warn" || value === "block") {
    return value;
  }
  throw new Error("Firewall: response mode must be shadow, warn, or block");
}

function legacyMode(shadowMode: boolean | undefined): FirewallMode | undefined {
  return shadowMode === undefined ? undefined : shadowMode ? "shadow" : "block";
}

function blockResultFromResponse(
  data: SingleClassifyResponse,
  fallbackMode?: FirewallMode,
): BlockResult {
  if (data.prediction !== "BENIGN" && data.prediction !== "MALICIOUS") {
    throw new Error("Firewall: response prediction must be BENIGN or MALICIOUS");
  }
  const result: {
    prediction: Prediction;
    score: number;
    threshold: number;
    mode: FirewallMode;
    primaryOutcome?: NonNullable<BlockResult["primaryOutcome"]>;
    outcomeScores?: NonNullable<BlockResult["outcomeScores"]>;
    detectorScores?: NonNullable<BlockResult["detectorScores"]>;
    detectorCounts?: NonNullable<BlockResult["detectorCounts"]>;
  } = {
    prediction: data.prediction,
    score: Number(data.score),
    threshold: Number(data.threshold),
    mode: normalizeMode(data.mode, fallbackMode),
  };
  if (data.primary_outcome !== undefined) {
    result.primaryOutcome = normalizePrimaryOutcome(data.primary_outcome);
  }
  if (data.outcome_scores !== undefined) {
    const outcomeScores = normalizeHarmfulOutcomeMap(data.outcome_scores, "outcome_scores");
    if (outcomeScores !== undefined) {
      result.outcomeScores = outcomeScores;
    }
  }
  if (data.detector_scores !== undefined) {
    const detectorScores = normalizeHarmfulOutcomeMap(data.detector_scores, "detector_scores");
    if (detectorScores !== undefined) {
      result.detectorScores = detectorScores;
    }
  }
  if (data.detector_counts !== undefined) {
    const detectorCounts = normalizeHarmfulOutcomeMap(data.detector_counts, "detector_counts");
    if (detectorCounts !== undefined) {
      result.detectorCounts = detectorCounts;
    }
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
    inputIndex?: number;
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
    ...(info.inputIndex === undefined ? {} : { input_index: info.inputIndex }),
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

export class Firewall {
  readonly apiKey: string;
  readonly apiUrl: string;
  readonly timeoutMs: number;
  readonly shadowMode: boolean;
  readonly mode: FirewallMode | undefined;

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
    this.mode = options.mode ?? legacyMode(options.shadowMode);
    this.shadowMode = this.mode === "shadow";
    this.headers = Object.freeze({
      "x-api-key": this.apiKey,
      "content-type": "application/json",
    });
  }

  async classify(text: string, options: ClassifyOptions = {}): Promise<BlockResult> {
    const requestId = options.requestId ?? randomUUID();
    return this.classifySingle(sanitizeText(text), options, { requestId });
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
    const requestedMode = options.mode ?? this.mode;
    if (requestedMode !== undefined) {
      payload.mode = requestedMode;
    }
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
      }),
    );
    const data = await this.postWithRetry<BatchClassifyResponse>(payload);
    return data.predictions.map((p) => blockResultFromResponse(p, requestedMode));
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

  private async classifySingle(
    text: string,
    options: ClassifyOptions,
    metadataInfo: {
      requestId: string;
    },
  ): Promise<BlockResult> {
    const payload: SingleClassifyPayload = { text };
    const requestedMode = options.mode ?? this.mode;
    if (requestedMode !== undefined) {
      payload.mode = requestedMode;
    }
    if (options.hook !== undefined) {
      payload.hook = options.hook;
    }
    if (options.toolName !== undefined) {
      payload.tool_name = options.toolName;
    }
    payload.metadata = withSdkMetadata(options.metadata, metadataInfo);
    const data = await this.postWithRetry<SingleClassifyResponse>(payload);
    return blockResultFromResponse(data, requestedMode);
  }
}
