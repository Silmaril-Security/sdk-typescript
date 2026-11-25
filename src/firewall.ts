// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import { randomUUID } from "node:crypto";

import { createMiddleware, type FirewallMiddleware } from "./adapters/vercel.js";
import {
  FirewallBlockedException,
  ReviewCompatibilityError,
  SilmarilApiError,
} from "./exceptions.js";
import { HookLabel } from "./hooks.js";
import { validateMode } from "./modes.js";
import {
  DEFAULT_MAX_CONCURRENT,
  DEFAULT_MAX_QUEUED,
  PendingVerdicts,
  conversationId,
  reportBackground,
  retryBudget,
  validateLimit,
} from "./pending.js";
import { sanitizeText } from "./sanitization.js";
import { isPythonNonblankString } from "./validation.js";
import type {
  BlockResult,
  ClassifyBatchOptions,
  ClassifyOptions,
  ClassificationMetadata,
  Confidence,
  FirewallOptions,
  FirewallMode,
  GovernanceContext,
  GovernanceDecision,
  GovernanceResource,
  LangChainAdapterOptions,
  LangChainFirewallHandler,
  MiddlewareOptions,
  ProtectOptions,
  ReviewLevel,
  Severity,
} from "./types.js";

export const SDK_VERSION = "1.0.0";
export const DEFAULT_TIMEOUT_MS = 10_000;
const VERSION_1_PATH = "/classify";
const VERSION_2_PATH = "/v2/classify";
const VERSION_1_FALLBACK_STATUSES: ReadonlySet<number> = new Set([403, 404, 405]);
const DEFAULT_MAX_RETRIES = 5;
const MAX_BACKOFF_SECONDS = 30;
const MAX_ERROR_BODY_BYTES = 1 << 16;
/**
 * Largest delay a timer can represent. Both `setTimeout` and the
 * `AbortSignal.timeout` this client used before silently collapse a larger
 * delay to 1 ms, which would turn a long timeout into an immediate abort.
 */
const MAX_TIMEOUT_MS = 2_147_483_647;

interface SingleClassifyPayload {
  text: string;
  mode?: FirewallMode;
  review?: ReviewLevel;
  hook?: string;
  tool_name?: string;
  metadata?: ClassificationMetadata;
  resource?: Record<string, string>;
}

interface BatchClassifyPayload {
  texts: readonly string[];
  mode?: FirewallMode;
  review?: ReviewLevel;
  hooks?: readonly string[];
  tool_names?: readonly (string | null)[];
  metadata?: readonly (ClassificationMetadata | null)[];
  resources?: readonly (Record<string, string> | null)[];
}

interface ClassifyEndpoints {
  readonly version1: string;
  readonly version2: string;
}

interface WireDecisions {
  readonly results: unknown;
  readonly modes: readonly unknown[];
}

function classifyEndpoints(apiUrl: string): ClassifyEndpoints {
  const endpoint = (path: string): string => {
    const url = new URL(apiUrl);
    url.pathname = url.pathname.replace(/\/$/, "").replace(/\/(?:v2\/)?classify$/, "") + path;
    return url.href;
  };
  return { version1: endpoint(VERSION_1_PATH), version2: endpoint(VERSION_2_PATH) };
}

function validateReview(value: unknown, name: string): ReviewLevel | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (value !== "standard" && value !== "deep") {
    throw new Error(`Firewall: ${name} must be standard or deep`);
  }
  return value;
}

function resolveReview(perCallReview: unknown, clientReview?: ReviewLevel): ReviewLevel | undefined {
  return perCallReview === undefined
    ? clientReview
    : validateReview(perCallReview, "review");
}

function verifyReviewAcknowledgement(
  acknowledgedReview: unknown,
  requestedReview: ReviewLevel | undefined,
): void {
  if (requestedReview !== undefined && acknowledgedReview !== requestedReview) {
    throw new ReviewCompatibilityError(requestedReview, acknowledgedReview);
  }
}

function resolveMode(value: unknown, requestedMode?: FirewallMode): FirewallMode | undefined {
  let responseMode: FirewallMode | undefined;
  if (value === "shadow" || value === "warn" || value === "block") {
    responseMode = value;
  } else if (value !== undefined) {
    throw new Error("Firewall: response mode must be shadow, warn, or block");
  }

  // A supplied mode is the per-request override contract. Prefer it during
  // rolling upgrades so a missing or stale response field cannot strengthen
  // enforcement beyond what the caller requested.
  return requestedMode ?? responseMode;
}

function legacyMode(shadowMode: boolean | undefined): FirewallMode | undefined {
  return shadowMode === undefined ? undefined : shadowMode ? "shadow" : "block";
}

function surfaced<K extends string, V extends string = string>(
  key: K,
  value: unknown,
): { readonly [P in K]?: V } {
  return typeof value === "string" ? ({ [key]: value } as { readonly [P in K]: V }) : {};
}

function blockResultFromDecision(
  decision: unknown,
  mode: FirewallMode | undefined,
  review: ReviewLevel | undefined,
): BlockResult {
  if (!isRecord(decision) || typeof decision.action !== "string") {
    throw new Error("Firewall: response result action must be a string");
  }
  return Object.freeze({
    action: decision.action === "allow" ? "allow" : "block",
    ...surfaced("source", decision.source),
    ...surfaced<"confidence", Confidence>("confidence", decision.confidence),
    ...surfaced<"severity", Severity>("severity", decision.severity),
    ...surfaced("outcome", decision.outcome),
    ...(decision.governance === undefined || decision.governance === null
      ? {}
      : { governance: governanceDecisionFromResponse(decision.governance) }),
    ...surfaced("modelId", decision.model_id),
    ...(review === undefined ? {} : { review }),
    ...(mode === undefined ? {} : { mode }),
  });
}

export function blockResultsFromResponse(
  body: unknown,
  inputCount: number,
  requestedMode?: FirewallMode,
  requestedReview?: ReviewLevel,
): BlockResult[] {
  verifyReviewAcknowledgement(isRecord(body) ? body.review : undefined, requestedReview);
  const { results, modes } = wireDecisions(body);
  if (!Array.isArray(results)) {
    throw new Error("Firewall: response results must be an array");
  }
  if (results.length !== inputCount) {
    throw new Error(
      `Firewall: response results length ${results.length} does not match submitted texts length ${inputCount}`,
    );
  }
  return results.map((decision, index) =>
    blockResultFromDecision(decision, resolveMode(modes[index], requestedMode), requestedReview)
  );
}

function wireDecisions(body: unknown): WireDecisions {
  return isRecord(body) && "results" in body
    ? { results: body.results, modes: [] }
    : {
        results: adaptVersion1Response(body).results,
        modes: version1Predictions(body).map((prediction) => prediction.mode),
      };
}

function version1Predictions(body: unknown): readonly Record<string, unknown>[] {
  const predictions: unknown = isRecord(body) && "predictions" in body ? body.predictions : [body];
  if (!Array.isArray(predictions)) {
    throw new Error("Firewall: response predictions must be an array");
  }
  if (!predictions.every(isRecord)) {
    throw new Error("Firewall: response prediction must be an object");
  }
  return predictions;
}

function adaptVersion1Prediction(prediction: Record<string, unknown>): Record<string, unknown> {
  if (prediction.prediction !== "BENIGN" && prediction.prediction !== "MALICIOUS") {
    throw new Error("Firewall: response prediction must be BENIGN or MALICIOUS");
  }
  const blocks = prediction.prediction === "MALICIOUS"
    || (isRecord(prediction.governance) && prediction.governance.action === "block");
  const modelBlocks = blocks
    && (prediction.model_prediction ?? prediction.prediction) === "MALICIOUS";
  const hasOutcome = modelBlocks
    && isRecord(prediction.outcome_scores)
    && Object.keys(prediction.outcome_scores).length > 0;
  return {
    action: blocks ? "block" : "allow",
    source: modelBlocks ? "model" : blocks ? "governance" : null,
    confidence: null,
    severity: null,
    outcome: hasOutcome ? prediction.primary_outcome ?? null : null,
    governance: prediction.governance ?? null,
    model_id: prediction.model_id ?? null,
  };
}

export function adaptVersion1Response(body: unknown): Record<string, unknown> {
  return {
    results: version1Predictions(body).map(adaptVersion1Prediction),
    ...(isRecord(body) && body.review !== undefined ? { review: body.review } : {}),
  };
}

function wireCopy<T>(value: T): T {
  const encoded = JSON.stringify(value);
  return encoded === undefined ? value : JSON.parse(encoded) as T;
}

/** Copy caller-owned request data so a queued classification never reads it after the caller continues. */
function snapshotRequest(options: ClassifyOptions): ClassifyOptions {
  return {
    ...options,
    ...(options.metadata === undefined ? {} : { metadata: wireCopy(options.metadata) }),
    ...(options.governance === undefined ? {} : { governance: wireCopy(options.governance) }),
  };
}

function outputRequest(input: ClassifyOptions): ClassifyOptions {
  return {
    hook: HookLabel.LLM_OUTPUT,
    ...(input.mode === undefined ? {} : { mode: input.mode }),
    ...(input.review === undefined ? {} : { review: input.review }),
    ...(input.metadata === undefined ? {} : { metadata: input.metadata }),
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function withSdkMetadata(
  metadata: ClassificationMetadata | undefined,
  info: {
    requestId: string;
    inputIndex?: number;
    governance?: GovernanceContext;
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
    ...(info.governance === undefined
      ? {}
      : { governance: governanceContextToWire(info.governance) }),
  };
  return payload;
}

const GOVERNANCE_RESOURCE_KINDS = [
  "agent",
  "tool",
  "mcp_server",
  "mcp_tool",
  "plugin",
  "skill",
  "extension",
] as const;

function isGovernanceResourceKind(value: unknown): value is GovernanceResource["kind"] {
  return typeof value === "string"
    && (GOVERNANCE_RESOURCE_KINDS as readonly string[]).includes(value);
}

function governanceResourceToWire(resource: NonNullable<GovernanceContext["resource"]>): Record<string, string> {
  if (!isGovernanceResourceKind(resource.kind)) {
    throw new Error("Firewall: invalid governance resource kind");
  }
  if (typeof resource.id !== "string" || !resource.id.trim()) {
    throw new Error("Firewall: governance resource id must be a non-empty string");
  }
  if (resource.kind === "mcp_tool") {
    if (typeof resource.parentId !== "string" || !resource.parentId.trim()) {
      throw new Error("Firewall: mcp_tool resource requires a non-empty parentId");
    }
  } else if (resource.parentId !== undefined) {
    throw new Error("Firewall: parentId is valid only for mcp_tool resources");
  }
  return {
    kind: resource.kind,
    id: resource.id,
    ...(resource.parentId === undefined ? {} : { parent_id: resource.parentId }),
  };
}

function governanceResourceFromResponse(value: unknown): GovernanceResource {
  if (!isRecord(value)) {
    throw new Error("Firewall: response governance resource must be an object");
  }
  if (!isGovernanceResourceKind(value.kind)) {
    throw new Error("Firewall: response governance resource has an invalid kind");
  }
  if (typeof value.id !== "string" || !value.id.trim()) {
    throw new Error("Firewall: response governance resource id must be a non-empty string");
  }
  if (value.kind === "mcp_tool") {
    if (typeof value.parent_id !== "string" || !value.parent_id.trim()) {
      throw new Error(
        "Firewall: response governance mcp_tool resource requires a non-empty parent_id",
      );
    }
    return Object.freeze({
      kind: value.kind,
      id: value.id,
      parentId: value.parent_id,
    });
  }
  if (value.parent_id !== undefined && value.parent_id !== null) {
    throw new Error(
      "Firewall: response governance parent_id is valid only for mcp_tool resources",
    );
  }
  return Object.freeze({
    kind: value.kind,
    id: value.id,
  });
}

function governanceContextToWire(context: GovernanceContext): Record<string, unknown> {
  return {
    ...(context.agent === undefined ? {} : { agent: context.agent }),
    ...(context.resource === undefined
      ? {}
      : {
          resource: governanceResourceToWire(context.resource),
        }),
  };
}

function governanceDecisionFromResponse(value: unknown): GovernanceDecision {
  if (!isRecord(value)) {
    throw new Error("Firewall: response governance must be an object");
  }
  if (value.action !== "allow" && value.action !== "block") {
    throw new Error("Firewall: response governance action must be allow or block");
  }
  if (typeof value.policy_version !== "string" || value.policy_version.length === 0) {
    throw new Error("Firewall: response governance policy_version must be a non-empty string");
  }
  if (value.rule_id !== undefined && value.rule_id !== null && typeof value.rule_id !== "string") {
    throw new Error("Firewall: response governance rule_id must be a string when provided");
  }
  if (
    value.identity_revision !== undefined
    && value.identity_revision !== null
    && !isPythonNonblankString(value.identity_revision)
  ) {
    throw new Error(
      "Firewall: response governance identity_revision must be a non-empty string when provided",
    );
  }
  if (
    value.reason !== undefined
    && value.reason !== null
    && !isPythonNonblankString(value.reason)
  ) {
    throw new Error(
      "Firewall: response governance reason must be a non-empty string when provided",
    );
  }
  const resource = value.resource === undefined || value.resource === null
    ? undefined
    : governanceResourceFromResponse(value.resource);
  return Object.freeze({
    action: value.action,
    ...(value.rule_id === undefined || value.rule_id === null ? {} : { ruleId: value.rule_id }),
    policyVersion: value.policy_version,
    ...(resource === undefined ? {} : { resource }),
    ...(value.identity_revision === undefined || value.identity_revision === null
      ? {}
      : { identityRevision: value.identity_revision }),
    ...(value.reason === undefined || value.reason === null ? {} : { reason: value.reason }),
  });
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

/** Releases a response we will not read so a retry does not leak its socket. */
async function releaseDiscardedResponseBody(response: Response): Promise<void> {
  try {
    if (response.body) {
      if (!response.body.locked) {
        await response.body.cancel();
      }
      return;
    }
    await response.text();
  } catch {
    // The discarded body belongs to a response we already decided to retry.
  }
}

/** Cleanup must not postpone caller cancellation or an attempt timeout. */
async function discardResponseBody(response: Response, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  let onAbort!: () => void;
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    await Promise.race([releaseDiscardedResponseBody(response), aborted]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

function isAbortLikeError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const name = (error as { name?: unknown }).name;
  return name === "AbortError" || name === "TimeoutError";
}

/**
 * Reads a decoded body under an attempt signal. Native fetch can reject a body
 * read that the signal cancelled with a generic `AbortError`, which would drop
 * the caller's abort reason or the timeout reason. Only abort-caused failures
 * are rewritten; decode and transport errors are surfaced unchanged.
 */
async function readBodyUnderSignal<T>(read: () => Promise<T>, signal: AbortSignal): Promise<T> {
  try {
    return await read();
  } catch (error) {
    if (signal.aborted && isAbortLikeError(error)) {
      throw signal.reason;
    }
    throw error;
  }
}

interface AttemptSignal {
  readonly signal: AbortSignal;
  dispose(): void;
}

/**
 * Combines the per-attempt timeout with an optional caller signal. The caller
 * signal is shared across sibling calls, so the listener and the timer are
 * released by `dispose()` once the attempt no longer needs them.
 */
function createAttemptSignal(timeoutMs: number, callerSignal?: AbortSignal): AttemptSignal {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(
      new DOMException("The operation was aborted due to timeout", "TimeoutError"),
    );
  }, timeoutMs);
  const onCallerAbort = (): void => {
    // Body disposal may never settle, so do not wait for finally to release
    // a timer that could keep a command hook alive beyond the caller deadline.
    clearTimeout(timer);
    controller.abort(callerSignal?.reason);
  };
  callerSignal?.addEventListener("abort", onCallerAbort, { once: true });
  return {
    signal: controller.signal,
    dispose: () => {
      clearTimeout(timer);
      callerSignal?.removeEventListener("abort", onCallerAbort);
    },
  };
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Firewall client for the `/v2/classify` API, falling back to `/classify` on
 * runtimes that predate it.
 *
 * Configuration is set once in the constructor. The only state a request
 * changes is the remembered fallback, which moves one way and only selects the
 * endpoint, so one client is safe to share across any number of concurrent
 * `classify()` and `classifyBatch()` promises within a single JavaScript
 * runtime. Each worker thread owns its own client: `Firewall` instances are
 * not transferable across `worker_threads` boundaries.
 */
export class Firewall {
  readonly apiKey: string;
  readonly apiUrl: string;
  readonly timeoutMs: number;
  readonly shadowMode: boolean;
  readonly mode: FirewallMode | undefined;
  readonly review: ReviewLevel | undefined;
  /** @internal Shared by adapters so one conversation keeps a single send order. */
  readonly pending: PendingVerdicts;

  private readonly headers: Readonly<Record<string, string>>;
  private readonly endpoints: ClassifyEndpoints;
  private version1Only = false;

  constructor(options: FirewallOptions) {
    if (!options.apiKey) {
      throw new Error("Firewall: apiKey is required");
    }
    if (!options.apiUrl) {
      throw new Error("Firewall: apiUrl is required");
    }
    this.apiKey = options.apiKey;
    this.apiUrl = options.apiUrl;
    this.endpoints = classifyEndpoints(options.apiUrl);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (typeof this.timeoutMs !== "number" || !Number.isFinite(this.timeoutMs) || this.timeoutMs < 0) {
      throw new Error(`Firewall: timeoutMs must be a finite non-negative number, got ${this.timeoutMs}`);
    }
    if (this.timeoutMs > MAX_TIMEOUT_MS) {
      throw new Error(
        `Firewall: timeoutMs must be at most ${MAX_TIMEOUT_MS} ms, got ${this.timeoutMs}`,
      );
    }
    this.mode = validateMode(options.mode) ?? legacyMode(options.shadowMode);
    this.review = validateReview(options.review, "review");
    this.shadowMode = this.mode === "shadow";
    this.pending = new PendingVerdicts(
      validateLimit("maxConcurrent", options.maxConcurrent ?? DEFAULT_MAX_CONCURRENT),
      validateLimit("maxQueued", options.maxQueued ?? DEFAULT_MAX_QUEUED),
    );
    this.headers = Object.freeze({
      "x-api-key": this.apiKey,
      "content-type": "application/json",
    });
  }

  async classify(text: string, options: ClassifyOptions = {}): Promise<BlockResult> {
    const requestId = options.requestId ?? randomUUID();
    return this.classifySingle(sanitizeText(text), options, { requestId });
  }

  /**
   * Run an operation while its input is classified and withhold a blocked result.
   * The operation's signal aborts when a block arrives before it finishes.
   */
  async protect<TResult>(
    operation: (signal: AbortSignal) => PromiseLike<TResult> | TResult,
    options: ProtectOptions<TResult>,
  ): Promise<TResult> {
    const { text, output, ...request } = options;
    const requestedMode = validateMode(options.mode) ?? this.mode;
    const controller = new AbortController();
    if (requestedMode === "shadow" || requestedMode === "warn") {
      const observed = this.observable(request);
      if (observed !== undefined) {
        void this.background(text, observed);
      }
      const result = await operation(controller.signal);
      if (observed !== undefined && output !== undefined) {
        void this.background(output(result), outputRequest(observed));
      }
      return result;
    }
    const input = snapshotRequest(request);
    const conversation = conversationId(input.metadata);
    const outputOptions = outputRequest(input);
    const verdict = this.pending.submit(() => this.enforce(text, input), conversation, input.signal);
    const [, result] = await Promise.all([
      verdict.catch((error: unknown) => {
        controller.abort(error);
        throw error;
      }),
      Promise.resolve().then(() => operation(controller.signal)),
    ]);
    if (output !== undefined) {
      const generated = output(result);
      await this.pending.submit(
        () => this.enforce(generated, outputOptions),
        conversation,
        input.signal,
      );
    }
    return result;
  }

  /** Wait for classifications still running in the background. */
  flush(): Promise<void> {
    return this.pending.drain();
  }

  /**
   * @internal Classify in the background with one retry; resolves undefined on failure.
   * The request is copied now and detached from the caller's signal.
   */
  observe(text: string, options: ClassifyOptions = {}): Promise<BlockResult | undefined> {
    const request = this.observable(options);
    return request === undefined ? Promise.resolve(undefined) : this.background(text, request);
  }

  private background(text: string, request: ClassifyOptions): Promise<BlockResult | undefined> {
    return this.pending.observe(() => this.classify(text, request), conversationId(request.metadata));
  }

  /** Copy a background request, reporting one that cannot be copied instead of failing the caller. */
  private observable(options: ClassifyOptions): ClassifyOptions | undefined {
    try {
      const request = snapshotRequest(options);
      delete request.signal;
      return request;
    } catch (error) {
      reportBackground("background classification failed", error);
      return undefined;
    }
  }

  private async enforce(text: string, options: ClassifyOptions): Promise<BlockResult> {
    const result = await this.classify(text, options);
    if (result.action !== "allow" && (result.mode ?? "block") === "block") {
      throw new FirewallBlockedException({
        promptText: text,
        ...(options.hook === undefined ? {} : { hook: options.hook }),
        ...(options.toolName === undefined ? {} : { toolName: options.toolName }),
        result,
      });
    }
    return result;
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
    if (options.governance !== undefined && options.governance.length !== texts.length) {
      throw new Error(
        `Firewall: governance length ${options.governance.length} does not match texts length ${texts.length}`,
      );
    }

    const requestId = options.requestId ?? randomUUID();
    const payload: BatchClassifyPayload = {
      texts: texts.map((text) => sanitizeText(text)),
    };
    const requestedMode = validateMode(options.mode) ?? this.mode;
    const requestedReview = resolveReview(options.review, this.review);
    if (requestedMode !== undefined) {
      payload.mode = requestedMode;
    }
    if (requestedReview !== undefined) {
      payload.review = requestedReview;
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
        ...(options.governance?.[index] === undefined
          ? {}
          : { governance: options.governance[index] }),
      }),
    );
    if (options.governance !== undefined) {
      payload.resources = options.governance.map((context) =>
        context?.resource === undefined ? null : governanceResourceToWire(context.resource),
      );
    }
    return this.decide(payload, requestedMode, requestedReview, options.signal);
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

  private async decide(
    payload: SingleClassifyPayload | BatchClassifyPayload,
    requestedMode: FirewallMode | undefined,
    requestedReview: ReviewLevel | undefined,
    callerSignal?: AbortSignal,
  ): Promise<BlockResult[]> {
    // Cancellation outranks payload serialization, which can itself throw on
    // cyclic metadata or a throwing `toJSON`.
    callerSignal?.throwIfAborted();
    // Serialize before the first attempt so retries and the version 1 fallback
    // resend the same logical event even if the caller mutates the objects it
    // passed in.
    const body = JSON.stringify(payload);
    const decode = (response: unknown): BlockResult[] => blockResultsFromResponse(
      response,
      "texts" in payload ? payload.texts.length : 1,
      requestedMode,
      requestedReview,
    );
    if (!this.version1Only) {
      try {
        return decode(await this.postWithRetry(this.endpoints.version2, body, callerSignal));
      } catch (error) {
        if (!(error instanceof SilmarilApiError) || !VERSION_1_FALLBACK_STATUSES.has(error.status)) {
          throw error;
        }
      }
    }
    const results = decode(await this.postWithRetry(this.endpoints.version1, body, callerSignal));
    this.version1Only = true;
    return results;
  }

  private async postWithRetry(
    url: string,
    body: string,
    callerSignal?: AbortSignal,
  ): Promise<unknown> {
    const maxRetries = retryBudget(DEFAULT_MAX_RETRIES);
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      callerSignal?.throwIfAborted();
      const attemptSignal = createAttemptSignal(this.timeoutMs, callerSignal);
      try {
        const response = await fetch(url, {
          method: "POST",
          headers: this.headers,
          body,
          redirect: "error",
          signal: attemptSignal.signal,
        });
        if (response.status !== 429 || attempt === maxRetries) {
          if (!response.ok) {
            const errorBody = await readCappedErrorBody(response);
            // The capped read swallows its own failures, so an abort during it
            // would otherwise be reported as a plain API error.
            attemptSignal.signal.throwIfAborted();
            throw new SilmarilApiError({
              status: response.status,
              statusText: response.statusText,
              body: errorBody,
            });
          }
          return await readBodyUnderSignal<unknown>(
            () => response.json(),
            attemptSignal.signal,
          );
        }
        await discardResponseBody(response, attemptSignal.signal);
      } finally {
        attemptSignal.dispose();
      }
      await sleep(Math.min(2 ** attempt, MAX_BACKOFF_SECONDS) * 1000, callerSignal);
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
    const requestedMode = validateMode(options.mode) ?? this.mode;
    const requestedReview = resolveReview(options.review, this.review);
    if (requestedMode !== undefined) {
      payload.mode = requestedMode;
    }
    if (requestedReview !== undefined) {
      payload.review = requestedReview;
    }
    if (options.hook !== undefined) {
      payload.hook = options.hook;
    }
    if (options.toolName !== undefined) {
      payload.tool_name = options.toolName;
    }
    if (options.governance?.resource !== undefined) {
      payload.resource = governanceResourceToWire(options.governance.resource);
    }
    payload.metadata = withSdkMetadata(options.metadata, {
      ...metadataInfo,
      ...(options.governance === undefined ? {} : { governance: options.governance }),
    });
    return (await this.decide(payload, requestedMode, requestedReview, options.signal))[0]!;
  }
}
