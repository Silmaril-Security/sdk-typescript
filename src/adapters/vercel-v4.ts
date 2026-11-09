// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

/**
 * Vercel AI SDK 7 middleware integration.
 *
 * Import this adapter explicitly from
 * `@silmaril-security/sdk/adapters/vercel-v4`. AI SDK 7 requires Node.js 22
 * or newer; the rest of the Silmaril SDK continues to support Node.js 20.
 */
import type { Firewall } from "../firewall.js";
import { FirewallBlockedException } from "../exceptions.js";
import { HookLabel } from "../hooks.js";
import { validateMode } from "../modes.js";
import type { BlockResult, MiddlewareOptions } from "../types.js";

export const DEFAULT_V4_MAX_BUFFERED_BYTES = 1_048_576;
export const DEFAULT_V4_MAX_BUFFERED_PARTS = 10_000;

export class VercelV4BufferLimitError extends Error {
  constructor(limitName: "bytes" | "parts", limit: number) {
    super(`Silmaril Vercel v4 middleware exceeded its ${limitName} buffer limit (${limit})`);
    this.name = "VercelV4BufferLimitError";
  }
}

export interface VercelV4MiddlewareOptions extends MiddlewareOptions {
  /**
   * Maximum estimated bytes retained while Block-mode output is awaiting a
   * verdict. Circular or otherwise non-serializable parts fail closed.
   */
  maxBufferedBytes?: number;
  /** Maximum retained stream parts and distinct content IDs. */
  maxBufferedParts?: number;
}

interface V4ContentPart {
  readonly type: string;
  readonly text?: string;
  readonly toolCallId?: string;
  readonly toolName?: string;
  readonly input?: unknown;
  readonly output?: unknown;
}

interface V4PromptMessage {
  readonly role: string;
  readonly content: string | ReadonlyArray<V4ContentPart>;
}

interface V4CallOptions {
  readonly prompt: ReadonlyArray<V4PromptMessage>;
  readonly abortSignal?: AbortSignal;
}

interface V4GenerateResult {
  readonly content: ReadonlyArray<V4ContentPart>;
}

interface V4StreamPart {
  readonly type: string;
  readonly id?: string;
  readonly delta?: string;
  readonly toolName?: string;
  readonly toolCallId?: string;
  readonly input?: string;
  readonly inputEncoding?: "json" | "text";
  readonly error?: unknown;
}

interface V4StreamResult {
  readonly stream: ReadableStream<V4StreamPart>;
}

interface WrapGenerateArgs<TResult extends V4GenerateResult> {
  readonly params: V4CallOptions;
  readonly doGenerate: () => PromiseLike<TResult>;
}

interface WrapStreamArgs<TResult extends V4StreamResult> {
  readonly params: V4CallOptions;
  readonly doStream: () => PromiseLike<TResult>;
}

export interface FirewallMiddlewareV4 {
  readonly specificationVersion: "v4";
  readonly wrapGenerate: <TResult extends V4GenerateResult>(
    args: WrapGenerateArgs<TResult>,
  ) => Promise<TResult>;
  readonly wrapStream: <TResult extends V4StreamResult>(
    args: WrapStreamArgs<TResult>,
  ) => Promise<TResult>;
}

interface StepContext {
  readonly toolName?: string;
  readonly toolCallId?: string;
}

interface QueueEntry {
  readonly part: V4StreamPart;
  readonly size: number;
  status: "pending" | "approved" | "dropped";
  replacement?: V4StreamPart;
}

interface StreamSegment {
  readonly id: string;
  readonly order: number;
  readonly entries: QueueEntry[];
  readonly deltas: string[];
  byteLength: number;
}

interface ToolStreamSegment extends StreamSegment {
  readonly toolName: string;
  readonly inputEncoding: "json" | "text";
}

interface CompletedToolStream {
  blocked: boolean;
  readonly toolName: string;
  readonly inputEncoding: "json" | "text";
  inputFingerprint: string;
  finalSeen: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringifyValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function stringifyToolResult(output: unknown): string {
  if (!isRecord(output) || typeof output.type !== "string") {
    return stringifyValue(output);
  }
  if (
    (output.type === "text" || output.type === "error-text")
    && typeof output.value === "string"
  ) {
    return output.value;
  }
  if (
    (output.type === "json" || output.type === "error-json")
    && output.value !== undefined
  ) {
    return stringifyValue(output.value);
  }
  if (output.type === "content" && Array.isArray(output.value)) {
    return output.value
      .map((part) =>
        isRecord(part) && part.type === "text" && typeof part.text === "string"
          ? part.text
          : ""
      )
      .filter(Boolean)
      .join(" ");
  }
  if (output.type === "execution-denied" && typeof output.reason === "string") {
    return output.reason;
  }
  return "";
}

function promptText(message: V4PromptMessage): string {
  if (typeof message.content === "string") return message.content;
  return message.content
    .filter((part) => part.type === "text" && typeof part.text === "string")
    .map((part) => part.text)
    .join("");
}

function promptToolResults(
  message: V4PromptMessage,
): Array<{ text: string; toolName: string; toolCallId: string }> {
  if (typeof message.content === "string") return [];
  const results: Array<{ text: string; toolName: string; toolCallId: string }> = [];
  for (const part of message.content) {
    if (
      part.type !== "tool-result"
      || typeof part.toolName !== "string"
      || typeof part.toolCallId !== "string"
    ) {
      continue;
    }
    const text = stringifyToolResult(part.output);
    if (text.trim()) {
      results.push({
        text,
        toolName: part.toolName,
        toolCallId: part.toolCallId,
      });
    }
  }
  return results;
}

function validatePositiveLimit(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return resolved;
}

function encodedLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

async function inputFingerprint(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

function finalInputBytes(segment: ToolStreamSegment): string {
  const input = segment.deltas.join("");
  return segment.inputEncoding === "text" ? JSON.stringify(input) : input;
}

function estimatedPartSize(part: V4StreamPart, maximum: number): number {
  try {
    const serialized = JSON.stringify(part);
    if (serialized === undefined) return 64;
    return Math.min(encodedLength(serialized), maximum + 1);
  } catch {
    return maximum + 1;
  }
}

/**
 * Create an AI SDK 7 `LanguageModelV4Middleware`.
 *
 * Reasoning parts are passed through unchanged and are intentionally not
 * classified. Text and tool inputs are classified. In possible Block mode,
 * their original stream parts are held until a complete verdict is available.
 */
export function createMiddlewareV4(
  firewall: Firewall,
  options: VercelV4MiddlewareOptions = {},
): FirewallMiddlewareV4 {
  const scanInput = options.scanInput ?? true;
  const scanOutput = options.scanOutput ?? false;
  const scanToolCalls = options.scanToolCalls ?? false;
  const requestedMode = validateMode(options.mode) ?? (
    options.shadowMode === undefined
      ? firewall.mode
      : options.shadowMode ? "shadow" : "block"
  );
  const possibleBlock = requestedMode === undefined || requestedMode === "block";
  const maxBufferedBytes = validatePositiveLimit(
    options.maxBufferedBytes,
    DEFAULT_V4_MAX_BUFFERED_BYTES,
    "maxBufferedBytes",
  );
  const maxBufferedParts = validatePositiveLimit(
    options.maxBufferedParts,
    DEFAULT_V4_MAX_BUFFERED_PARTS,
    "maxBufferedParts",
  );

  const classifyOrBlock = async (
    text: string,
    hook: HookLabel,
    context: StepContext = {},
    signal?: AbortSignal,
  ): Promise<void> => {
    if (!text.trim()) return;
    const result: BlockResult = await firewall.classify(text, {
      hook,
      ...(context.toolName === undefined ? {} : { toolName: context.toolName }),
      ...(requestedMode === undefined ? {} : { mode: requestedMode }),
      ...(signal === undefined ? {} : { signal }),
    });
    const blocked =
      result.prediction === "MALICIOUS" || result.governance?.action === "block";
    const effectiveMode = requestedMode ?? result.mode ?? "block";
    const event = {
      hook,
      ...(context.toolName === undefined ? {} : { toolName: context.toolName }),
      ...(context.toolCallId === undefined ? {} : { toolCallId: context.toolCallId }),
      text,
      result,
      blocked,
      mode: effectiveMode,
      shadowMode: effectiveMode === "shadow",
    };
    options.onClassify?.(event);
    if (!blocked || effectiveMode !== "block") return;

    const error = new FirewallBlockedException({
      score: result.score,
      threshold: result.threshold,
      promptText: text,
      hook,
      ...(context.toolName === undefined ? {} : { toolName: context.toolName }),
      ...(context.toolCallId === undefined ? {} : { toolCallId: context.toolCallId }),
      result,
    });
    options.onBlocked?.(error);
    throw error;
  };

  const scanPrompt = async (
    prompt: ReadonlyArray<V4PromptMessage>,
    signal?: AbortSignal,
  ): Promise<void> => {
    // A tool turn can contain several adjacent tool messages. Scan every result
    // in that latest turn while retaining each call's name and ID.
    const toolTurnResults: Array<{
      text: string;
      toolName: string;
      toolCallId: string;
    }> = [];
    for (let index = prompt.length - 1; index >= 0; index--) {
      const message = prompt[index]!;
      const results = promptToolResults(message);
      toolTurnResults.unshift(...results);
      if (message.role.toLowerCase() !== "tool") break;
    }
    if (toolTurnResults.length > 0) {
      for (const result of toolTurnResults) {
        await classifyOrBlock(result.text, HookLabel.TOOL_RESPONSE, result, signal);
      }
      return;
    }

    for (let index = prompt.length - 1; index >= 0; index--) {
      const message = prompt[index]!;
      if (message.role.toLowerCase() !== "user") continue;
      const text = promptText(message);
      if (text.trim()) {
        await classifyOrBlock(text, HookLabel.USER_INPUT, {}, signal);
      }
      return;
    }
  };

  const scanGenerateResult = async (
    result: V4GenerateResult,
    signal?: AbortSignal,
  ): Promise<void> => {
    let text = "";
    const flushText = async (): Promise<void> => {
      if (scanOutput && text) {
        await classifyOrBlock(text, HookLabel.LLM_OUTPUT, {}, signal);
      }
      text = "";
    };
    for (const part of result.content) {
      if (part.type === "text" && typeof part.text === "string") {
        text += part.text;
        continue;
      }
      if (
        scanToolCalls
        && part.type === "tool-call"
        && typeof part.toolName === "string"
        && typeof part.toolCallId === "string"
      ) {
        await flushText();
        const input = typeof part.input === "string"
          ? part.input
          : stringifyValue(part.input);
        await classifyOrBlock(input, HookLabel.TOOL_CALL, {
          toolName: part.toolName,
          toolCallId: part.toolCallId,
        }, signal);
      }
    }
    await flushText();
  };

  return {
    specificationVersion: "v4",

    async wrapGenerate<TResult extends V4GenerateResult>({
      params,
      doGenerate,
    }: WrapGenerateArgs<TResult>): Promise<TResult> {
      if (scanInput) await scanPrompt(params.prompt, params.abortSignal);
      const result = await doGenerate();
      await scanGenerateResult(result, params.abortSignal);
      return result;
    },

    async wrapStream<TResult extends V4StreamResult>({
      params,
      doStream,
    }: WrapStreamArgs<TResult>): Promise<TResult> {
      if (scanInput) await scanPrompt(params.prompt, params.abortSignal);
      const result = await doStream();

      if (!scanOutput && !scanToolCalls) return result;

      const textStreams = new Map<string, StreamSegment>();
      const toolStreams = new Map<string, ToolStreamSegment>();
      const completedTextIds = new Set<string>();
      const completedToolIds = new Map<string, CompletedToolStream>();
      const queue: QueueEntry[] = [];
      let queueHead = 0;
      let queuedBytes = 0;
      let activeBytes = 0;
      let distinctIds = 0;
      let nextSegmentOrder = 0;

      const registerId = (): void => {
        distinctIds++;
        if (distinctIds > maxBufferedParts) {
          throw new VercelV4BufferLimitError("parts", maxBufferedParts);
        }
      };

      const checkActiveBytes = (additional: number): void => {
        activeBytes += additional;
        if (activeBytes > maxBufferedBytes) {
          throw new VercelV4BufferLimitError("bytes", maxBufferedBytes);
        }
      };

      const hold = (
        part: V4StreamPart,
        status: QueueEntry["status"],
      ): QueueEntry => {
        const size = estimatedPartSize(part, maxBufferedBytes);
        if (queue.length - queueHead + 1 > maxBufferedParts) {
          throw new VercelV4BufferLimitError("parts", maxBufferedParts);
        }
        if (queuedBytes + size > maxBufferedBytes) {
          throw new VercelV4BufferLimitError("bytes", maxBufferedBytes);
        }
        const entry: QueueEntry = { part, size, status };
        queue.push(entry);
        queuedBytes += size;
        return entry;
      };

      const emitOrHold = (
        part: V4StreamPart,
        pending: boolean,
        controller: TransformStreamDefaultController<V4StreamPart>,
      ): QueueEntry | undefined => {
        if (!possibleBlock) {
          controller.enqueue(part);
          return undefined;
        }
        return hold(part, pending ? "pending" : "approved");
      };

      const drain = (
        controller: TransformStreamDefaultController<V4StreamPart>,
      ): void => {
        while (queueHead < queue.length) {
          const entry = queue[queueHead]!;
          if (entry.status === "pending") break;
          queueHead++;
          queuedBytes -= entry.size;
          if (entry.replacement !== undefined) {
            controller.enqueue(entry.replacement);
          } else if (entry.status === "approved") {
            controller.enqueue(entry.part);
          }
        }
        if (queueHead === queue.length) {
          queue.length = 0;
          queueHead = 0;
        }
      };

      const resolveSegment = (
        segment: StreamSegment,
        error: FirewallBlockedException | undefined,
      ): void => {
        activeBytes -= segment.byteLength;
        if (!possibleBlock) return;
        for (const entry of segment.entries) {
          entry.status = error === undefined ? "approved" : "dropped";
        }
        if (error !== undefined && segment.entries.length > 0) {
          segment.entries[0]!.replacement = { type: "error", error };
        }
      };

      const classifyTextSegment = async (
        segment: StreamSegment,
      ): Promise<boolean> => {
        try {
          await classifyOrBlock(
            segment.deltas.join(""),
            HookLabel.LLM_OUTPUT,
            {},
            params.abortSignal,
          );
          resolveSegment(segment, undefined);
          return false;
        } catch (error) {
          if (!(error instanceof FirewallBlockedException)) throw error;
          resolveSegment(segment, error);
          return true;
        }
      };

      const classifyToolSegment = async (
        segment: ToolStreamSegment,
      ): Promise<{ blocked: boolean; fingerprint: string }> => {
        const input = segment.deltas.join("");
        const fingerprint = await inputFingerprint(finalInputBytes(segment));
        try {
          await classifyOrBlock(
            input,
            HookLabel.TOOL_CALL,
            { toolName: segment.toolName, toolCallId: segment.id },
            params.abortSignal,
          );
          resolveSegment(segment, undefined);
          return { blocked: false, fingerprint };
        } catch (error) {
          if (!(error instanceof FirewallBlockedException)) throw error;
          resolveSegment(segment, error);
          return { blocked: true, fingerprint };
        }
      };

      const finalizeActive = async (): Promise<void> => {
        const active = [
          ...Array.from(textStreams, ([id, segment]) => ({
            kind: "text" as const,
            id,
            segment,
          })),
          ...Array.from(toolStreams, ([id, segment]) => ({
            kind: "tool" as const,
            id,
            segment,
          })),
        ].sort((left, right) => left.segment.order - right.segment.order);
        for (const item of active) {
          if (item.kind === "text") {
            await classifyTextSegment(item.segment);
            textStreams.delete(item.id);
            completedTextIds.add(item.id);
          } else {
            const verdict = await classifyToolSegment(item.segment);
            toolStreams.delete(item.id);
            completedToolIds.set(item.id, {
              blocked: verdict.blocked,
              toolName: item.segment.toolName,
              inputEncoding: item.segment.inputEncoding,
              inputFingerprint: verdict.fingerprint,
              finalSeen: false,
            });
          }
        }
      };

      const transformed = result.stream.pipeThrough(
        new TransformStream<V4StreamPart, V4StreamPart>({
          async transform(part, controller): Promise<void> {
            params.abortSignal?.throwIfAborted();

            if (part.type === "finish") {
              await finalizeActive();
              emitOrHold(part, false, controller);
              drain(controller);
              return;
            }

            if (scanOutput && part.type === "text-start") {
              if (
                typeof part.id !== "string"
                || textStreams.has(part.id)
                || completedTextIds.has(part.id)
              ) {
                throw new Error("Invalid AI SDK v4 text-start stream identity");
              }
              registerId();
              const entry = emitOrHold(part, true, controller);
              textStreams.set(part.id, {
                id: part.id,
                order: nextSegmentOrder++,
                entries: entry === undefined ? [] : [entry],
                deltas: [],
                byteLength: 0,
              });
              drain(controller);
              return;
            }

            if (scanOutput && part.type === "text-delta") {
              if (typeof part.id !== "string" || typeof part.delta !== "string") {
                throw new Error("Invalid AI SDK v4 text-delta stream part");
              }
              const segment = textStreams.get(part.id);
              if (segment === undefined) {
                throw new Error("AI SDK v4 text-delta has no matching text-start");
              }
              const bytes = encodedLength(part.delta);
              checkActiveBytes(bytes);
              segment.byteLength += bytes;
              segment.deltas.push(part.delta);
              const entry = emitOrHold(part, true, controller);
              if (entry !== undefined) segment.entries.push(entry);
              drain(controller);
              return;
            }

            if (scanOutput && part.type === "text-end") {
              if (typeof part.id !== "string") {
                throw new Error("Invalid AI SDK v4 text-end stream identity");
              }
              const segment = textStreams.get(part.id);
              if (segment === undefined) {
                throw new Error("AI SDK v4 text-end has no matching text-start");
              }
              const entry = emitOrHold(part, true, controller);
              if (entry !== undefined) segment.entries.push(entry);
              textStreams.delete(part.id);
              const blocked = await classifyTextSegment(segment);
              completedTextIds.add(part.id);
              void blocked;
              drain(controller);
              return;
            }

            if (scanToolCalls && part.type === "tool-input-start") {
              if (
                typeof part.id !== "string"
                || typeof part.toolName !== "string"
                || toolStreams.has(part.id)
                || completedToolIds.has(part.id)
              ) {
                throw new Error("Invalid AI SDK v4 tool-input-start stream identity");
              }
              registerId();
              const entry = emitOrHold(part, true, controller);
              toolStreams.set(part.id, {
                id: part.id,
                order: nextSegmentOrder++,
                toolName: part.toolName,
                inputEncoding: part.inputEncoding ?? "json",
                entries: entry === undefined ? [] : [entry],
                deltas: [],
                byteLength: 0,
              });
              drain(controller);
              return;
            }

            if (scanToolCalls && part.type === "tool-input-delta") {
              if (typeof part.id !== "string" || typeof part.delta !== "string") {
                throw new Error("Invalid AI SDK v4 tool-input-delta stream part");
              }
              const segment = toolStreams.get(part.id);
              if (segment === undefined) {
                throw new Error("AI SDK v4 tool-input-delta has no matching tool-input-start");
              }
              const bytes = encodedLength(part.delta);
              checkActiveBytes(bytes);
              segment.byteLength += bytes;
              segment.deltas.push(part.delta);
              const entry = emitOrHold(part, true, controller);
              if (entry !== undefined) segment.entries.push(entry);
              drain(controller);
              return;
            }

            if (scanToolCalls && part.type === "tool-input-end") {
              if (typeof part.id !== "string") {
                throw new Error("Invalid AI SDK v4 tool-input-end stream identity");
              }
              const segment = toolStreams.get(part.id);
              if (segment === undefined) {
                throw new Error("AI SDK v4 tool-input-end has no matching tool-input-start");
              }
              const entry = emitOrHold(part, true, controller);
              if (entry !== undefined) segment.entries.push(entry);
              toolStreams.delete(part.id);
              const verdict = await classifyToolSegment(segment);
              completedToolIds.set(part.id, {
                blocked: verdict.blocked,
                toolName: segment.toolName,
                inputEncoding: segment.inputEncoding,
                inputFingerprint: verdict.fingerprint,
                finalSeen: false,
              });
              drain(controller);
              return;
            }

            if (scanToolCalls && part.type === "tool-call") {
              if (
                typeof part.toolCallId !== "string"
                || typeof part.toolName !== "string"
                || typeof part.input !== "string"
              ) {
                throw new Error("Invalid AI SDK v4 tool-call stream part");
              }
              if (toolStreams.has(part.toolCallId)) {
                throw new Error("AI SDK v4 tool-call arrived before tool-input-end");
              }
              const completed = completedToolIds.get(part.toolCallId);
              if (completed !== undefined) {
                if (completed.toolName !== part.toolName) {
                  throw new Error("AI SDK v4 tool-call name does not match its streamed input ID");
                }
                if (completed.finalSeen) {
                  throw new Error("AI SDK v4 tool-call repeated a completed streamed input ID");
                }
                completed.finalSeen = true;
                if (completed.blocked) {
                  drain(controller);
                  return;
                }
                const actualFingerprint = await inputFingerprint(part.input);
                if (actualFingerprint === completed.inputFingerprint) {
                  emitOrHold(part, false, controller);
                  drain(controller);
                  return;
                }

                const bytes = encodedLength(part.input);
                checkActiveBytes(bytes);
                const entry = emitOrHold(part, true, controller);
                const changedSegment: ToolStreamSegment = {
                  id: part.toolCallId,
                  order: nextSegmentOrder++,
                  toolName: part.toolName,
                  inputEncoding: "json",
                  entries: entry === undefined ? [] : [entry],
                  deltas: [part.input],
                  byteLength: bytes,
                };
                const changedVerdict = await classifyToolSegment(changedSegment);
                completed.blocked = changedVerdict.blocked;
                completed.inputFingerprint = changedVerdict.fingerprint;
                drain(controller);
                return;
              }

              registerId();
              const bytes = encodedLength(part.input);
              checkActiveBytes(bytes);
              const entry = emitOrHold(part, true, controller);
              const segment: ToolStreamSegment = {
                id: part.toolCallId,
                order: nextSegmentOrder++,
                toolName: part.toolName,
                inputEncoding: "json",
                entries: entry === undefined ? [] : [entry],
                deltas: [part.input],
                byteLength: bytes,
              };
              const verdict = await classifyToolSegment(segment);
              completedToolIds.set(part.toolCallId, {
                blocked: verdict.blocked,
                toolName: part.toolName,
                inputEncoding: segment.inputEncoding,
                inputFingerprint: verdict.fingerprint,
                finalSeen: true,
              });
              drain(controller);
              return;
            }

            emitOrHold(part, false, controller);
            drain(controller);
          },

          async flush(controller): Promise<void> {
            params.abortSignal?.throwIfAborted();
            await finalizeActive();
            drain(controller);
            if (queueHead !== queue.length) {
              throw new Error("Silmaril Vercel v4 middleware retained unresolved stream parts");
            }
          },
        }),
      );

      return Object.assign({}, result, { stream: transformed });
    },
  };
}
