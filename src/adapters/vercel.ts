// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type { Firewall } from "../firewall.js";
import { FirewallBlockedException } from "../exceptions.js";
import { HookLabel } from "../hooks.js";
import type { BlockResult, MiddlewareOptions } from "../types.js";

interface VercelContentPart {
  type?: string;
  text?: string;
  toolCallId?: string;
  toolName?: string;
  args?: unknown;
  output?: unknown;
  result?: unknown;
}

interface VercelPromptMessage {
  role: string;
  content: string | ReadonlyArray<VercelContentPart | string>;
}

interface VercelToolCall {
  toolCallType?: string;
  toolCallId?: string;
  toolName?: string;
  args?: unknown;
  input?: unknown;
}

interface VercelGenerateResult {
  text?: string;
  toolCalls?: ReadonlyArray<VercelToolCall>;
}

interface WrapGenerateArgs<TResult extends VercelGenerateResult & Record<string, unknown>> {
  params: { prompt?: ReadonlyArray<VercelPromptMessage> } & Record<string, unknown>;
  doGenerate: () => PromiseLike<TResult>;
}

interface WrapStreamArgs<
  TResult extends { stream: ReadableStream<unknown> } & Record<string, unknown>,
> {
  params: { prompt?: ReadonlyArray<VercelPromptMessage> } & Record<string, unknown>;
  doStream: () => PromiseLike<TResult>;
}

interface StreamPart {
  type?: string;
  textDelta?: string;
  delta?: string;
}

interface VercelStepContext {
  toolName: string | undefined;
  toolCallId: string | undefined;
}

function stringifyToolValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractContentText(content: VercelPromptMessage["content"]): string {
  if (typeof content === "string") {
    return content;
  }
  const parts: string[] = [];
  for (const block of content) {
    if (typeof block === "string") {
      parts.push(block);
    } else if (block && block.type === "text") {
      parts.push(block.text ?? "");
    }
  }
  return parts.join(" ");
}

function iterateToolResultParts(
  message: VercelPromptMessage,
): Array<{ text: string; toolName: string | undefined; toolCallId: string | undefined }> {
  if (typeof message.content === "string") {
    return [];
  }
  const out: Array<{ text: string; toolName: string | undefined; toolCallId: string | undefined }> = [];
  for (const part of message.content) {
    if (typeof part === "string") {
      continue;
    }
    if (part.type === "tool-result") {
      const text = stringifyToolResult(part.result !== undefined ? part.result : part.output);
      if (text.trim()) {
        out.push({ text, toolName: part.toolName, toolCallId: part.toolCallId });
      }
    }
  }
  return out;
}

function stringifyToolResult(value: unknown): string {
  if (!isRecord(value)) {
    return stringifyToolValue(value);
  }
  if ((value.type === "text" || value.type === "error-text") && typeof value.value === "string") {
    return value.value;
  }
  if ((value.type === "json" || value.type === "error-json") && value.value !== undefined) {
    return stringifyToolValue(value.value);
  }
  if (value.type === "content" && Array.isArray(value.value)) {
    return value.value
      .map((part) => (isRecord(part) && part.type === "text" && typeof part.text === "string" ? part.text : ""))
      .filter((text) => text.length > 0)
      .join(" ");
  }
  return stringifyToolValue(value);
}

function findLastUserMessage(
  messages: ReadonlyArray<VercelPromptMessage>,
): VercelPromptMessage | undefined {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i]!;
    if (msg.role.toLowerCase() === "user") {
      return msg;
    }
  }
  return undefined;
}

export interface FirewallMiddleware {
  readonly specificationVersion: "v3";
  readonly middlewareVersion: "v2";
  wrapGenerate: <TResult extends VercelGenerateResult & Record<string, unknown>>(
    args: WrapGenerateArgs<TResult>,
  ) => Promise<TResult>;
  wrapStream: <TResult extends { stream: ReadableStream<unknown> } & Record<string, unknown>>(
    args: WrapStreamArgs<TResult>,
  ) => Promise<TResult>;
}

export function createMiddleware(
  firewall: Firewall,
  options: MiddlewareOptions = {},
): FirewallMiddleware {
  const scanInput = options.scanInput ?? true;
  const scanOutput = options.scanOutput ?? false;
  const shadowMode = options.shadowMode ?? firewall.shadowMode;

  const classifyOrBlock = async (
    text: string,
    hook: HookLabel,
    context: VercelStepContext = { toolName: undefined, toolCallId: undefined },
  ): Promise<void> => {
    if (!text.trim()) {
      return;
    }
    const { toolName, toolCallId } = context;
    const result: BlockResult = await firewall.classify(
      text,
      toolName !== undefined ? { hook, toolName } : { hook },
    );
    const threshold = result.threshold;
    const blocked = result.score >= threshold;
    const commonEventFields = {
      hook,
      ...(toolName !== undefined ? { toolName } : {}),
      ...(toolCallId !== undefined ? { toolCallId } : {}),
      text,
      result,
    };
    options.onClassify?.({
      ...commonEventFields,
      blocked,
      shadowMode,
    });
    if (!blocked || shadowMode) {
      return;
    }

    const err = new FirewallBlockedException({
      score: result.score,
      threshold,
      promptText: text,
      hook,
      ...(toolName !== undefined ? { toolName } : {}),
      ...(toolCallId !== undefined ? { toolCallId } : {}),
      result,
    });
    options.onBlocked?.(err);
    throw err;
  };

  const scanPrompt = async (prompt: ReadonlyArray<VercelPromptMessage>): Promise<void> => {
    if (prompt.length === 0) {
      return;
    }
    const last = prompt[prompt.length - 1]!;
    const role = last.role.toLowerCase();

    // If the newest message is a tool result (typical mid-flow in a
    // tool-calling loop), classify each tool-result part individually with
    // tool_response + toolName. No manual wiring from the caller — the
    // toolName is read directly from the Vercel content part.
    if (role === "tool") {
      for (const { text, toolName, toolCallId } of iterateToolResultParts(last)) {
        await classifyOrBlock(text, HookLabel.TOOL_RESPONSE, { toolName, toolCallId });
      }
      return;
    }

    // Otherwise, fall back to scanning the most recent user message.
    // Covers: [user], [system, user], [user, assistant(text), user], etc.
    const lastUser = findLastUserMessage(prompt);
    if (!lastUser) {
      return;
    }
    const text = extractContentText(lastUser.content).trim();
    if (!text) {
      return;
    }
    await classifyOrBlock(text, HookLabel.USER_INPUT);
  };

  const scanGenerateResult = async (result: VercelGenerateResult): Promise<void> => {
    if (scanOutput && typeof result.text === "string" && result.text.length > 0) {
      await classifyOrBlock(result.text, HookLabel.LLM_OUTPUT);
    }
    if (options.scanToolCalls && Array.isArray(result.toolCalls)) {
      for (const call of result.toolCalls) {
        if (!call || typeof call !== "object") {
          continue;
        }
        const toolInput = call.args !== undefined ? call.args : call.input;
        const args =
          typeof toolInput === "string" ? toolInput : stringifyToolValue(toolInput);
        const toolName = typeof call.toolName === "string" ? call.toolName : undefined;
        const toolCallId = typeof call.toolCallId === "string" ? call.toolCallId : undefined;
        if (args.trim()) {
          await classifyOrBlock(args, HookLabel.TOOL_CALL, { toolName, toolCallId });
        }
      }
    }
  };

  return {
    specificationVersion: "v3",
    middlewareVersion: "v2",

    async wrapGenerate<TResult extends VercelGenerateResult & Record<string, unknown>>({
      params,
      doGenerate,
    }: WrapGenerateArgs<TResult>): Promise<TResult> {
      if (scanInput) {
        await scanPrompt(params.prompt ?? []);
      }
      const result = await doGenerate();
      await scanGenerateResult(result);
      return result;
    },

    async wrapStream<TResult extends { stream: ReadableStream<unknown> } & Record<string, unknown>>({
      params,
      doStream,
    }: WrapStreamArgs<TResult>): Promise<TResult> {
      if (scanInput) {
        await scanPrompt(params.prompt ?? []);
      }
      const { stream, ...rest } = await doStream();
      if (!scanOutput) {
        return { stream, ...rest } as unknown as TResult;
      }

      let buffered = "";
      const transformed = stream.pipeThrough(
        new TransformStream<unknown, unknown>({
          transform(chunk, controller): void {
            const part = chunk as StreamPart;
            if (part && part.type === "text-delta") {
              const delta = part.textDelta ?? part.delta ?? "";
              buffered += delta;
            }
            controller.enqueue(chunk);
          },
          async flush(controller): Promise<void> {
            if (!buffered.trim()) {
              return;
            }
            try {
              await classifyOrBlock(buffered, HookLabel.LLM_OUTPUT);
            } catch (err) {
              if (err instanceof FirewallBlockedException) {
                controller.enqueue({ type: "error", error: err });
                return;
              }
              throw err;
            }
          },
        }),
      );
      return { stream: transformed, ...rest } as unknown as TResult;
    },
  };
}
