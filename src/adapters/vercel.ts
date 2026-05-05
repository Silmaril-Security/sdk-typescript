// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type { Firewall } from "../firewall.js";
import { PromptBlockedException } from "../exceptions.js";
import { HookLabel } from "../hooks.js";
import type { BlockResult, MiddlewareOptions } from "../types.js";

interface VercelContentPart {
  type?: string;
  text?: string;
  toolCallId?: string;
  toolName?: string;
  args?: unknown;
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
}

interface VercelGenerateResult {
  text?: string;
  toolCalls?: ReadonlyArray<VercelToolCall>;
}

interface WrapGenerateArgs<TResult extends VercelGenerateResult & Record<string, unknown>> {
  params: { prompt: ReadonlyArray<VercelPromptMessage> } & Record<string, unknown>;
  doGenerate: () => PromiseLike<TResult>;
}

interface WrapStreamArgs<
  TResult extends { stream: ReadableStream<unknown> } & Record<string, unknown>,
> {
  params: { prompt: ReadonlyArray<VercelPromptMessage> } & Record<string, unknown>;
  doStream: () => PromiseLike<TResult>;
}

interface StreamPart {
  type?: string;
  textDelta?: string;
  delta?: string;
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
): Array<{ text: string; toolName: string | undefined }> {
  if (typeof message.content === "string") {
    return [];
  }
  const out: Array<{ text: string; toolName: string | undefined }> = [];
  for (const part of message.content) {
    if (typeof part === "string") {
      continue;
    }
    if (part.type === "tool-result") {
      const text = stringifyToolValue(part.result);
      if (text.trim()) {
        out.push({ text, toolName: part.toolName });
      }
    }
  }
  return out;
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
  const overrideThreshold = options.threshold;
  const overrideHookThresholds = options.hookThresholds ?? {};
  const shadowMode = options.shadowMode ?? firewall.shadowMode;

  const effectiveThreshold = (label: HookLabel): number => {
    if (overrideHookThresholds[label] !== undefined) {
      return overrideHookThresholds[label] as number;
    }
    if (firewall.hookThresholds[label] !== undefined) {
      return firewall.hookThresholds[label] as number;
    }
    return overrideThreshold ?? firewall.threshold;
  };

  const classifyOrBlock = async (
    text: string,
    hook: HookLabel,
    toolName?: string,
  ): Promise<void> => {
    if (!text.trim()) {
      return;
    }
    const result: BlockResult = await firewall.classify(
      text,
      toolName !== undefined ? { hook, toolName } : { hook },
    );
    const threshold = effectiveThreshold(hook);
    const blocked = result.score >= threshold;
    options.onClassify?.({
      hook,
      ...(toolName !== undefined ? { toolName } : {}),
      text,
      result,
      blocked,
      shadowMode,
    });
    if (blocked && !shadowMode) {
      const err = new PromptBlockedException({
        score: result.score,
        threshold,
        promptText: text,
      });
      options.onBlocked?.(err);
      throw err;
    }
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
      for (const { text, toolName } of iterateToolResultParts(last)) {
        await classifyOrBlock(text, HookLabel.TOOL_RESPONSE, toolName);
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
        const args =
          typeof call.args === "string" ? call.args : stringifyToolValue(call.args);
        const toolName = typeof call.toolName === "string" ? call.toolName : undefined;
        if (args.trim()) {
          await classifyOrBlock(args, HookLabel.TOOL_CALL, toolName);
        }
      }
    }
  };

  return {
    async wrapGenerate<TResult extends VercelGenerateResult & Record<string, unknown>>({
      params,
      doGenerate,
    }: WrapGenerateArgs<TResult>): Promise<TResult> {
      if (scanInput) {
        await scanPrompt(params.prompt);
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
        await scanPrompt(params.prompt);
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
              if (err instanceof PromptBlockedException) {
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
