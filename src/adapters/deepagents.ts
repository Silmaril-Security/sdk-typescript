// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

/** Optional Deep Agents integration. Import from @silmaril-security/sdk/adapters/deepagents. */
import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { Command } from "@langchain/langgraph";
import { createDeepAgent, GENERAL_PURPOSE_SUBAGENT, type AnySubAgent, type CompiledSubAgent } from "deepagents";
import { createAgent, createMiddleware, type CreateAgentParams } from "langchain";

import type { Firewall } from "../firewall.js";
import { HookLabel } from "../hooks.js";
import type { ClassifyEvent, FirewallMode } from "../types.js";

export const SAFE_TOOL_MESSAGE = "Silmaril Firewall blocked this tool interaction. Choose a different safe action.";
export const SAFE_FINAL_MESSAGE = "Silmaril Firewall stopped this request after repeated unsafe actions.";
export const SAFE_OUTPUT_MESSAGE = "Silmaril Firewall blocked this response.";
const BLOCKED_TOOL_MARKER = "silmaril-firewall:v1:blocked-tool";

// A protected graph is identified by the exact runnable returned by our factory.
const protectedCompiledGraphs = new WeakMap<object, Firewall>();

export interface DeepAgentsMiddlewareOptions {
  mode?: FirewallMode;
  failOpen?: boolean;
  maxBlockedAttempts?: number;
  /** A caller-supplied sequence identity; never derived from a LangChain run ID. */
  conversationId?: string;
  onClassify?: (event: ClassifyEvent) => void;
}

function textOf(message: { content: unknown }): string {
  return typeof message.content === "string" ? message.content : JSON.stringify(message.content);
}

function textOfStructuredValue(value: unknown, seen = new WeakSet<object>()): string {
  if (value == null) return "";
  if (typeof value !== "object") return String(value);
  if (seen.has(value)) return "[circular]";
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => textOfStructuredValue(item, seen)).join("\n");
  return Object.entries(value).map(([key, item]) => `${key}: ${textOfStructuredValue(item, seen)}`).join("\n");
}

function stripAllowedMarker(result: ToolMessage | Command): ToolMessage | Command {
  const strip = (message: ToolMessage): void => {
    if (message.additional_kwargs?.silmarilBlocked === BLOCKED_TOOL_MARKER) {
      delete message.additional_kwargs.silmarilBlocked;
    }
  };
  if (ToolMessage.isInstance(result)) strip(result);
  else if (result instanceof Command) {
    const update = result.update;
    if (update && !Array.isArray(update) && "messages" in update && Array.isArray(update.messages)) {
      for (const message of update.messages) {
        if (ToolMessage.isInstance(message)) strip(message);
      }
    }
  }
  return result;
}

export function createDeepAgentsMiddleware(firewall: Firewall, options: DeepAgentsMiddlewareOptions = {}) {
  const maxBlockedAttempts = options.maxBlockedAttempts ?? 3;
  if (!Number.isInteger(maxBlockedAttempts) || maxBlockedAttempts < 1) {
    throw new Error("maxBlockedAttempts must be a positive integer");
  }
  const effectiveMode = options.mode ?? firewall.mode;
  const classify = async (text: string, hook: HookLabel, toolName?: string): Promise<{ enforce: boolean; mode: FirewallMode | undefined }> => {
    if (!text.trim()) return { enforce: false, mode: effectiveMode };
    try {
      const result = await firewall.classify(text, {
        hook,
        ...(toolName === undefined ? {} : { toolName }),
        ...(effectiveMode === undefined ? {} : { mode: effectiveMode }),
        ...(options.conversationId === undefined ? {} : { metadata: { conversationId: options.conversationId } }),
      });
      const mode = effectiveMode ?? result.mode ?? "block";
      const blocked = result.prediction === "MALICIOUS" || result.governance?.action === "block";
      if (options.onClassify) {
        try {
          options.onClassify({ hook, ...(toolName === undefined ? {} : { toolName }), text, result, blocked, mode, shadowMode: mode === "shadow" });
        } catch {
          // Observation callbacks do not change enforcement.
        }
      }
      return { enforce: blocked && mode === "block", mode };
    } catch (error) {
      if (options.failOpen === false) throw error;
      return { enforce: false, mode: effectiveMode };
    }
  };

  return createMiddleware({
    name: "SilmarilDeepAgentsMiddleware",
    wrapModelCall: async (request, handler) => {
      const history = request.state.messages;
      let lastUserIndex = -1;
      for (let i = history.length - 1; i >= 0; i--) {
        if (HumanMessage.isInstance(history[i])) {
          lastUserIndex = i;
          break;
        }
      }
      const blockedCount = history.slice(lastUserIndex + 1).filter(
        (message) => ToolMessage.isInstance(message) && message.content === SAFE_TOOL_MESSAGE
          && message.additional_kwargs?.silmarilBlocked === BLOCKED_TOOL_MARKER,
      ).length;
      const latestUser = [...request.messages].reverse().find(HumanMessage.isInstance);
      const inputDecision = latestUser
        ? await classify(textOf(latestUser), HookLabel.USER_INPUT)
        : undefined;
      if (inputDecision?.enforce) return new AIMessage(SAFE_OUTPUT_MESSAGE);
      // The marker is added only after a Block decision, so neither an
      // unrelated input mode nor tool output that quotes the safe text affects the cap.
      if (blockedCount >= maxBlockedAttempts) {
        return new AIMessage(SAFE_FINAL_MESSAGE);
      }
      const response = await handler(request);
      if (response instanceof Command && (await classify(textOfStructuredValue(response.update), HookLabel.LLM_OUTPUT)).enforce) {
        return new AIMessage(SAFE_OUTPUT_MESSAGE);
      }
      if (AIMessage.isInstance(response) && (await classify(textOf(response), HookLabel.LLM_OUTPUT)).enforce) {
        return new AIMessage(SAFE_OUTPUT_MESSAGE);
      }
      return response;
    },
    wrapToolCall: async (request, handler) => {
      const safe = () => new ToolMessage({
        content: SAFE_TOOL_MESSAGE,
        tool_call_id: request.toolCall.id ?? "",
        name: request.toolCall.name,
        additional_kwargs: { silmarilBlocked: BLOCKED_TOOL_MARKER },
      });
      if ((await classify(JSON.stringify(request.toolCall.args ?? {}), HookLabel.TOOL_CALL, request.toolCall.name)).enforce) {
        return safe();
      }
      const result = await handler(request);
      let resultText: string;
      try {
        resultText = ToolMessage.isInstance(result) ? textOf(result)
          : result instanceof Command ? textOfStructuredValue(result.update) : String(result);
      } catch {
        // Content cannot be inspected, but the backend still resolves the
        // enforcement mode. Observation modes retain the original result.
        const decision = await classify("[uninspectable tool result]", HookLabel.TOOL_RESPONSE, request.toolCall.name);
        return decision.mode === "block" ? safe() : stripAllowedMarker(result);
      }
      if ((await classify(resultText, HookLabel.TOOL_RESPONSE, request.toolCall.name)).enforce) {
        return safe();
      }
      return stripAllowedMarker(result);
    },
  });
}

export interface ProtectedCompiledSubagentOptions extends Omit<CreateAgentParams, "middleware"> {
  name: string;
  description: string;
  middleware?: CreateAgentParams["middleware"];
  silmaril?: DeepAgentsMiddlewareOptions;
}

/** Compile a subagent with Silmaril middleware and register that exact graph. */
export function createProtectedCompiledSubagent(firewall: Firewall, options: ProtectedCompiledSubagentOptions): CompiledSubAgent {
  const { name, description, silmaril, middleware = [], ...agentOptions } = options;
  const runnable = createAgent({
    ...agentOptions,
    middleware: [...middleware, createDeepAgentsMiddleware(firewall, silmaril)] as const,
  });
  protectedCompiledGraphs.set(runnable, firewall);
  return { name, description, runnable };
}

export interface ProtectedDeepAgentOptions extends Omit<NonNullable<Parameters<typeof createDeepAgent>[0]>, "subagents" | "middleware"> {
  subagents?: readonly AnySubAgent[];
  /** Only pass specs returned by createProtectedCompiledSubagent for this client. */
  protectedCompiledSubagents?: readonly CompiledSubAgent[];
  middleware?: NonNullable<Parameters<typeof createDeepAgent>[0]>["middleware"];
  silmaril?: DeepAgentsMiddlewareOptions;
}

/** Protect root, default general-purpose, and declarative subagents. */
export function createProtectedDeepAgent(firewall: Firewall, options: ProtectedDeepAgentOptions = {}) {
  const { silmaril, subagents = [], protectedCompiledSubagents = [], middleware = [], ...agentOptions } = options;
  const protectedSubagents = subagents.map((subagent) => {
    if ("runnable" in subagent || "graphId" in subagent) {
      throw new Error("Compiled or remote subagents must install Silmaril middleware inside their own graph");
    }
    return { ...subagent, middleware: [...(subagent.middleware ?? []), createDeepAgentsMiddleware(firewall, silmaril)] };
  });
  if (!protectedSubagents.some((subagent) => subagent.name === GENERAL_PURPOSE_SUBAGENT.name)) {
    protectedSubagents.unshift({ ...GENERAL_PURPOSE_SUBAGENT, middleware: [createDeepAgentsMiddleware(firewall, silmaril)] });
  }
  for (const spec of protectedCompiledSubagents) {
    if (!spec.runnable || protectedCompiledGraphs.get(spec.runnable) !== firewall) {
      throw new Error("Compiled subagents must be built with createProtectedCompiledSubagent for this Firewall client");
    }
  }
  return createDeepAgent({
    ...agentOptions,
    middleware: [...middleware, createDeepAgentsMiddleware(firewall, silmaril)],
    subagents: [...protectedSubagents, ...protectedCompiledSubagents],
  });
}
