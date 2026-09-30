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

export function createDeepAgentsMiddleware(firewall: Firewall, options: DeepAgentsMiddlewareOptions = {}) {
  const maxBlockedAttempts = options.maxBlockedAttempts ?? 3;
  if (!Number.isInteger(maxBlockedAttempts) || maxBlockedAttempts < 1) {
    throw new Error("maxBlockedAttempts must be a positive integer");
  }
  const effectiveMode = options.mode ?? firewall.mode;
  const classify = async (text: string, hook: HookLabel, toolName?: string): Promise<boolean> => {
    if (!text.trim()) return false;
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
      return blocked && mode === "block";
    } catch (error) {
      if (options.failOpen === false) throw error;
      return false;
    }
  };

  return createMiddleware({
    name: "SilmarilDeepAgentsMiddleware",
    wrapModelCall: async (request, handler) => {
      const blockedCount = request.state.messages.filter(
        (message) => ToolMessage.isInstance(message) && message.content === SAFE_TOOL_MESSAGE,
      ).length;
      if (blockedCount >= maxBlockedAttempts) return new AIMessage(SAFE_FINAL_MESSAGE);
      const last = request.messages.at(-1);
      if (last && HumanMessage.isInstance(last) && await classify(textOf(last), HookLabel.USER_INPUT)) {
        return new AIMessage(SAFE_OUTPUT_MESSAGE);
      }
      const response = await handler(request);
      if (response instanceof Command && await classify(JSON.stringify(response.update), HookLabel.LLM_OUTPUT)) {
        return new AIMessage(SAFE_OUTPUT_MESSAGE);
      }
      if (AIMessage.isInstance(response) && await classify(textOf(response), HookLabel.LLM_OUTPUT)) {
        return new AIMessage(SAFE_OUTPUT_MESSAGE);
      }
      return response;
    },
    wrapToolCall: async (request, handler) => {
      const safe = () => new ToolMessage({
        content: SAFE_TOOL_MESSAGE,
        tool_call_id: request.toolCall.id ?? "",
        name: request.toolCall.name,
      });
      if (await classify(JSON.stringify(request.toolCall.args ?? {}), HookLabel.TOOL_CALL, request.toolCall.name)) {
        return safe();
      }
      const result = await handler(request);
      if (await classify(ToolMessage.isInstance(result) ? textOf(result) : String(result), HookLabel.TOOL_RESPONSE, request.toolCall.name)) {
        return safe();
      }
      return result;
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
