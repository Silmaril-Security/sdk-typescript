// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

/** Optional Deep Agents integration. Import from @silmaril-security/sdk/adapters/deepagents. */
import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { ensureConfig } from "@langchain/core/runnables";
import type { StructuredTool } from "@langchain/core/tools";
import { Command } from "@langchain/langgraph";
import {
  createDeepAgent,
  EMPTY_HARNESS_PROFILE,
  GENERAL_PURPOSE_SUBAGENT,
  getHarnessProfile,
  type AnySubAgent,
  type CompiledSubAgent,
  type HarnessProfile,
} from "deepagents";
import { createAgent, createMiddleware, type CreateAgentParams } from "langchain";

import type { Firewall } from "../firewall.js";
import { isReviewCompatibilityError } from "../exceptions.js";
import { HookLabel } from "../hooks.js";
import { validateMode } from "../modes.js";
import type { ClassifyEvent, FirewallMode } from "../types.js";

import { nativeThreadId, rejectConversationOptions } from "./thread-identity.js";

export const SAFE_TOOL_MESSAGE = "Silmaril Firewall blocked this tool interaction. Choose a different safe action.";
export const SAFE_FINAL_MESSAGE = "Silmaril Firewall stopped this request after repeated unsafe actions.";
export const SAFE_OUTPUT_MESSAGE = "Silmaril Firewall blocked this response.";
const BLOCKED_TOOL_MARKER = "silmaril-firewall:v1:blocked-tool";
const issuedBlockedMessages = new WeakSet<ToolMessage>();

// A protected graph is identified by the exact runnable returned by our factory.
// Store the original mode too so a mutable spec cannot change execution
// semantics after its graph has been registered.
const protectedCompiledGraphs = new WeakMap<
  object,
  { readonly firewall: Firewall; readonly mode: "isolated" | "fork" | undefined }
>();
const GENERAL_PURPOSE_DEFAULT_MIDDLEWARE = new Set([
  "FilesystemMiddleware",
  "SummarizationMiddleware",
  "PatchToolCallsMiddleware",
]);
type DeepAgentMiddleware = NonNullable<
  NonNullable<Parameters<typeof createDeepAgent>[0]>["middleware"]
>[number];

function isCompiledMode(value: unknown): value is "isolated" | "fork" {
  return value === "isolated" || value === "fork";
}

function recordValue(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function modelCompatName(model: object): string {
  const getName = Reflect.get(model, "getName");
  if (typeof getName !== "function") {
    throw new Error(
      "Protected Deep Agents model-object profiles require a callable getName()",
    );
  }
  const name: unknown = Reflect.apply(getName, model, []);
  if (typeof name !== "string" || !name) {
    throw new Error(
      "Protected Deep Agents model-object getName() must return a non-empty string",
    );
  }
  return name;
}

function optionalModelHint(
  record: object,
  key: string,
  location: string,
): string | undefined {
  const value: unknown = Reflect.get(record, key);
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new Error(
      `Protected Deep Agents ${location}.${key} profile hint must be a string`,
    );
  }
  return value;
}

function configurableDefaults(model: object): Record<string, unknown> | undefined {
  const value: unknown = Reflect.get(model, "_defaultConfig");
  if (value === undefined || value === null) return undefined;
  const defaults = recordValue(value);
  if (defaults === undefined) {
    throw new Error(
      "Protected Deep Agents ConfigurableModel._defaultConfig must be an object",
    );
  }
  return defaults;
}

function modelProviderHint(model: object): string | undefined {
  const name = modelCompatName(model);
  if (name === "ConfigurableModel") {
    const defaults = configurableDefaults(model);
    return defaults === undefined
      ? undefined
      : optionalModelHint(defaults, "modelProvider", "_defaultConfig");
  }
  const providers: Readonly<Record<string, string>> = {
    ChatAnthropic: "anthropic",
    ChatOpenAI: "openai",
    ChatGoogleGenerativeAI: "google",
  };
  return providers[name];
}

function modelIdentifierHint(model: object): string | undefined {
  const name = modelCompatName(model);
  const configurable = name === "ConfigurableModel"
    ? configurableDefaults(model)
    : undefined;
  return (
    (configurable === undefined
      ? undefined
      : optionalModelHint(configurable, "model", "_defaultConfig"))
    ?? optionalModelHint(model, "model_name", name)
    ?? optionalModelHint(model, "modelName", name)
  );
}

function resolveProtectedHarnessProfile(model: unknown): HarnessProfile | undefined {
  if (typeof model === "string") {
    return getHarnessProfile(model);
  }
  if (
    (typeof model !== "object" && typeof model !== "function")
    || model === null
  ) {
    throw new Error(
      "Protected Deep Agents model must be a string or model object",
    );
  }
  const providerHint = modelProviderHint(model);
  const identifierHint = modelIdentifierHint(model);

  if (providerHint && identifierHint && !identifierHint.includes(":")) {
    const exact = getHarnessProfile(`${providerHint}:${identifierHint}`);
    if (exact !== undefined) return exact;
  }
  if (identifierHint?.includes(":")) {
    const exact = getHarnessProfile(identifierHint);
    if (exact !== undefined) return exact;
  }
  if (providerHint) {
    const provider = getHarnessProfile(providerHint);
    if (provider !== undefined) return provider;
  }
  return EMPTY_HARNESS_PROFILE;
}

function applyProfileToolDescriptions<T>(
  tools: readonly T[],
  profile: HarnessProfile | undefined,
): T[] {
  const overrides = profile?.toolDescriptionOverrides ?? {};
  if (Object.keys(overrides).length === 0) return [...tools];
  return tools.map((tool) => {
    if (
      (typeof tool !== "object" && typeof tool !== "function")
      || tool === null
    ) {
      return tool;
    }
    const name: unknown = Reflect.get(tool, "name");
    if (typeof name !== "string" || !(name in overrides)) return tool;
    return Object.assign(
      Object.create(Object.getPrototypeOf(tool)),
      tool,
      { description: overrides[name] },
    );
  });
}

function generalPurposeRootOverrides(
  profile: HarnessProfile | undefined,
  middleware: readonly DeepAgentMiddleware[],
): DeepAgentMiddleware[] {
  const profileMiddleware = profile?.extraMiddleware ?? [];
  if (typeof profileMiddleware === "function" && middleware.length > 0) {
    throw new Error(
      "Protected Deep Agents cannot preserve root middleware overrides when the active profile uses an extraMiddleware factory; use a static profile middleware array",
    );
  }
  const names = new Set(GENERAL_PURPOSE_DEFAULT_MIDDLEWARE);
  names.add("SkillsMiddleware");
  if (Array.isArray(profileMiddleware)) {
    for (const entry of profileMiddleware) names.add(entry.name);
  }
  for (const excluded of profile?.excludedMiddleware ?? []) {
    names.delete(excluded);
  }
  return middleware.filter((entry) => names.has(entry.name));
}

function applyGeneralPurposeProfile(
  profile: HarnessProfile | undefined,
): Pick<AnySubAgent, "description"> & { systemPrompt: string } {
  const config = profile?.generalPurposeSubagent;
  if (config?.systemPrompt !== undefined) {
    return {
      description: config.description ?? GENERAL_PURPOSE_SUBAGENT.description,
      systemPrompt: config.systemPrompt,
    };
  }
  let systemPrompt =
    profile?.baseSystemPrompt ?? GENERAL_PURPOSE_SUBAGENT.systemPrompt;
  if (profile?.systemPromptSuffix !== undefined) {
    systemPrompt = systemPrompt
      ? `${systemPrompt}\n\n${profile.systemPromptSuffix}`
      : profile.systemPromptSuffix;
  }
  return {
    description: config?.description ?? GENERAL_PURPOSE_SUBAGENT.description,
    systemPrompt,
  };
}

export interface DeepAgentsMiddlewareOptions {
  mode?: FirewallMode;
  failOpen?: boolean;
  maxBlockedAttempts?: number;
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
  const strip = (message: ToolMessage): ToolMessage => {
    if (message.additional_kwargs?.silmarilBlocked !== BLOCKED_TOOL_MARKER) return message;
    if (issuedBlockedMessages.has(message)) return message;
    const { silmarilBlocked: _marker, ...additional_kwargs } = message.additional_kwargs;
    // Tool providers may return frozen messages or metadata. Copy rather
    // than mutating a result owned by the caller.
    return new ToolMessage({ ...message, additional_kwargs });
  };
  if (ToolMessage.isInstance(result)) return strip(result);
  if (result instanceof Command) {
    const update = result.update;
    if (update && !Array.isArray(update) && "messages" in update && Array.isArray(update.messages)) {
      const originalMessages = update.messages;
      const messages = originalMessages.map((message) => ToolMessage.isInstance(message) ? strip(message) : message);
      if (messages.some((message, index) => message !== originalMessages[index])) {
        return new Command({ ...result, update: { ...update, messages } });
      }
    }
  }
  return result;
}

function remoteLineage(config: unknown): Record<string, unknown> {
  const record = (v: unknown): Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : {};
  const native = record(record(config).metadata);
  const parent = record(record(record(config).configurable).deepagents_parent);
  const lineage = Object.fromEntries(Object.entries({
    parent_thread_id: native.parent_thread_id ?? parent.thread_id,
    subagent_name: native.subagent_name,
  }).filter(([, value]) => typeof value === "string" && value.trim().length > 0));
  return Object.keys(lineage).length ? { langgraph: lineage } : {};
}

function remoteNotification(message: { additional_kwargs?: Record<string, unknown> }): boolean {
  const extra = message.additional_kwargs ?? {};
  // Notification metadata selects inspection, never authority.
  return (typeof extra.lc_source === "string" && extra.lc_source.includes("async_subagent"))
    || (extra.deepagents_notification !== null && typeof extra.deepagents_notification === "object");
}

async function notificationKey(message: { id?: string; content: unknown; additional_kwargs?: Record<string, unknown> }, threadId: string | undefined, mode: FirewallMode | undefined): Promise<string | undefined> {
  if (!threadId || !message.id) return undefined;
  try {
    const payload = JSON.stringify([message.content, message.additional_kwargs]);
    const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
    const hash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
    return JSON.stringify([threadId, message.id, hash, mode]);
  } catch {
    // Unserializable messages or unavailable hashing always receive a fresh check.
    return undefined;
  }
}

export function createDeepAgentsMiddleware(firewall: Firewall, options: DeepAgentsMiddlewareOptions = {}) {
  rejectConversationOptions(options);
  const maxBlockedAttempts = options.maxBlockedAttempts ?? 3;
  if (!Number.isInteger(maxBlockedAttempts) || maxBlockedAttempts < 1) {
    throw new Error("maxBlockedAttempts must be a positive integer");
  }
  const effectiveMode = validateMode(options.mode) ?? firewall.mode;
  const notificationChecks = new Map<string, boolean>();
  const classify = async (text: string, hook: HookLabel, conversationId: string | undefined, toolName?: string): Promise<{ enforce: boolean; mode: FirewallMode | undefined; cacheable?: boolean }> => {
    if (!text.trim()) return { enforce: false, mode: effectiveMode };
    try {
      const result = await firewall.classify(text, {
        hook,
        ...(toolName === undefined ? {} : { toolName }),
        ...(effectiveMode === undefined ? {} : { mode: effectiveMode }),
        metadata: { ...(conversationId === undefined ? {} : { conversationId }), ...remoteLineage(ensureConfig()) },
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
      return { enforce: blocked && mode === "block", mode, cacheable: true };
    } catch (error) {
      if (isReviewCompatibilityError(error)) throw error;
      if (options.failOpen === false) throw error;
      return { enforce: false, mode: effectiveMode };
    }
  };

  return createMiddleware({
    name: "SilmarilDeepAgentsMiddleware",
    wrapModelCall: async (request, handler) => {
      const conversationId = nativeThreadId(request.runtime, undefined, undefined, ensureConfig());
      const messages = [];
      for (const message of request.messages) {
        let blocked = false;
        if (remoteNotification(message)) {
          const key = await notificationKey(message, conversationId, effectiveMode);
          const cached = key === undefined ? undefined : notificationChecks.get(key);
          if (cached !== undefined) {
            blocked = cached;
            notificationChecks.delete(key!); notificationChecks.set(key!, cached);
          } else {
            const decision = await classify(textOf(message), HookLabel.TOOL_RESPONSE, conversationId, "async_subagent");
            blocked = decision.enforce;
            if (key !== undefined && decision.cacheable) {
              notificationChecks.set(key, blocked);
              while (notificationChecks.size > 1024) notificationChecks.delete(notificationChecks.keys().next().value!);
            }
          }
        }
        messages.push(blocked
          ? new HumanMessage({ content: SAFE_TOOL_MESSAGE, ...(message.id === undefined ? {} : { id: message.id }) })
          : message);
      }
      request = { ...request, messages };
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
        ? await classify(textOf(latestUser), HookLabel.USER_INPUT, conversationId)
        : undefined;
      if (inputDecision?.enforce) return new AIMessage(SAFE_OUTPUT_MESSAGE);
      const capMode = effectiveMode ?? inputDecision?.mode ?? "block";
      // Only genuine prior Block markers count, and the terminal cap requires current effective Block mode.
      if (blockedCount >= maxBlockedAttempts && capMode === "block") {
        return new AIMessage(SAFE_FINAL_MESSAGE);
      }
      const response = await handler(request);
      if (response instanceof Command && (await classify(textOfStructuredValue(response.update), HookLabel.LLM_OUTPUT, conversationId)).enforce) {
        return new AIMessage(SAFE_OUTPUT_MESSAGE);
      }
      if (AIMessage.isInstance(response) && (await classify(textOf(response), HookLabel.LLM_OUTPUT, conversationId)).enforce) {
        return new AIMessage(SAFE_OUTPUT_MESSAGE);
      }
      return response;
    },
    wrapToolCall: async (request, handler) => {
      const conversationId = nativeThreadId(request.runtime, undefined, undefined, ensureConfig());
      const safe = () => {
        const message = new ToolMessage({
          content: SAFE_TOOL_MESSAGE,
          tool_call_id: request.toolCall.id ?? "",
          name: request.toolCall.name,
          additional_kwargs: { silmarilBlocked: BLOCKED_TOOL_MARKER },
        });
        issuedBlockedMessages.add(message);
        return message;
      };
      if ((await classify(JSON.stringify(request.toolCall.args ?? {}), HookLabel.TOOL_CALL, conversationId, request.toolCall.name)).enforce) {
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
        const decision = await classify("[uninspectable tool result]", HookLabel.TOOL_RESPONSE, conversationId, request.toolCall.name);
        return decision.mode === "block" ? safe() : stripAllowedMarker(result);
      }
      if ((await classify(resultText, HookLabel.TOOL_RESPONSE, conversationId, request.toolCall.name)).enforce) {
        if (["start_async_task", "check_async_task", "update_async_task", "cancel_async_task", "list_async_tasks"].includes(request.toolCall.name)
          && result instanceof Command && result.update && !Array.isArray(result.update)
          && "asyncTasks" in result.update) {
          return new Command({ update: { messages: [safe()], asyncTasks: result.update.asyncTasks } });
        }
        return safe();
      }
      return stripAllowedMarker(result);
    },
  });
}

export interface ProtectedCompiledSubagentOptions extends Omit<CreateAgentParams, "middleware" | "mode"> {
  name: string;
  description: string;
  mode?: "isolated" | "fork";
  middleware?: CreateAgentParams["middleware"];
  silmaril?: DeepAgentsMiddlewareOptions;
}

/** Compile a subagent with Silmaril middleware and register that exact graph. */
export function createProtectedCompiledSubagent(firewall: Firewall, options: ProtectedCompiledSubagentOptions): CompiledSubAgent {
  rejectConversationOptions(options);
  const { name, description, mode, silmaril, middleware = [], ...agentOptions } = options;
  if (mode !== undefined && !isCompiledMode(mode)) {
    throw new Error("Compiled subagent mode must be isolated or fork");
  }
  const runnable = createAgent({
    ...agentOptions,
    middleware: [...middleware, createDeepAgentsMiddleware(firewall, silmaril)] as const,
  });
  protectedCompiledGraphs.set(runnable, { firewall, mode });
  return {
    name,
    description,
    runnable,
    ...(mode === undefined ? {} : { mode }),
  };
}

export interface ProtectedDeepAgentOptions extends Omit<NonNullable<Parameters<typeof createDeepAgent>[0]>, "subagents" | "middleware"> {
  subagents?: readonly AnySubAgent[];
  /** Only pass specs returned by createProtectedCompiledSubagent for this client. */
  protectedCompiledSubagents?: readonly CompiledSubAgent[];
  middleware?: NonNullable<Parameters<typeof createDeepAgent>[0]>["middleware"];
  silmaril?: DeepAgentsMiddlewareOptions;
}

/** Protect this graph and inline children; support native remote subagents.
 * Deploy each remote graph with this constructor too. Parent checks cover
 * delegation/results; the child's middleware enforces its internal actions.
 */
export function createProtectedDeepAgent(firewall: Firewall, options: ProtectedDeepAgentOptions = {}) {
  rejectConversationOptions(options);
  const { silmaril, subagents = [], protectedCompiledSubagents = [], middleware = [], ...agentOptions } = options;
  const model = agentOptions.model ?? "anthropic:claude-sonnet-4-6";
  const harnessProfile = resolveProtectedHarnessProfile(model);
  const parentTools = agentOptions.tools ?? [];
  const effectiveParentTools = applyProfileToolDescriptions(
    parentTools,
    harnessProfile,
  );
  const protectedSubagents = subagents.map((subagent) => {
    if ("runnable" in subagent) {
      throw new Error("Compiled subagents must use createProtectedCompiledSubagent");
    }
    if ("graphId" in subagent) return { ...subagent };
    return { ...subagent, middleware: [...(subagent.middleware ?? []), createDeepAgentsMiddleware(firewall, silmaril)] };
  });
  const gpConfig = harnessProfile?.generalPurposeSubagent;
  if (
    gpConfig?.enabled !== false
    && !protectedSubagents.some(
      (subagent) => subagent.name === GENERAL_PURPOSE_SUBAGENT.name,
    )
  ) {
    const inheritedMiddleware = generalPurposeRootOverrides(
      harnessProfile,
      middleware,
    );
    protectedSubagents.unshift({
      ...GENERAL_PURPOSE_SUBAGENT,
      ...applyGeneralPurposeProfile(harnessProfile),
      model,
      tools: effectiveParentTools as StructuredTool[],
      ...(agentOptions.skills === undefined ? {} : { skills: agentOptions.skills }),
      middleware: [
        ...inheritedMiddleware,
        createDeepAgentsMiddleware(firewall, silmaril),
      ],
    });
  }
  for (const spec of protectedCompiledSubagents) {
    const registration = spec.runnable
      ? protectedCompiledGraphs.get(spec.runnable)
      : undefined;
    const candidateMode: unknown = spec.mode;
    if (
      registration?.firewall !== firewall
      || (candidateMode !== undefined && !isCompiledMode(candidateMode))
      || candidateMode !== registration.mode
    ) {
      throw new Error("Compiled subagents must be built with createProtectedCompiledSubagent for this Firewall client");
    }
  }
  return createDeepAgent({
    ...agentOptions,
    middleware: [...middleware, createDeepAgentsMiddleware(firewall, silmaril)],
    subagents: [...protectedSubagents, ...protectedCompiledSubagents],
  });
}
