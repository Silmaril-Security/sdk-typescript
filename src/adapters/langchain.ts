// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type { BaseCallbackHandler } from "@langchain/core/callbacks/base";
import type { Serialized } from "@langchain/core/load/serializable";
import type { BaseMessage } from "@langchain/core/messages";
import type { LLMResult } from "@langchain/core/outputs";

import type { Firewall } from "../firewall.js";
import { FirewallBlockedException } from "../exceptions.js";
import {
  FIREWALL_HOOK_TO_LABEL,
  FirewallHook,
  HookLabel,
  resolveHooks,
} from "../hooks.js";
import type { BlockResult, ClassifyEvent, LangChainAdapterOptions } from "../types.js";
import {
  extractTextFromDocuments,
  extractTextFromLLMResult,
  extractTextFromPrompts,
  extractTextFromToolInput,
} from "../utils/extract.js";

const USER_ROLES: ReadonlySet<string> = new Set(["human", "user"]);

/** In-flight chat/LLM runs whose output may still need the selected model. */
const AGENT_MODEL_RUN_LIMIT = 1024;
const AGENT_MODEL_ID_MAX_CHARS = 256;

const MODEL_ID_KEYS = ["model", "model_id", "modelId", "model_name", "modelName"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function modelIdString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= AGENT_MODEL_ID_MAX_CHARS &&
    !Array.from(trimmed).some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)
    ? trimmed
    : undefined;
}

function modelIdFromFields(fields: Record<string, unknown> | undefined): string | undefined {
  if (fields === undefined) {
    return undefined;
  }
  for (const key of MODEL_ID_KEYS) {
    const modelId = modelIdString(fields[key]);
    if (modelId !== undefined) {
      return modelId;
    }
  }
  return undefined;
}

/**
 * Selected model for this callback. Invocation params are the call about to
 * run, `ls_model_name` is LangChain's explicit model metadata, and serialized
 * kwargs hold the constructor model. `serialized.id` is the class path and is
 * never used as a model id.
 */
function selectedAgentModelId(
  llm: unknown,
  extraParams: Record<string, unknown> | undefined,
  metadata: Record<string, unknown> | undefined,
): string | undefined {
  const invocationParams = extraParams?.invocation_params;
  const fromInvocation = modelIdFromFields(isRecord(invocationParams) ? invocationParams : undefined);
  if (fromInvocation !== undefined) {
    return fromInvocation;
  }
  const fromMetadata = modelIdString(metadata?.ls_model_name);
  if (fromMetadata !== undefined) {
    return fromMetadata;
  }
  const kwargs = isRecord(llm) ? llm.kwargs : undefined;
  return modelIdFromFields(isRecord(kwargs) ? kwargs : undefined);
}

interface LangChainDucktypedMessage {
  role?: string;
  type?: string;
  content?: string | ReadonlyArray<string | { type?: string; text?: string }>;
}

function getMessageRole(message: LangChainDucktypedMessage): string {
  if (typeof message.role === "string") {
    return message.role.toLowerCase();
  }
  if (typeof message.type === "string") {
    return message.type.toLowerCase();
  }
  return "";
}

function extractMessageText(content: LangChainDucktypedMessage["content"]): string {
  if (content === undefined) {
    return "";
  }
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

function findLastUserMessage(
  messages: ReadonlyArray<LangChainDucktypedMessage>,
): LangChainDucktypedMessage | undefined {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i]!;
    if (USER_ROLES.has(getMessageRole(msg))) {
      return msg;
    }
  }
  return undefined;
}

export async function createLangChainHandler(
  firewall: Firewall,
  options: LangChainAdapterOptions = {},
): Promise<BaseCallbackHandler> {
  const { BaseCallbackHandler } = await import("@langchain/core/callbacks/base");

  const enabledHooks = resolveHooks(options.hooks);
  // includeSystem / includeTool are retained in LangChainAdapterOptions for
  // backwards compat but are inert under the per-message hook-routing algorithm:
  // handleChatModelStart only scans the last user-role message; system and tool
  // messages are either trusted or already classified by their own hooks.
  const failOpen = options.failOpen ?? true;
  const logger =
    options.logger ??
    ((message: string, error: unknown): void => {
      // eslint-disable-next-line no-console
      console.warn(`silmaril.firewall: ${message}`, error);
    });
  const requestedMode = options.mode ?? (
    options.shadowMode === undefined
      ? firewall.mode
      : options.shadowMode ? "shadow" : "block"
  );
  const onClassify = options.onClassify;

  const fireOnClassify = (event: ClassifyEvent): void => {
    if (!onClassify) {
      return;
    }
    try {
      onClassify(event);
    } catch (err) {
      logger("onClassify callback threw", err);
    }
  };

  const runModelIds = new Map<string, string>();

  const rememberRunModel = (runId: string, modelId: string | undefined): void => {
    runModelIds.delete(runId);
    if (modelId === undefined) {
      return;
    }
    runModelIds.set(runId, modelId);
    while (runModelIds.size > AGENT_MODEL_RUN_LIMIT) {
      const oldest = runModelIds.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      runModelIds.delete(oldest);
    }
  };

  const takeRunModel = (runId: string): string | undefined => {
    const modelId = runModelIds.get(runId);
    runModelIds.delete(runId);
    return modelId;
  };

  const classify = async (
    text: string,
    hookLabel: HookLabel,
    runId: string,
    toolName?: string,
    agentModelId?: string,
  ): Promise<void> => {
    let result: BlockResult;
    try {
      result = await firewall.classify(text, {
        hook: hookLabel,
        ...(requestedMode !== undefined ? { mode: requestedMode } : {}),
        ...(toolName !== undefined ? { toolName } : {}),
        ...(agentModelId !== undefined
          ? { metadata: { silmaril: { agent_model_id: agentModelId } } }
          : {}),
      });
    } catch (err) {
      if (!failOpen) {
        throw err;
      }
      logger("classification failed, allowing prompt through", err);
      return;
    }
    const threshold = result.threshold;
    const blocked = result.prediction === "MALICIOUS" || result.governance?.action === "block";
    const effectiveMode = requestedMode ?? result.mode ?? "block";
    const commonEventFields = {
      hook: hookLabel,
      ...(toolName !== undefined ? { toolName } : {}),
      runId,
      text,
      result,
    };
    fireOnClassify({
      ...commonEventFields,
      blocked,
      mode: effectiveMode,
      shadowMode: effectiveMode === "shadow",
    });
    if (!blocked || effectiveMode !== "block") {
      return;
    }

    throw new FirewallBlockedException({
      score: result.score,
      threshold,
      promptText: text,
      runId,
      hook: hookLabel,
      ...(toolName !== undefined ? { toolName } : {}),
      result,
    });
  };

  class SilmarilFirewallHandler extends BaseCallbackHandler {
    override name = "silmaril_firewall_handler";
    override raiseError = true;
    override awaitHandlers = true;

    override async handleChatModelStart(
      llm: Serialized,
      messages: BaseMessage[][],
      runId: string,
      _parentRunId?: string,
      extraParams?: Record<string, unknown>,
      _tags?: string[],
      metadata?: Record<string, unknown>,
      _runName?: string,
    ): Promise<void> {
      const agentModelId = selectedAgentModelId(llm, extraParams, metadata);
      rememberRunModel(runId, agentModelId);
      if (!enabledHooks.has(FirewallHook.CHAT_MODEL_START)) {
        return;
      }
      const batches = messages as ReadonlyArray<ReadonlyArray<LangChainDucktypedMessage>>;
      const flat: LangChainDucktypedMessage[] = [];
      for (const batch of batches) {
        for (const m of batch) {
          flat.push(m);
        }
      }
      const lastUser = findLastUserMessage(flat);
      if (!lastUser) {
        return;
      }
      const text = extractMessageText(lastUser.content).trim();
      if (!text) {
        return;
      }
      await classify(
        text,
        FIREWALL_HOOK_TO_LABEL[FirewallHook.CHAT_MODEL_START],
        runId,
        undefined,
        agentModelId,
      );
    }

    override async handleLLMStart(
      llm: Serialized,
      prompts: string[],
      runId: string,
      _parentRunId?: string,
      extraParams?: Record<string, unknown>,
      _tags?: string[],
      metadata?: Record<string, unknown>,
      _runName?: string,
    ): Promise<void> {
      const agentModelId = selectedAgentModelId(llm, extraParams, metadata);
      rememberRunModel(runId, agentModelId);
      if (!enabledHooks.has(FirewallHook.LLM_START)) {
        return;
      }
      const text = extractTextFromPrompts(prompts);
      if (!text) {
        return;
      }
      await classify(
        text,
        FIREWALL_HOOK_TO_LABEL[FirewallHook.LLM_START],
        runId,
        undefined,
        agentModelId,
      );
    }

    override async handleToolStart(
      tool: { name?: string } | undefined,
      inputStr: string,
      runId: string,
    ): Promise<void> {
      if (!enabledHooks.has(FirewallHook.TOOL_START)) {
        return;
      }
      const text = extractTextFromToolInput(inputStr);
      if (!text) {
        return;
      }
      const toolName = tool?.name;
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.TOOL_START], runId, toolName);
    }

    override async handleRetrieverStart(
      _retriever: unknown,
      query: string,
      runId: string,
    ): Promise<void> {
      if (!enabledHooks.has(FirewallHook.RETRIEVER_START)) {
        return;
      }
      const text = query.trim();
      if (!text) {
        return;
      }
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.RETRIEVER_START], runId);
    }

    override async handleLLMEnd(
      output: LLMResult,
      runId: string,
      _parentRunId?: string,
      _tags?: string[],
      _extraParams?: Record<string, unknown>,
    ): Promise<void> {
      const agentModelId = takeRunModel(runId);
      if (!enabledHooks.has(FirewallHook.LLM_END)) {
        return;
      }
      const text = extractTextFromLLMResult(output);
      if (!text) {
        return;
      }
      await classify(
        text,
        FIREWALL_HOOK_TO_LABEL[FirewallHook.LLM_END],
        runId,
        undefined,
        agentModelId,
      );
    }

    override async handleLLMError(
      _err: unknown,
      runId: string,
      _parentRunId?: string,
      _tags?: string[],
      _extraParams?: Record<string, unknown>,
    ): Promise<void> {
      rememberRunModel(runId, undefined);
    }

    override async handleToolEnd(
      output: unknown,
      runId: string,
      _parentRunId?: string,
      _tags?: string[],
      _kwargs?: { name?: string },
    ): Promise<void> {
      if (!enabledHooks.has(FirewallHook.TOOL_END)) {
        return;
      }
      const text = String(output).trim();
      if (!text) {
        return;
      }
      const toolName = _kwargs?.name;
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.TOOL_END], runId, toolName);
    }

    override async handleRetrieverEnd(
      documents: ReadonlyArray<{ pageContent?: string }>,
      runId: string,
    ): Promise<void> {
      if (!enabledHooks.has(FirewallHook.RETRIEVER_END)) {
        return;
      }
      const text = extractTextFromDocuments(documents);
      if (!text) {
        return;
      }
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.RETRIEVER_END], runId);
    }
  }

  return new SilmarilFirewallHandler();
}
