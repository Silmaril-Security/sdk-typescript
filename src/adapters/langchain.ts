// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type { BaseCallbackHandler } from "@langchain/core/callbacks/base";

import type { Firewall } from "../firewall.js";
import { PromptBlockedException } from "../exceptions.js";
import {
  FIREWALL_HOOK_TO_LABEL,
  FirewallHook,
  HookLabel,
  resolveHooks,
} from "../hooks.js";
import type { BlockResult, LangChainAdapterOptions } from "../types.js";
import {
  extractTextFromDocuments,
  extractTextFromLLMResult,
  extractTextFromPrompts,
  extractTextFromToolInput,
} from "../utils/extract.js";
import { validateHookThresholds, validateOptionalThreshold } from "../validation.js";

const USER_ROLES: ReadonlySet<string> = new Set(["human", "user"]);

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
  const overrideThreshold = validateOptionalThreshold("threshold", options.threshold);
  const overrideHookThresholds = validateHookThresholds("hookThresholds", options.hookThresholds);
  const shadowMode = options.shadowMode ?? firewall.shadowMode;
  const onClassify = options.onClassify;

  const effectiveThreshold = (label: HookLabel): number => {
    if (overrideHookThresholds[label] !== undefined) {
      return overrideHookThresholds[label] as number;
    }
    if (firewall.hookThresholds[label] !== undefined) {
      return firewall.hookThresholds[label] as number;
    }
    return overrideThreshold ?? firewall.threshold;
  };

  const fireOnClassify = (
    hookLabel: HookLabel,
    text: string,
    result: BlockResult,
    blocked: boolean,
    toolName: string | undefined,
  ): void => {
    if (!onClassify) {
      return;
    }
    try {
      onClassify({
        hook: hookLabel,
        ...(toolName !== undefined ? { toolName } : {}),
        text,
        result,
        blocked,
        shadowMode,
      });
    } catch (err) {
      logger("onClassify callback threw", err);
    }
  };

  const classify = async (
    text: string,
    hookLabel: HookLabel,
    runId: string,
    toolName?: string,
  ): Promise<void> => {
    let result: BlockResult;
    try {
      result = await firewall.classify(text, {
        hook: hookLabel,
        ...(toolName !== undefined ? { toolName } : {}),
      });
    } catch (err) {
      if (!failOpen) {
        throw err;
      }
      logger("classification failed, allowing prompt through", err);
      return;
    }
    const threshold = effectiveThreshold(hookLabel);
    const blocked = result.score >= threshold;
    fireOnClassify(hookLabel, text, result, blocked, toolName);
    if (blocked && !shadowMode) {
      throw new PromptBlockedException({
        score: result.score,
        threshold,
        promptText: text,
        runId,
      });
    }
  };

  class SilmarilFirewallHandler extends BaseCallbackHandler {
    override name = "silmaril_firewall_handler";
    override raiseError = true;
    override awaitHandlers = true;

    override async handleChatModelStart(
      _llm: unknown,
      messages: unknown,
      runId: string,
    ): Promise<void> {
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
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.CHAT_MODEL_START], runId);
    }

    override async handleLLMStart(
      _llm: unknown,
      prompts: string[],
      runId: string,
    ): Promise<void> {
      if (!enabledHooks.has(FirewallHook.LLM_START)) {
        return;
      }
      const text = extractTextFromPrompts(prompts);
      if (!text) {
        return;
      }
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.LLM_START], runId);
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

    override async handleLLMEnd(output: unknown, runId: string): Promise<void> {
      if (!enabledHooks.has(FirewallHook.LLM_END)) {
        return;
      }
      const text = extractTextFromLLMResult(output as { generations?: ReadonlyArray<ReadonlyArray<{ text?: string }>> });
      if (!text) {
        return;
      }
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.LLM_END], runId);
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
