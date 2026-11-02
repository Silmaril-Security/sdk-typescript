// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type { Runnable, RunnableBinding as RunnableBindingType, RunnableConfig } from "@langchain/core/runnables";
import type { Serialized } from "@langchain/core/load/serializable";
import type { BaseTracer as BaseTracerType, Run } from "@langchain/core/tracers/base";
import type { BaseCallbackHandler } from "@langchain/core/callbacks/base";

import type { Firewall } from "../firewall.js";
import {
  FirewallBlockedException,
  isReviewCompatibilityError,
} from "../exceptions.js";
import {
  FIREWALL_HOOK_TO_LABEL,
  FirewallHook,
  HookLabel,
  resolveHooks,
} from "../hooks.js";
import type { BlockResult, ClassifyEvent, LangChainAdapterOptions } from "../types.js";
import { validateMode } from "../modes.js";
import {
  extractTextFromDocuments,
  extractTextFromLLMResult,
  extractTextFromPrompts,
  extractTextFromToolInput,
} from "../utils/extract.js";

import { rejectConversationOptions, RunThreadIdentity, validThreadId } from "./thread-identity.js";

const handlerCleanups = new WeakMap<object, () => void>();

const USER_ROLES: ReadonlySet<string> = new Set(["human", "user"]);

interface LangChainDucktypedMessage {
  role?: string;
  type?: string;
  getType?: () => string;
  _getType?: () => string;
  content?: string | ReadonlyArray<string | { type?: string; text?: string }>;
}

function getMessageRole(message: LangChainDucktypedMessage): string {
  if (typeof message.role === "string") {
    return message.role.toLowerCase();
  }
  if (typeof message.type === "string") {
    return message.type.toLowerCase();
  }
  const legacyType = message.getType?.() ?? message._getType?.();
  return typeof legacyType === "string" ? legacyType.toLowerCase() : "";
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
  return buildLangChainHandler(firewall, options);
}

async function buildLangChainHandler(
  firewall: Firewall, options: LangChainAdapterOptions,
  boundIdentity?: { threadId: string | undefined },
): Promise<BaseCallbackHandler> {
  rejectConversationOptions(options);
  const { ensureConfig } = await import("@langchain/core/runnables");
  const threads = new RunThreadIdentity(boundIdentity, () => ensureConfig());
  const { BaseTracer } = await import("@langchain/core/tracers/base");
  let finishRun = (runId: string): void => { threads.finish(runId); };

  const enabledHooks = resolveHooks(options.hooks);
  // includeSystem remains inert for the user-only chat-model scan.
  // includeTool still controls the explicit tool start and end callbacks.
  const includeTool = options.includeTool ?? true;
  const failOpen = options.failOpen ?? true;
  const logger =
    options.logger ??
    ((message: string, error: unknown): void => {
      // eslint-disable-next-line no-console
      console.warn(`silmaril.firewall: ${message}`, error);
    });
  const requestedMode = validateMode(options.mode) ?? (
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

  const classifyEvent = async (
    text: string,
    hookLabel: HookLabel,
    runId: string,
    toolName?: string,
  ): Promise<void> => {
    let result: BlockResult;
    try {
      result = await firewall.classify(text, {
        hook: hookLabel,
        metadata: {
          langgraph: { run_id: runId },
          ...(threads.get(runId) === undefined ? {} : { conversationId: threads.get(runId) }),
        },
        ...(requestedMode !== undefined ? { mode: requestedMode } : {}),
        ...(toolName !== undefined ? { toolName } : {}),
      });
    } catch (err) {
      if (isReviewCompatibilityError(err)) {
        throw err;
      }
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

  const classify = async (text: string, hook: HookLabel, runId: string, toolName?: string): Promise<void> => {
    try {
      await classifyEvent(text, hook, runId, toolName);
    } catch (error) {
      finishRun(runId);
      throw error;
    }
  };

  function serialized(value: unknown, name: string): Serialized {
    if (value && typeof value === "object" && "id" in value && Array.isArray(value.id)) return value as Serialized;
    return { lc: 1, type: "not_implemented", id: [name] };
  }

  class SilmarilFirewallHandler extends BaseTracer {
    override name = "silmaril_firewall_handler";
    override raiseError = true;
    override awaitHandlers = true;

    // LangChain clears runnable context inside ordinary callbacks. Its synchronous
    // tracer pre-start hooks capture native config before that boundary. Runs are
    // memory-only and every terminal path discards both native tracer maps.
    protected override async persistRun(): Promise<void> {}
    protected override getRunById(runId?: string): Run | undefined {
      return runId === undefined ? undefined : this.runMap.get(runId);
    }

    // Only lifecycle identity is needed. Do not retain prompts, outputs, token
    // events, or completed children when upstream omits a cancellation callback.
    override _addRunToRunMap(run: Run) {
      return super._addRunToRunMap({ ...run, inputs: {}, extra: {}, serialized: {},
        tags: [], child_runs: [], events: [],
      });
    }
    protected override _addChildRun(): void {}
    protected override async _endTrace(run: Run): Promise<void> {
      try { await super._endTrace(run); } finally {
        run.inputs = {};
        delete run.outputs;
        delete run.error;
        run.extra = {};
        run.events = [];
        run.child_runs = [];
      }
    }
    override async handleText(): Promise<void> {}
    override async handleAgentAction(): Promise<void> {}
    override async handleAgentEnd(): Promise<void> {}
    override async handleLLMNewToken(_token: string, _idx: unknown, runId: string): Promise<Run> {
      return this.getRunById(runId) ?? this._createRunForLLMStart(serialized(undefined, "llm"), [], runId);
    }

    capture(runId: string, parentRunId?: string, metadata?: unknown): void {
      for (const id of threads.start(runId, parentRunId, metadata)) {
        this.runMap.delete(id);
        this.runTreeMap?.delete(id);
      }
    }

    finishAll(): void {
      for (const id of [...this.runMap.keys()]) this.finishRun(id);
      this.runTreeMap?.clear();
    }

    finishRun(runId: string): void {
      for (const id of threads.finish(runId)) {
        this.runMap.delete(id);
        this.runTreeMap?.delete(id);
      }
    }

    override _createRunForLLMStart(...args: Parameters<BaseTracerType["_createRunForLLMStart"]>) {
      this.capture(args[2], args[3], args[6]);
      return super._createRunForLLMStart(...args);
    }

    override _createRunForChatModelStart(...args: Parameters<BaseTracerType["_createRunForChatModelStart"]>) {
      this.capture(args[2], args[3], args[6]);
      return super._createRunForChatModelStart(...args);
    }

    override _createRunForChainStart(...args: Parameters<BaseTracerType["_createRunForChainStart"]>) {
      this.capture(args[2], args[3], args[5]);
      return super._createRunForChainStart(...args);
    }

    override _createRunForToolStart(...args: Parameters<BaseTracerType["_createRunForToolStart"]>) {
      this.capture(args[2], args[3], args[5]);
      return super._createRunForToolStart(...args);
    }

    override _createRunForRetrieverStart(...args: Parameters<BaseTracerType["_createRunForRetrieverStart"]>) {
      this.capture(args[2], args[3], args[5]);
      return super._createRunForRetrieverStart(...args);
    }

    override async handleChatModelStart(
      llm: unknown, messages: unknown, runId: string, parentRunId?: string,
      extraParams?: Record<string, unknown>, tags?: string[], metadata?: Record<string, unknown>,
    ): Promise<Run> {
      const batches = messages as ReadonlyArray<ReadonlyArray<LangChainDucktypedMessage>>;
      const run = this.getRunById(runId) ?? this._createRunForChatModelStart(
        serialized(llm, "chat_model"), messages as Parameters<BaseTracerType["_createRunForChatModelStart"]>[1], runId,
        parentRunId, extraParams, tags, metadata,
      );
      if (enabledHooks.has(FirewallHook.CHAT_MODEL_START)) {
        const lastUser = findLastUserMessage(batches.flat());
        const text = lastUser ? extractMessageText(lastUser.content).trim() : "";
        if (text) await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.CHAT_MODEL_START], runId);
      }
      return run;
    }

    override async handleLLMStart(
      llm: unknown, prompts: string[], runId: string, parentRunId?: string,
      extraParams?: Record<string, unknown>, tags?: string[], metadata?: Record<string, unknown>,
    ): Promise<Run> {
      const run = this.getRunById(runId) ?? this._createRunForLLMStart(
        serialized(llm, "llm"), prompts, runId, parentRunId, extraParams, tags, metadata,
      );
      if (enabledHooks.has(FirewallHook.LLM_START)) {
        const text = extractTextFromPrompts(prompts);
        if (text) await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.LLM_START], runId);
      }
      return run;
    }

    override async handleToolStart(
      tool: { name?: string } | undefined, inputStr: string, runId: string, parentRunId?: string,
      tags?: string[], metadata?: Record<string, unknown>,
    ): Promise<Run> {
      const run = this.getRunById(runId) ?? this._createRunForToolStart(
        serialized(tool, tool?.name ?? "tool"), inputStr, runId, parentRunId, tags, metadata,
      );
      if (includeTool && enabledHooks.has(FirewallHook.TOOL_START)) {
        const text = extractTextFromToolInput(inputStr);
        if (text) await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.TOOL_START], runId, tool?.name);
      }
      return run;
    }

    override async handleRetrieverStart(
      retriever: unknown, query: string, runId: string, parentRunId?: string,
      tags?: string[], metadata?: Record<string, unknown>,
    ): Promise<Run> {
      const run = this.getRunById(runId) ?? this._createRunForRetrieverStart(
        serialized(retriever, "retriever"), query, runId, parentRunId, tags, metadata,
      );
      if (enabledHooks.has(FirewallHook.RETRIEVER_START) && query.trim()) {
        await classify(query.trim(), FIREWALL_HOOK_TO_LABEL[FirewallHook.RETRIEVER_START], runId);
      }
      return run;
    }

    override async handleLLMEnd(output: unknown, runId: string): Promise<Run> {
      try {
        if (!this.getRunById(runId)) this._createRunForLLMStart(serialized(undefined, "llm"), [], runId);
        if (enabledHooks.has(FirewallHook.LLM_END)) {
          const text = extractTextFromLLMResult(output as Parameters<typeof extractTextFromLLMResult>[0]);
          if (text) await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.LLM_END], runId);
        }
        return await super.handleLLMEnd(output as Parameters<BaseTracerType["handleLLMEnd"]>[0], runId);
      } finally {
        finishRun(runId);
      }
    }

    override async handleToolEnd(
      output: unknown, runId: string, _parentRunId?: string, _tags?: string[], kwargs?: { name?: string },
    ): Promise<Run> {
      try {
        if (!this.getRunById(runId)) this._createRunForToolStart(serialized(undefined, "tool"), "", runId);
        if (includeTool && enabledHooks.has(FirewallHook.TOOL_END)) {
          const text = String(output).trim();
          if (text) await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.TOOL_END], runId, kwargs?.name);
        }
        return await super.handleToolEnd(output, runId);
      } finally {
        finishRun(runId);
      }
    }

    override async handleRetrieverEnd(documents: ReadonlyArray<{ pageContent?: string }>, runId: string): Promise<Run> {
      try {
        if (!this.getRunById(runId)) this._createRunForRetrieverStart(serialized(undefined, "retriever"), "", runId);
        if (enabledHooks.has(FirewallHook.RETRIEVER_END)) {
          const text = extractTextFromDocuments(documents);
          if (text) await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.RETRIEVER_END], runId);
        }
        return await super.handleRetrieverEnd(documents as Parameters<BaseTracerType["handleRetrieverEnd"]>[0], runId);
      } finally {
        finishRun(runId);
      }
    }

    override async handleChainStart(
      chain: unknown, inputs: Record<string, unknown>, runId: string, parentRunId?: string,
      tags?: string[], metadata?: Record<string, unknown>, runType?: string, name?: string,
    ): Promise<Run> {
      return super.handleChainStart(serialized(chain, "chain"), inputs, runId, parentRunId, tags, metadata, runType, name);
    }

    override async handleChainEnd(...args: Parameters<BaseTracerType["handleChainEnd"]>): Promise<Run> {
      if (!this.getRunById(args[1])) this._createRunForChainStart(serialized(undefined, "chain"), {}, args[1]);
      try { return await super.handleChainEnd(...args); } finally { finishRun(args[1]); }
    }

    override async handleChainError(...args: Parameters<BaseTracerType["handleChainError"]>): Promise<Run> {
      if (!this.getRunById(args[1])) this._createRunForChainStart(serialized(undefined, "chain"), {}, args[1]);
      try { return await super.handleChainError(...args); } finally { finishRun(args[1]); }
    }

    override async handleLLMError(...args: Parameters<BaseTracerType["handleLLMError"]>): Promise<Run> {
      if (!this.getRunById(args[1])) this._createRunForLLMStart(serialized(undefined, "llm"), [], args[1]);
      try { return await super.handleLLMError(...args); } finally { finishRun(args[1]); }
    }

    override async handleToolError(...args: Parameters<BaseTracerType["handleToolError"]>): Promise<Run> {
      if (!this.getRunById(args[1])) this._createRunForToolStart(serialized(undefined, "tool"), "", args[1]);
      try { return await super.handleToolError(...args); } finally { finishRun(args[1]); }
    }

    override async handleRetrieverError(...args: Parameters<BaseTracerType["handleRetrieverError"]>): Promise<Run> {
      if (!this.getRunById(args[1])) this._createRunForRetrieverStart(serialized(undefined, "retriever"), "", args[1]);
      try { return await super.handleRetrieverError(...args); } finally { finishRun(args[1]); }
    }
  }

  const handler = new SilmarilFirewallHandler();
  finishRun = (runId: string): void => { handler.finishRun(runId); };
  handlerCleanups.set(handler, () => handler.finishAll());
  return handler;
}


/** Protect a runnable using its actual invocation config, including direct model/tool calls. */
export async function protectLangChainRunnable<RunInput, RunOutput, CallOptions extends RunnableConfig = RunnableConfig>(
  firewall: Firewall,
  runnable: Runnable<RunInput, RunOutput, CallOptions>,
  options: LangChainAdapterOptions = {},
): Promise<RunnableBindingType<RunInput, RunOutput, CallOptions>> {
  rejectConversationOptions(options);
  const { RunnableBinding, RunnableRetry, ensureConfig, mergeConfigs } = await import("@langchain/core/runnables");
  const { IterableReadableStream } = await import("@langchain/core/utils/stream");
  const configFactories = [async (config: RunnableConfig): Promise<RunnableConfig> => {
    const effective = ensureConfig(config);
    const handler = await buildLangChainHandler(firewall, options, {
      threadId: validThreadId(effective.configurable?.thread_id),
    });
    return { callbacks: [handler] };
  }];
  // Upstream withConfig/withRetry reconstruct a binding without its factories.
  // Retain ours so normal runnable composition cannot drop protection.
  class ProtectedBinding extends RunnableBinding<RunInput, RunOutput, CallOptions> {
    async scopedConfig(...configs: Parameters<RunnableBindingType<RunInput, RunOutput, CallOptions>["_mergeConfig"]>) {
      const created: BaseCallbackHandler[] = [];
      const scopedFactories = configFactories.map((factory) => async (config: RunnableConfig) => {
        const update = await factory(config);
        // This factory returns exactly its fresh handler. Never dispose inherited
        // caller/parent handlers from a merged callback manager.
        if (Array.isArray(update.callbacks)) created.push(...update.callbacks as BaseCallbackHandler[]);
        return update;
      });
      const scoped = new RunnableBinding({ bound: this.bound, config: this.config, configFactories: scopedFactories });
      const config = await scoped._mergeConfig(...configs);
      return { config, dispose: () => { for (const handler of created) handlerCleanups.get(handler)?.(); } };
    }
    override async invoke(input: RunInput, options?: Partial<CallOptions>): Promise<RunOutput> {
      const scoped = await this.scopedConfig(options, this.kwargs);
      try { return await this.bound.invoke(input, scoped.config); } finally { scoped.dispose(); }
    }
    override async stream(input: RunInput, options?: Partial<CallOptions>) {
      const scoped = await this.scopedConfig(ensureConfig(options as RunnableConfig | undefined), this.kwargs);
      let upstream;
      try { upstream = await this.bound.stream(input, scoped.config); } catch (error) { scoped.dispose(); throw error; }
      const managed = async function* () {
        try { yield* upstream; } finally { scoped.dispose(); }
      };
      return IterableReadableStream.fromAsyncGenerator(managed());
    }
    override async *_streamIterator(input: RunInput, options?: Partial<CallOptions>) {
      const stream = await this.stream(input, options);
      yield* stream;
    }
    override withConfig(config: Partial<CallOptions>) {
      return new ProtectedBinding({ bound: this.bound, config: mergeConfigs(this.config, config as RunnableConfig), configFactories });
    }
    override withListeners(fields: Parameters<RunnableBindingType<RunInput, RunOutput, CallOptions>["withListeners"]>[0]): ReturnType<RunnableBindingType<RunInput, RunOutput, CallOptions>["withListeners"]> {
      return new RunnableBinding({ bound: this, config: {} }).withListeners(fields);
    }
    override withRetry(fields?: Parameters<RunnableBindingType<RunInput, RunOutput, CallOptions>["withRetry"]>[0]): ReturnType<RunnableBindingType<RunInput, RunOutput, CallOptions>["withRetry"]> {
      return new RunnableRetry({ bound: this, config: {},
        ...(fields?.stopAfterAttempt === undefined ? {} : { maxAttemptNumber: fields.stopAfterAttempt }),
        ...(fields?.onFailedAttempt === undefined ? {} : { onFailedAttempt: fields.onFailedAttempt }),
      });
    }
  }
  const bindings = new Set<Runnable<RunInput, RunOutput, CallOptions>>();
  const installBoundary = (candidate: Runnable<RunInput, RunOutput, CallOptions>): RunnableBindingType<RunInput, RunOutput, CallOptions> => {
    if (!RunnableBinding.isRunnableBinding(candidate)) {
      return new ProtectedBinding({ bound: candidate, config: {}, configFactories });
    }
    if (bindings.has(candidate)) throw new TypeError("Cannot protect cyclic runnable bindings");
    bindings.add(candidate);
    const binding = candidate as RunnableBindingType<RunInput, RunOutput, CallOptions>;
    const Binding = binding.constructor as new (fields: Record<string, unknown>) => RunnableBindingType<RunInput, RunOutput, CallOptions>;
    // Keep native defaults, kwargs, retry settings and config factories outside
    // our boundary. They resolve exactly once before we capture the final config.
    // Reconstruct rather than mutate a runnable owned by the caller.
    return new Binding({ ...binding, bound: installBoundary(binding.bound) });
  };
  // Keep original native layers inside a stable composition shell. Native
  // binding helpers can otherwise reconstruct themselves without their factories.
  class ComposableBinding extends RunnableBinding<RunInput, RunOutput, CallOptions> {
    override withConfig(config: Partial<CallOptions>) {
      return new ComposableBinding({ bound: this.bound, config: mergeConfigs(this.config, config as RunnableConfig) });
    }
    override withListeners(fields: Parameters<RunnableBindingType<RunInput, RunOutput, CallOptions>["withListeners"]>[0]): ReturnType<RunnableBindingType<RunInput, RunOutput, CallOptions>["withListeners"]> {
      return new RunnableBinding({ bound: this, config: {} }).withListeners(fields);
    }
    override withRetry(fields?: Parameters<RunnableBindingType<RunInput, RunOutput, CallOptions>["withRetry"]>[0]): ReturnType<RunnableBindingType<RunInput, RunOutput, CallOptions>["withRetry"]> {
      return new RunnableRetry({ bound: this, config: {},
        ...(fields?.stopAfterAttempt === undefined ? {} : { maxAttemptNumber: fields.stopAfterAttempt }),
        ...(fields?.onFailedAttempt === undefined ? {} : { onFailedAttempt: fields.onFailedAttempt }),
      });
    }
  }
  return new ComposableBinding({ bound: installBoundary(runnable), config: {} });
}
