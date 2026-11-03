import { AIMessage, HumanMessage, ToolMessage, type BaseMessage } from "@langchain/core/messages";
import { RunnableBinding, RunnableLambda } from "@langchain/core/runnables";
import { fakeModel } from "@langchain/core/testing";
import { tool } from "@langchain/core/tools";
import { FakeListChatModel, FakeRetriever } from "@langchain/core/utils/testing";
import { Document } from "@langchain/core/documents";
import { Command, interrupt, END, MemorySaver, MessagesAnnotation, START, StateGraph } from "@langchain/langgraph";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { ALL_HOOKS, Firewall, FirewallHook, HookLabel } from "../src/index.js";
import { createLangChainHandler, protectLangChainRunnable } from "../src/adapters/langchain.js";
import { createDeepAgentsMiddleware, createProtectedCompiledSubagent, createProtectedDeepAgent } from "../src/adapters/deepagents.js";
import { nativeThreadId, RunThreadIdentity } from "../src/adapters/thread-identity.js";

function recordingFirewall() {
  const firewall = new Firewall({ apiKey: "test", apiUrl: "https://test.invalid/classify" });
  const calls: Array<{ text: string; hook?: string; conversationId?: unknown; runId?: unknown }> = [];
  firewall.classify = vi.fn(async (text, options) => {
    calls.push({ text, hook: options?.hook, conversationId: options?.metadata?.conversationId,
      runId: (options?.metadata?.langgraph as Record<string, unknown> | undefined)?.run_id });
    return { prediction: "BENIGN", score: 0, threshold: 0.5, mode: "block" };
  }) as typeof firewall.classify;
  return { firewall, calls };
}

function echoModel() {
  class EchoModel extends FakeListChatModel {
    override bindTools() { return this; }
    override async _generate(messages: BaseMessage[]) {
      const text = `answer:${[...messages].reverse().find(HumanMessage.isInstance)?.content}`;
      return { generations: [{ text, message: new AIMessage(text) }] };
    }
  }
  return new EchoModel({ responses: ["unused"] });
}

describe("native thread identity", () => {
  it.each([undefined, null, "", "  ", 1, true, {}, []])("omits invalid native ID %j", (id) => {
    expect(nativeThreadId({ configurable: { thread_id: id } }, { thread_id: "metadata" }, "parent")).toBeUndefined();
  });

  it("preserves exact native ID and prioritizes native runtime over metadata", () => {
    expect(nativeThreadId({ configurable: { thread_id: " native " } }, { thread_id: "metadata" })).toBe(" native ");
  });

  it("keeps child identities and prunes complete or failed root subtrees", () => {
    const threads = new RunThreadIdentity();
    threads.start("root", undefined, { thread_id: "root-thread", langgraph_node: "root" });
    threads.start("child", "root");
    threads.start("independent", "child", { thread_id: "child-thread" });
    expect(threads.get("child")).toBe("root-thread");
    expect(threads.get("independent")).toBe("child-thread");
    threads.finish("root");
    expect(threads.get("child")).toBeUndefined();
    expect(threads.get("independent")).toBeUndefined();
  });

  it("omits repeated or absent unproven child context but keeps distinct and orphan identities", () => {
    const threads = new RunThreadIdentity();
    threads.start("ordinary-parent", undefined, { thread_id: "parent-thread" });
    threads.start("ambiguous-child", "ordinary-parent", { thread_id: "parent-thread" });
    threads.start("missing-child", "ordinary-parent");
    threads.start("distinct-child", "ordinary-parent", { thread_id: "child-thread" });
    threads.start("invalid-child", "ordinary-parent", { thread_id: "" });
    threads.start("orphan", "unknown-parent", { thread_id: "parent-thread" });
    expect(threads.get("ambiguous-child")).toBeUndefined();
    expect(threads.get("missing-child")).toBeUndefined();
    expect(threads.get("distinct-child")).toBe("child-thread");
    expect(threads.get("invalid-child")).toBeUndefined();
    expect(threads.get("orphan")).toBe("parent-thread");
  });

  it("limits bound native authority to its root", () => {
    const threads = new RunThreadIdentity({ threadId: "bound-root" });
    threads.start("root", undefined, { thread_id: "wrong" });
    threads.start("missing-child", "root");
    threads.start("repeated-child", "root", { thread_id: "bound-root" });
    threads.start("distinct-child", "root", { thread_id: "child-native" });
    expect(threads.get("root")).toBe("bound-root");
    expect(threads.get("missing-child")).toBeUndefined();
    expect(threads.get("repeated-child")).toBeUndefined();
    expect(threads.get("distinct-child")).toBe("child-native");
  });

  it("inherits graph-proven identity from step zero without requiring exposed thread metadata", () => {
    const threads = new RunThreadIdentity(undefined, () => ({
      configurable: { thread_id: "current-graph" },
    }));
    threads.start("graph-parent", undefined, { langgraph_step: 0 });
    threads.start("missing-child", "graph-parent");
    threads.start("repeated-child", "graph-parent", { thread_id: "current-graph" });
    expect(threads.get("graph-parent")).toBe("current-graph");
    expect(threads.get("missing-child")).toBe("current-graph");
    expect(threads.get("repeated-child")).toBe("current-graph");
  });

  it("rejects removed options at every JavaScript entrypoint", async () => {
    const { firewall } = recordingFirewall();
    for (const option of ["conversationId", "conversation_id"]) {
      await expect(createLangChainHandler(firewall, { [option]: "old" } as never)).rejects.toThrow(/configurable.thread_id/);
      expect(() => createDeepAgentsMiddleware(firewall, { [option]: "old" } as never)).toThrow(/configurable.thread_id/);
      expect(() => createProtectedDeepAgent(firewall, { silmaril: { [option]: "old" } } as never)).toThrow(/configurable.thread_id/);
      expect(() => createProtectedCompiledSubagent(firewall, {
        name: "review", description: "Review", model: echoModel(), silmaril: { [option]: "old" },
      } as never)).toThrow(/configurable.thread_id/);
    }
  });
});

describe("callback identity lifecycle", () => {
  it.each([
    ["model", "handleChatModelStart", "handleLLMEnd", "handleLLMError"],
    ["tool", "handleToolStart", "handleToolEnd", "handleToolError"],
    ["retriever", "handleRetrieverStart", "handleRetrieverEnd", "handleRetrieverError"],
  ])("retains %s end identity even when its start hook is disabled", async (kind, start, end, error) => {
    const { firewall, calls } = recordingFirewall();
    const handler = await createLangChainHandler(firewall, { hooks: new Set([
      FirewallHook.LLM_END, FirewallHook.TOOL_END, FirewallHook.RETRIEVER_END,
    ]) });
    const lifecycle = handler as unknown as Record<string, (...args: any[]) => Promise<void>>;
    const startArgs = kind === "model" ? [{}, [[new HumanMessage("hello")]], "run", undefined, undefined, undefined, { thread_id: "native" }]
      : [{ name: "search" }, "hello", "run", undefined, undefined, { thread_id: "native" }];
    await lifecycle[start!]!(...startArgs);
    const output = kind === "model" ? { generations: [[{ text: "answer" }]] }
      : kind === "tool" ? "result" : [new Document({ pageContent: "document" })];
    await lifecycle[end!]!(output, "run");
    expect(calls.map((call) => call.conversationId)).toEqual(["native"]);
    // Same run ID after completion has no retained conversation.
    await lifecycle[end!]!(output, "run");
    expect(calls.at(-1)?.conversationId).toBeUndefined();
    await lifecycle[start!]!(...startArgs);
    await lifecycle[error!]!(new Error("failed"), "run");
    await lifecycle[end!]!(output, "run");
    expect(calls.at(-1)?.conversationId).toBeUndefined();
  });

  it("bounds callback-only abandoned runs without retaining prompts or tokens", async () => {
    const { firewall, calls } = recordingFirewall();
    const handler = await createLangChainHandler(firewall, { hooks: new Set([FirewallHook.LLM_END]) });
    const secret = "private prompt and token contents";
    await handler.handleChainStart!({} as never, { input: secret }, "evicted-chain", undefined, [], { thread_id: "old-thread" });
    for (let i = 0; i < 4100; i++) {
      await handler.handleLLMStart!({} as never, [secret], `abandoned-${i}`, undefined, undefined, [], { thread_id: `thread-${i}` });
      await handler.handleLLMNewToken!(secret, { prompt: 0, completion: 0 }, `abandoned-${i}`);
    }
    const tracer = handler as unknown as { runMap: Map<string, unknown>; runTreeMap: Map<string, unknown> };
    expect(tracer.runMap.size).toBeLessThanOrEqual(4096);
    expect(tracer.runTreeMap.size).toBe(0);
    expect(JSON.stringify([...tracer.runMap.values()])).not.toContain(secret);
    expect(tracer.runMap.has("evicted-chain")).toBe(false);
    await expect(handler.handleChainEnd!({ output: "successful completion" }, "evicted-chain")).resolves.toBeDefined();
    expect(tracer.runMap.has("evicted-chain")).toBe(false);
    await handler.handleLLMEnd!({ generations: [[{ text: "safe" }]] }, "abandoned-0");
    expect(calls.at(-1)?.conversationId).toBeUndefined();
  });

  it("uses real parent dispatch order and clears descendants on root completion/error", async () => {
    const { firewall, calls } = recordingFirewall();
    const handler = await createLangChainHandler(firewall);
    for (const terminal of ["handleChainEnd", "handleChainError"]) {
      const lifecycle = handler as unknown as Record<string, (...args: any[]) => Promise<void>>;
      await lifecycle.handleChainStart!({}, {}, "root", undefined, [], { thread_id: "parent", langgraph_node: "root" });
      await handler.handleToolStart!({ name: "search" } as never, "hello", "child", "root");
      expect(calls.at(-1)?.conversationId).toBe("parent");
      await lifecycle[terminal]!({}, "root");
      await handler.handleToolEnd!("late result", "child");
      expect(calls.at(-1)?.conversationId).toBeUndefined();
    }
  });

  it("cleans a denied start immediately without waiting for a framework error callback", async () => {
    const { firewall, calls } = recordingFirewall();
    const classify = firewall.classify.bind(firewall);
    firewall.classify = vi.fn(async (text, options) => {
      const result = await classify(text, options);
      return { ...result, prediction: text === "deny" ? "MALICIOUS" : "BENIGN" };
    }) as typeof firewall.classify;
    const handler = await createLangChainHandler(firewall);
    await expect(handler.handleToolStart!({ name: "search" } as never, "deny", "run", undefined, [], { thread_id: "blocked" })).rejects.toThrow();
    await handler.handleToolEnd!("result", "run");
    expect(calls.at(-1)?.conversationId).toBeUndefined();
  });
});

describe("real LangChain and LangGraph execution", () => {
  it("uses native graph config across all callback boundaries and reuses one handler", async () => {
    const { firewall, calls } = recordingFirewall();
    const handler = await createLangChainHandler(firewall, { hooks: ALL_HOOKS });
    const model = echoModel();
    const search = tool(async ({ query }) => `tool:${query}`, { name: "search", description: "Search", schema: z.object({ query: z.string() }) });
    const retriever = new FakeRetriever({ output: [new Document({ pageContent: "document" })] });
    const graph = new StateGraph(MessagesAnnotation).addNode("work", async (state) => {
      const query = String([...state.messages].reverse().find(HumanMessage.isInstance)?.content);
      await search.invoke({ query });
      await retriever.invoke(query);
      return { messages: [await model.invoke(state.messages)] };
    }).addEdge(START, "work").addEdge("work", END).compile();
    for (const thread of ["one", "two", undefined]) {
      const first = calls.length;
      await graph.invoke({ messages: [new HumanMessage(thread ?? "independent")] }, {
        callbacks: [handler], ...(thread === undefined ? {} : { configurable: { thread_id: thread }, metadata: { thread_id: "wrong" } }),
      });
      const batch = calls.slice(first);
      expect(new Set(batch.map((call) => call.hook))).toEqual(new Set([
        HookLabel.USER_INPUT, HookLabel.LLM_OUTPUT, HookLabel.TOOL_CALL, HookLabel.TOOL_RESPONSE,
      ]));
      expect(batch.map((call) => [call.hook, call.text, call.conversationId])).toEqual(batch.map((call) => [call.hook, call.text, thread]));
      expect(batch.every((call) => typeof call.runId === "string")).toBe(true);
      const tracer = handler as unknown as { runMap: Map<string, unknown>; runTreeMap: Map<string, unknown> };
      expect(tracer.runMap.size).toBe(0);
      expect(tracer.runTreeMap.size).toBe(0);
    }
  });

  it("keeps native conversation identity through checkpoint interrupt and resume", async () => {
    const { firewall, calls } = recordingFirewall();
    const handler = await createLangChainHandler(firewall, { hooks: ALL_HOOKS });
    const model = echoModel();
    const graph = new StateGraph(MessagesAnnotation)
      .addNode("before", async (state) => ({ messages: [await model.invoke(state.messages)] }))
      .addNode("approval", () => { interrupt("continue?"); return {}; })
      .addNode("after", async (state) => ({ messages: [await model.invoke(state.messages)] }))
      .addEdge(START, "before").addEdge("before", "approval").addEdge("approval", "after").addEdge("after", END)
      .compile({ checkpointer: new MemorySaver() });
    const config = { configurable: { thread_id: "resumed-thread" }, callbacks: [handler] };
    await graph.invoke({ messages: [new HumanMessage("hello")] }, config);
    const first = calls.length;
    expect(first).toBe(2);
    await graph.invoke(new Command({ resume: true }), config);
    expect(calls.length).toBe(4);
    expect(calls.every((call) => call.conversationId === "resumed-thread")).toBe(true);
  });

  it("isolates interleaved executions on one graph and handler", async () => {
    const { firewall, calls } = recordingFirewall();
    const handler = await createLangChainHandler(firewall, { hooks: ALL_HOOKS });
    let releaseFirst!: () => void;
    const firstMayFinish = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const search = tool(async ({ query }) => {
      if (query === "first") await firstMayFinish;
      else releaseFirst();
      return `tool:${query}`;
    }, { name: "search", description: "Search", schema: z.object({ query: z.string() }) });
    const model = echoModel();
    const graph = new StateGraph(MessagesAnnotation).addNode("work", async (state) => {
      const query = String(state.messages.at(-1)?.content);
      await search.invoke({ query });
      return { messages: [await model.invoke(state.messages)] };
    }).addEdge(START, "work").addEdge("work", END).compile();
    await Promise.all(["first", "second"].map((thread) => graph.invoke({ messages: [new HumanMessage(thread)] }, {
      callbacks: [handler], configurable: { thread_id: thread },
    })));
    for (const call of calls) {
      expect(call.conversationId).toBe(call.text.includes("first") ? "first" : "second");
    }
  });

  it("preserves a real output denial and clears native tracer maps after failure", async () => {
    const { firewall } = recordingFirewall();
    firewall.classify = vi.fn(async (_text, options) => ({
      prediction: options?.hook === HookLabel.LLM_OUTPUT ? "MALICIOUS" : "BENIGN",
      score: 0.9, threshold: 0.5, mode: "block",
    })) as typeof firewall.classify;
    const handler = await createLangChainHandler(firewall, { hooks: ALL_HOOKS });
    const model = echoModel();
    const graph = new StateGraph(MessagesAnnotation).addNode("work", async (state) => ({ messages: [await model.invoke(state.messages)] }))
      .addEdge(START, "work").addEdge("work", END).compile();
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    await expect(graph.invoke({ messages: [new HumanMessage("hello")] }, {
      callbacks: [handler], configurable: { thread_id: "blocked-thread" },
    })).rejects.toThrow(/blocked/i);
    const tracer = handler as unknown as { runMap: Map<string, unknown>; runTreeMap: Map<string, unknown> };
    expect(tracer.runMap.size).toBe(0);
    expect(tracer.runTreeMap.size).toBe(0);
  });

  it("omits hidden identity in standalone callback-only runnable context", async () => {
    const { firewall, calls } = recordingFirewall();
    const handler = await createLangChainHandler(firewall, { hooks: ALL_HOOKS });
    const model = echoModel();
    const runnable = RunnableLambda.from(async (input: string) => model.invoke(input));
    await runnable.invoke("hello", { configurable: { thread_id: "native-chain" }, callbacks: [handler] });
    expect(calls).toHaveLength(2);
    expect(calls.every((call) => call.conversationId === undefined)).toBe(true);
  });

  it("does not invent identity when a direct-root model exposes configurable only to tracing", async () => {
    const { firewall, calls } = recordingFirewall();
    const handler = await createLangChainHandler(firewall, { hooks: ALL_HOOKS });
    await echoModel().invoke("hello", { configurable: { thread_id: "not-exposed" }, callbacks: [handler] });
    expect(calls).toHaveLength(2);
    expect(calls.every((call) => call.conversationId === undefined)).toBe(true);
  });
});

describe("protected native LangChain runnable", () => {
  it("preserves pre-bound native defaults for invoke, batch and streaming", async () => {
    const { firewall, calls } = recordingFirewall();
    const underlying = echoModel();
    const bound = underlying.withConfig({ configurable: { thread_id: "saved-thread" } });
    const originalBound = (bound as unknown as { bound: unknown }).bound;
    const model = await protectLangChainRunnable(firewall, bound, { hooks: ALL_HOOKS });
    await model.invoke("saved invoke");
    await model.batch(["saved batch one", "saved batch two"]);
    const stream = await model.stream("saved stream");
    for await (const _chunk of stream) { /* consume */ }
    expect(calls.length).toBeGreaterThanOrEqual(7);
    expect(calls.every((call) => call.conversationId === "saved-thread")).toBe(true);
    expect((bound as unknown as { bound: unknown }).bound).toBe(originalBound);
  });

  it("keeps native overrides authoritative over nested saved defaults, ambient config and metadata", async () => {
    const { firewall, calls } = recordingFirewall();
    const inner = echoModel().withConfig({ configurable: { thread_id: "inner-default" } });
    const bound = new RunnableBinding({ bound: inner, config: { configurable: { thread_id: "outer-default" } } });
    const model = await protectLangChainRunnable(firewall, bound, { hooks: ALL_HOOKS });
    await model.invoke("default");
    expect(calls.every((call) => call.conversationId === "outer-default")).toBe(true);
    const first = calls.length;
    const parent = RunnableLambda.from(async () => model.invoke("override", {
      configurable: { thread_id: "explicit-thread" }, metadata: { thread_id: "wrong" },
    }));
    await parent.invoke("start", { configurable: { thread_id: "ambient-thread" } });
    expect(calls.slice(first).map((call) => call.conversationId)).toEqual(["explicit-thread", "explicit-thread"]);
    const batchFirst = calls.length;
    await model.batch(["override-a", "override-b", "default-item"], [
      { configurable: { thread_id: "batch-a" } }, { configurable: { thread_id: "batch-b" } }, {},
    ]);
    for (const call of calls.slice(batchFirst)) {
      expect(call.conversationId).toBe(call.text.includes("override-a") ? "batch-a" : call.text.includes("override-b") ? "batch-b" : "outer-default");
    }
    const invalid = calls.length;
    await model.invoke("independent", { configurable: { thread_id: "" }, metadata: { thread_id: "wrong" } });
    expect(calls.slice(invalid).every((call) => call.conversationId === undefined)).toBe(true);
  });

  it("executes existing config factories once and preserves native callbacks and retry settings", async () => {
    const { firewall, calls } = recordingFirewall();
    const observer = { name: "observer", handleLLMEnd: vi.fn() };
    const factory = vi.fn(async () => ({ configurable: { thread_id: "factory-thread" }, callbacks: [observer] }));
    const bound = new RunnableBinding({ bound: echoModel(), config: {}, configFactories: [factory] }).withRetry({ stopAfterAttempt: 2 });
    // Native withRetry drops factories, so test the factory-bearing binding as
    // its own outer layer while retaining an already configured retry wrapper.
    const configured = new RunnableBinding({ bound, config: {}, configFactories: [factory] });
    const model = await protectLangChainRunnable(firewall, configured, { hooks: ALL_HOOKS });
    await model.invoke("invoke");
    expect(factory).toHaveBeenCalledTimes(1);
    expect(observer.handleLLMEnd).toHaveBeenCalledTimes(1);
    expect(calls.map((call) => call.conversationId)).toEqual(["factory-thread", "factory-thread"]);
    await model.batch(["batch-one", "batch-two"], [{}, {}]);
    expect(factory).toHaveBeenCalledTimes(3);
    expect(observer.handleLLMEnd).toHaveBeenCalledTimes(3);
    const stream = await model.stream("stream");
    for await (const _chunk of stream) { /* consume */ }
    expect(factory).toHaveBeenCalledTimes(4);
    expect(calls.every((call) => call.conversationId === "factory-thread")).toBe(true);
  });

  it.each(["withConfig", "withRetry", "withListeners"] as const)("preserves existing dynamic factories after %s", async (method) => {
    const { firewall, calls } = recordingFirewall();
    const observer = { name: "observer", handleLLMEnd: vi.fn() };
    const factory = vi.fn(() => ({ configurable: { thread_id: "factory-thread" }, callbacks: [observer] }));
    const original = new RunnableBinding({ bound: echoModel(), config: {}, configFactories: [factory] });
    const protectedModel = await protectLangChainRunnable(firewall, original, { hooks: ALL_HOOKS });
    const model = method === "withConfig" ? protectedModel.withConfig({ tags: ["configured"] })
      : method === "withRetry" ? protectedModel.withRetry({ stopAfterAttempt: 2 })
      : protectedModel.withListeners({ onEnd: () => undefined });
    await model.invoke("hello");
    expect(factory).toHaveBeenCalledTimes(1);
    expect(observer.handleLLMEnd).toHaveBeenCalledTimes(1);
    expect(calls.map((call) => call.conversationId)).toEqual(["factory-thread", "factory-thread"]);
  });

  it("captures direct-root and hidden nested overrides without caller conversation options", async () => {
    const { firewall, calls } = recordingFirewall();
    const model = await protectLangChainRunnable(firewall, echoModel(), { hooks: ALL_HOOKS });
    const caller = { name: "observer", handleLLMEnd: vi.fn() };
    await model.invoke("root", { configurable: { thread_id: "root-thread" }, metadata: { thread_id: "wrong" }, callbacks: [caller] });
    expect(calls.map((call) => call.conversationId)).toEqual(["root-thread", "root-thread"]);
    const parent = RunnableLambda.from(async () => model.invoke("child", { configurable: { thread_id: "child-thread" } }));
    const first = calls.length;
    await parent.invoke("start", { configurable: { thread_id: "parent-thread" } });
    expect(calls.slice(first).map((call) => call.conversationId)).toEqual(["child-thread", "child-thread"]);
    expect(caller.handleLLMEnd).toHaveBeenCalledOnce();
    const independent = calls.length;
    await model.invoke("independent", { metadata: { thread_id: "not-native" } });
    expect(calls.slice(independent).every((call) => call.conversationId === undefined)).toBe(true);
  });

  it("does not misattribute hidden callback-only child overrides to a parent thread", async () => {
    const { firewall, calls } = recordingFirewall();
    const handler = await createLangChainHandler(firewall, { hooks: ALL_HOOKS });
    const model = echoModel();
    const parent = RunnableLambda.from(async (_input: string, config) => model.invoke("child", {
      ...config,
      configurable: { ...config?.configurable, thread_id: "child-native" },
    }));
    await parent.invoke("start", {
      callbacks: [handler],
      configurable: { thread_id: "parent-native" },
      metadata: { thread_id: "parent-native" },
    });
    expect(calls).toHaveLength(2);
    expect(calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT, HookLabel.LLM_OUTPUT]);
    expect(calls.every((call) => call.conversationId === undefined)).toBe(true);
  });

  it("keeps a protected child's hidden native override authoritative over forwarded parent metadata", async () => {
    const { firewall, calls } = recordingFirewall();
    const model = await protectLangChainRunnable(firewall, echoModel(), { hooks: ALL_HOOKS });
    const parent = RunnableLambda.from(async (_input: string, config) => model.invoke("child", {
      ...config,
      configurable: { ...config?.configurable, thread_id: "child-native" },
    }));
    await parent.invoke("start", {
      configurable: { thread_id: "parent-native" },
      metadata: { thread_id: "parent-native" },
    });
    expect(calls).toHaveLength(2);
    expect(calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT, HookLabel.LLM_OUTPUT]);
    expect(calls.every((call) => call.conversationId === "child-native")).toBe(true);
  });

  it("does not propagate a protected outer root identity into an ambiguous bare child", async () => {
    const { firewall, calls } = recordingFirewall();
    const bareModel = echoModel();
    const outer = await protectLangChainRunnable(firewall, RunnableLambda.from(async (_input: string, config) => {
      return bareModel.invoke("child", {
        ...config,
        configurable: { ...config?.configurable, thread_id: "child-native" },
      });
    }), { hooks: ALL_HOOKS });
    await outer.invoke("start", {
      configurable: { thread_id: "parent-native" },
      metadata: { thread_id: "parent-native" },
    });
    expect(calls).toHaveLength(2);
    expect(calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT, HookLabel.LLM_OUTPUT]);
    expect(calls.every((call) => call.conversationId === undefined)).toBe(true);
  });

  it("uses a separately executing child graph’s native thread instead of the wrapped parent", async () => {
    const { firewall, calls } = recordingFirewall();
    const model = echoModel();
    const child = new StateGraph(MessagesAnnotation).addNode("work", async (state) => ({
      messages: [await model.invoke(state.messages)],
    })).addEdge(START, "work").addEdge("work", END).compile();
    const outer = await protectLangChainRunnable(firewall, RunnableLambda.from(async (_input: string, config) => {
      return child.invoke({ messages: [new HumanMessage("child")] }, {
        ...config, configurable: { ...config?.configurable, thread_id: "child-thread" },
      });
    }), { hooks: ALL_HOOKS });
    await outer.invoke("parent", { configurable: { thread_id: "parent-thread" } });
    expect(calls).toHaveLength(2);
    expect(calls.every((call) => call.conversationId === "child-thread")).toBe(true);
  });

  it("preserves per-item batch IDs and threadless items", async () => {
    const { firewall, calls } = recordingFirewall();
    const model = await protectLangChainRunnable(firewall, echoModel(), { hooks: ALL_HOOKS });
    const output = await model.batch(["first", "second", "independent"], [
      { configurable: { thread_id: "first" } }, { configurable: { thread_id: "second" } }, {},
    ]);
    expect(output).toHaveLength(3);
    for (const call of calls) {
      const expected = call.text.includes("first") ? "first" : call.text.includes("second") ? "second" : undefined;
      expect(call.conversationId).toBe(expected);
    }
  });

  it("cleans invocation handlers when a stream is closed early", async () => {
    const { firewall } = recordingFirewall();
    const underlying = echoModel();
    const observed: Array<{ runMap: Map<string, unknown>; runTreeMap: Map<string, unknown> }> = [];
    const original = underlying.stream.bind(underlying);
    vi.spyOn(underlying, "stream").mockImplementation(async (input, config) => {
      const callbacks = config?.callbacks;
      for (const handler of Array.isArray(callbacks) ? callbacks : callbacks?.handlers ?? []) {
        if ("runMap" in handler) observed.push(handler as unknown as typeof observed[number]);
      }
      return original(input, config);
    });
    const model = await protectLangChainRunnable(firewall, underlying);
    for (let i = 0; i < 3; i++) {
      const stream = await model.stream("private prompt", { configurable: { thread_id: `thread-${i}` } });
      for await (const _chunk of stream) break;
    }
    expect(observed).toHaveLength(3);
    expect(observed.every((handler) => handler.runMap.size === 0 && handler.runTreeMap.size === 0)).toBe(true);
  });

  it("retains protection through withConfig, retry and streaming", async () => {
    const { firewall, calls } = recordingFirewall();
    const model = await protectLangChainRunnable(firewall, echoModel(), { hooks: ALL_HOOKS });
    const onStart = vi.fn();
    const stream = await model.withConfig({ configurable: { thread_id: "stream" } }).withRetry().withListeners({ onStart }).stream("hello");
    let chunks = 0;
    for await (const _chunk of stream) chunks++;
    expect(chunks).toBeGreaterThan(0);
    expect(onStart).toHaveBeenCalled();
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every((call) => call.conversationId === "stream")).toBe(true);
  });

  it.each([undefined, null, "", "  ", 1, true, {}, []])("omits invalid bound identity %j", async (id) => {
    const { firewall, calls } = recordingFirewall();
    const model = await protectLangChainRunnable(firewall, echoModel());
    await model.invoke("hello", { configurable: { thread_id: id }, metadata: { thread_id: "wrong" } });
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every((call) => call.conversationId === undefined)).toBe(true);
  });
});

describe("real Deep Agents thread identity", () => {
  it("resumes turns on one thread while isolating other threads with one agent", async () => {
    const { firewall, calls } = recordingFirewall();
    const agent = createProtectedDeepAgent(firewall, { model: echoModel(), checkpointer: new MemorySaver() });
    for (const [thread, text] of [["one", "hello"], ["two", "different"], ["one", "continue"]]) {
      const first = calls.length;
      const output = await agent.invoke({ messages: [new HumanMessage(text!)] }, { configurable: { thread_id: thread! } });
      expect(calls.slice(first).every((call) => call.conversationId === thread)).toBe(true);
      expect(output.messages.filter(HumanMessage.isInstance).map((message: HumanMessage) => message.content)).toEqual(
        text === "continue" ? ["hello", "continue"] : [text],
      );
    }
  });

  it("isolates overlapping model boundaries and a subsequent threadless invocation", async () => {
    const { firewall, calls } = recordingFirewall();
    const agent = createProtectedDeepAgent(firewall, { model: echoModel() });
    await Promise.all(["alpha", "beta"].map((thread) => agent.invoke({ messages: [new HumanMessage(thread)] }, { configurable: { thread_id: thread } })));
    expect(calls.map((call) => [call.text, call.conversationId])).toEqual(calls.map((call) => [call.text, call.text.includes("alpha") ? "alpha" : "beta"]));
    const first = calls.length;
    await agent.invoke({ messages: [new HumanMessage("independent")] });
    expect(calls.slice(first).every((call) => call.conversationId === undefined)).toBe(true);
  });

  it("covers nested protected agent work inside a declarative subagent", async () => {
    const { firewall, calls } = recordingFirewall();
    const nested = createProtectedDeepAgent(firewall, { model: echoModel() });
    const lookup = tool(async (_args, config) => {
      const result = await nested.invoke({ messages: [new HumanMessage("nested research")] }, config);
      return String(result.messages.at(-1)?.content);
    }, { name: "lookup", description: "Run nested research", schema: z.object({}) });
    const root = fakeModel().respondWithTools([{ name: "task", args: { description: "Research", subagent_type: "research" }, id: "task" }])
      .respond(new AIMessage("done"));
    const researcher = fakeModel().respondWithTools([{ name: "lookup", args: {}, id: "lookup" }]).respond(new AIMessage("research done"));
    const agent = createProtectedDeepAgent(firewall, { model: root, subagents: [
      { name: "research", description: "Research", model: researcher, tools: [lookup] },
    ] });
    await agent.invoke({ messages: [new HumanMessage("start")] }, { configurable: { thread_id: "nested-thread" } });
    expect(calls.some((call) => call.text === "nested research")).toBe(true);
    expect(calls.every((call) => call.conversationId === "nested-thread")).toBe(true);
  });

  it("retains request identity after interleaved tool completion", async () => {
    const { firewall, calls } = recordingFirewall();
    const middleware = createDeepAgentsMiddleware(firewall);
    let release!: () => void;
    const wait = new Promise<void>((resolve) => { release = resolve; });
    const run = (thread: string) => middleware.wrapToolCall!({
      toolCall: { id: thread, name: "search", args: { query: thread } }, state: { messages: [] }, runtime: { configurable: { thread_id: thread } },
    } as never, async () => {
      if (thread === "first") await wait;
      else release();
      return new ToolMessage({ content: `result:${thread}`, tool_call_id: thread });
    });
    await Promise.all([run("first"), run("second")]);
    expect(calls).toHaveLength(4);
    for (const call of calls) expect(call.conversationId).toBe(call.text.includes("first") ? "first" : "second");
  });
});
