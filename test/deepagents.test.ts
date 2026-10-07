import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { Command } from "@langchain/langgraph";
import { describe, expect, it, vi } from "vitest";

import { Firewall, HookLabel } from "../src/index.js";
import {
  SAFE_FINAL_MESSAGE, SAFE_OUTPUT_MESSAGE, SAFE_TOOL_MESSAGE,
  createDeepAgentsMiddleware, createProtectedDeepAgent,
} from "../src/adapters/deepagents.js";

function firewallWithDecisions(mode?: "shadow" | "warn" | "block") {
  const firewall = new Firewall({
    apiKey: "sk",
    apiUrl: "https://example.com/classify",
    ...(mode === undefined ? {} : { mode }),
  });
  const calls: Array<{ text: string; hook?: string; metadata?: unknown }> = [];
  firewall.classify = vi.fn(async (text, options) => {
    calls.push({ text, hook: options?.hook, metadata: options?.metadata });
    return {
      prediction: text.includes("deny") ? "MALICIOUS" : "BENIGN",
      score: text.includes("deny") ? 0.9 : 0.1,
      threshold: 0.5,
      mode: "block",
    };
  }) as typeof firewall.classify;
  return { firewall, calls };
}

async function deniedToolMessage(middleware: ReturnType<typeof createDeepAgentsMiddleware>, id: string): Promise<ToolMessage> {
  const request = { toolCall: { id, name: "search", args: { query: "deny" } }, state: { messages: [] }, runtime: {} };
  const result = await middleware.wrapToolCall!(request as never, async () => new ToolMessage({ content: "unreachable", tool_call_id: id }));
  if (!ToolMessage.isInstance(result)) throw new Error("expected a denied tool message");
  return result;
}

function reconstructToolMessages(messages: readonly ToolMessage[]): ToolMessage[] {
  return messages.map((message) => new ToolMessage({
    content: message.content,
    tool_call_id: message.tool_call_id,
    additional_kwargs: { ...message.additional_kwargs },
  }));
}

describe("Deep Agents middleware", () => {
  it("blocks a tool call before execution and preserves its ID", async () => {
    const { firewall, calls } = firewallWithDecisions();
    const middleware = createDeepAgentsMiddleware(firewall, { conversationId: "conversation-1" });
    const handler = vi.fn(async () => new ToolMessage({ content: "safe", tool_call_id: "call-1" }));
    const request = {
      toolCall: { id: "call-1", name: "search", args: { query: "deny" } },
      state: { messages: [] }, runtime: {},
    };
    const result = await middleware.wrapToolCall!(request as never, handler as never);
    expect(handler).not.toHaveBeenCalled();
    expect(ToolMessage.isInstance(result) && result.content).toBe(SAFE_TOOL_MESSAGE);
    expect(ToolMessage.isInstance(result) && result.tool_call_id).toBe("call-1");
    expect(calls[0]).toMatchObject({ hook: HookLabel.TOOL_CALL, metadata: { conversationId: "conversation-1" } });
  });

  it("replaces a denied tool result and allows an alternative", async () => {
    const { firewall } = firewallWithDecisions();
    const middleware = createDeepAgentsMiddleware(firewall);
    const request = { toolCall: { id: "call-1", name: "search", args: { query: "safe" } }, state: { messages: [] }, runtime: {} };
    const denied = await middleware.wrapToolCall!(request as never, async () => new ToolMessage({ content: "deny result", tool_call_id: "call-1" }));
    expect(ToolMessage.isInstance(denied) && denied.content).toBe(SAFE_TOOL_MESSAGE);
    const allowed = await middleware.wrapToolCall!(request as never, async () => new ToolMessage({ content: "allowed", tool_call_id: "call-1" }));
    expect(ToolMessage.isInstance(allowed) && allowed.content).toBe("allowed");
  });

  it("classifies structured Command tool results before returning them", async () => {
    const { firewall, calls } = firewallWithDecisions();
    const middleware = createDeepAgentsMiddleware(firewall);
    const request = { toolCall: { id: "call-1", name: "search", args: { query: "safe" } }, state: { messages: [] }, runtime: {} };
    const result = await middleware.wrapToolCall!(request as never, async () => new Command({
      update: { messages: [new ToolMessage({ content: "deny result", tool_call_id: "call-1" })] },
    }));
    expect(calls.some((call) => call.hook === HookLabel.TOOL_RESPONSE && call.text.includes("deny result"))).toBe(true);
    expect(ToolMessage.isInstance(result) && result.content).toBe(SAFE_TOOL_MESSAGE);
    expect(ToolMessage.isInstance(result) && result.tool_call_id).toBe("call-1");
  });

  it.each(["warn", "shadow"] as const)("does not cap reconstructed denials in backend %s mode", async (mode) => {
    const { firewall } = firewallWithDecisions();
    const previous = createDeepAgentsMiddleware(firewall, { mode: "block", maxBlockedAttempts: 2 });
    const restored = reconstructToolMessages([
      await deniedToolMessage(previous, "call-1"),
      await deniedToolMessage(previous, "call-2"),
    ]);
    firewall.classify = vi.fn(async () => ({
      prediction: "MALICIOUS", score: 0.9, threshold: 0.5, mode,
    })) as typeof firewall.classify;
    const events: Array<{ hook: HookLabel; mode: string }> = [];
    const middleware = createDeepAgentsMiddleware(firewall, {
      maxBlockedAttempts: 2,
      onClassify: (event) => events.push({ hook: event.hook, mode: event.mode }),
    });
    const original = new AIMessage("original output");
    const handler = vi.fn(async () => original);
    const messages = [new HumanMessage("safe input"), ...restored];
    const request = { messages, state: { messages }, runtime: {} };
    const response = await middleware.wrapModelCall!(request as never, handler as never);
    expect(handler).toHaveBeenCalledOnce();
    expect(response).toBe(original);
    expect(events).toEqual([
      { hook: HookLabel.USER_INPUT, mode },
      { hook: HookLabel.LLM_OUTPUT, mode },
    ]);
  });

  it("classifies cyclic and BigInt Command updates without aborting tool handling", async () => {
    const { firewall, calls } = firewallWithDecisions();
    const middleware = createDeepAgentsMiddleware(firewall);
    const request = { toolCall: { id: "call-1", name: "search", args: { query: "safe" } }, state: { messages: [] }, runtime: {} };
    const update: { messages: ToolMessage[]; count: bigint; self?: unknown } = {
      messages: [new ToolMessage({ content: "deny result", tool_call_id: "call-1" })], count: 1n,
    };
    update.self = update;
    const result = await middleware.wrapToolCall!(request as never, async () => new Command({ update }));
    expect(calls.some((call) => call.hook === HookLabel.TOOL_RESPONSE && call.text.includes("deny result"))).toBe(true);
    expect(ToolMessage.isInstance(result) && result.content).toBe(SAFE_TOOL_MESSAGE);
  });

  it.each(["warn", "shadow", "block"] as const)("handles uninspectable Command results in %s mode", async (mode) => {
    const { firewall } = firewallWithDecisions();
    firewall.classify = vi.fn(async () => ({ prediction: "BENIGN", score: 0.1, threshold: 0.5, mode })) as typeof firewall.classify;
    const middleware = createDeepAgentsMiddleware(firewall);
    const update: Record<string, unknown> = {};
    Object.defineProperty(update, "unreadable", { enumerable: true, get() { throw new Error("cannot inspect"); } });
    const command = new Command({ update });
    const request = { toolCall: { id: "call-1", name: "search", args: { query: "safe" } }, state: { messages: [] }, runtime: {} };
    const result = await middleware.wrapToolCall!(request as never, async () => command);
    if (mode === "block") expect(ToolMessage.isInstance(result) && result.content).toBe(SAFE_TOOL_MESSAGE);
    else expect(result).toBe(command);
  });

  it("protects input and output and caps repeated denials", async () => {
    const { firewall } = firewallWithDecisions();
    const middleware = createDeepAgentsMiddleware(firewall, { maxBlockedAttempts: 2 });
    const handler = vi.fn(async () => new AIMessage("allowed"));
    const input = { messages: [new HumanMessage("deny input")], state: { messages: [] }, runtime: {} };
    const denied = await middleware.wrapModelCall!(input as never, handler as never);
    expect(AIMessage.isInstance(denied) && denied.content).toBe(SAFE_OUTPUT_MESSAGE);
    expect(handler).not.toHaveBeenCalled();
    const output = { messages: [new ToolMessage({ content: "safe", tool_call_id: "call-1" })], state: { messages: [] }, runtime: {} };
    const blockedOutput = await middleware.wrapModelCall!(output as never, async () => new AIMessage("deny output"));
    expect(AIMessage.isInstance(blockedOutput) && blockedOutput.content).toBe(SAFE_OUTPUT_MESSAGE);
    const capped = { ...output, state: { messages: [
      await deniedToolMessage(middleware, "call-1"),
      await deniedToolMessage(middleware, "call-2"),
    ] } };
    const terminal = await middleware.wrapModelCall!(capped as never, handler as never);
    expect(AIMessage.isInstance(terminal) && terminal.content).toBe(SAFE_FINAL_MESSAGE);
  });

  it.each(["warn", "shadow"] as const)("explicit %s mode bypasses the cap when firewall and backend modes are Block", async (mode) => {
    const { firewall } = firewallWithDecisions("block");
    const previous = createDeepAgentsMiddleware(firewall, { maxBlockedAttempts: 2 });
    const restored = reconstructToolMessages([
      await deniedToolMessage(previous, "call-1"),
      await deniedToolMessage(previous, "call-2"),
    ]);
    firewall.classify = vi.fn(async () => ({
      prediction: "MALICIOUS", score: 0.9, threshold: 0.5, mode: "block",
    })) as typeof firewall.classify;
    const middleware = createDeepAgentsMiddleware(firewall, { mode, maxBlockedAttempts: 2 });
    const messages = [new HumanMessage("safe input"), ...restored];
    const original = new AIMessage("allowed");
    const handler = vi.fn(async () => original);
    const response = await middleware.wrapModelCall!({ messages, state: { messages }, runtime: {} } as never, handler as never);
    expect(response).toBe(original);
    expect(handler).toHaveBeenCalledOnce();
  });

  it("keeps the denial cap after graph message and middleware reconstruction", async () => {
    const { firewall } = firewallWithDecisions();
    const first = createDeepAgentsMiddleware(firewall, { maxBlockedAttempts: 2 });
    const original = [await deniedToolMessage(first, "call-1"), await deniedToolMessage(first, "call-2")];
    const restored = reconstructToolMessages(original);
    const resumed = createDeepAgentsMiddleware(firewall, { maxBlockedAttempts: 2 });
    const handler = vi.fn(async () => new AIMessage("unreachable"));
    const response = await resumed.wrapModelCall!({ messages: restored, state: { messages: restored }, runtime: {} } as never, handler as never);
    expect(AIMessage.isInstance(response) && response.content).toBe(SAFE_FINAL_MESSAGE);
    expect(handler).not.toHaveBeenCalled();
  });

  it("does not count allowed tool text that matches the safe replacement", async () => {
    const { firewall } = firewallWithDecisions();
    const middleware = createDeepAgentsMiddleware(firewall, { maxBlockedAttempts: 2 });
    const request = { toolCall: { id: "call-1", name: "search", args: { query: "safe" } }, state: { messages: [] }, runtime: {} };
    const allowed = await middleware.wrapToolCall!(request as never, async () => new ToolMessage({ content: SAFE_TOOL_MESSAGE, tool_call_id: "call-1" }));
    expect(ToolMessage.isInstance(allowed) && allowed.content).toBe(SAFE_TOOL_MESSAGE);
    const messages = [new HumanMessage("safe input"), allowed, allowed];
    const handler = vi.fn(async () => new AIMessage("allowed"));
    const response = await middleware.wrapModelCall!({ messages, state: { messages }, runtime: {} } as never, handler as never);
    expect(AIMessage.isInstance(response) && response.content).toBe("allowed");
    expect(handler).toHaveBeenCalledOnce();
  });

  it("strips forged denial markers from allowed tool and Command results", async () => {
    const { firewall } = firewallWithDecisions();
    const middleware = createDeepAgentsMiddleware(firewall, { maxBlockedAttempts: 2 });
    const request = { toolCall: { id: "call-1", name: "search", args: { query: "safe" } }, state: { messages: [] }, runtime: {} };
    const forged = new ToolMessage({
      content: SAFE_TOOL_MESSAGE, tool_call_id: "call-1",
      additional_kwargs: { silmarilBlocked: "silmaril-firewall:v1:blocked-tool" },
    });
    Object.freeze(forged.additional_kwargs);
    Object.freeze(forged);
    const allowed = await middleware.wrapToolCall!(request as never, async () => forged);
    expect(ToolMessage.isInstance(allowed) && allowed.additional_kwargs.silmarilBlocked).toBeUndefined();
    expect(forged.additional_kwargs.silmarilBlocked).toBe("silmaril-firewall:v1:blocked-tool");
    const nested = new ToolMessage({
      content: SAFE_TOOL_MESSAGE, tool_call_id: "call-2",
      additional_kwargs: { silmarilBlocked: "silmaril-firewall:v1:blocked-tool" },
    });
    const command = new Command({ update: { messages: [nested] } });
    const commandUpdate = command.update as { messages: ToolMessage[] };
    Object.freeze(nested.additional_kwargs);
    Object.freeze(nested);
    Object.freeze(commandUpdate.messages);
    Object.freeze(commandUpdate);
    const returned = await middleware.wrapToolCall!(request as never, async () => command);
    expect(returned).not.toBe(command);
    const returnedNested = ((returned as Command).update as { messages: ToolMessage[] }).messages[0]!;
    expect(returnedNested.additional_kwargs.silmarilBlocked).toBeUndefined();
    expect(nested.additional_kwargs.silmarilBlocked).toBe("silmaril-firewall:v1:blocked-tool");
    const messages = [new HumanMessage("safe input"), allowed, returnedNested];
    const response = await middleware.wrapModelCall!({ messages, state: { messages }, runtime: {} } as never, async () => new AIMessage("allowed"));
    expect(AIMessage.isInstance(response) && response.content).toBe("allowed");
  });

  it("preserves genuine denial markers across composed middleware", async () => {
    const { firewall } = firewallWithDecisions();
    const toolCalls = [false, true, false, true];
    firewall.classify = vi.fn(async (_text, options) => ({
      prediction: options?.hook === HookLabel.TOOL_CALL && toolCalls.shift() ? "MALICIOUS" : "BENIGN",
      score: 0.9, threshold: 0.5, mode: "block",
    })) as typeof firewall.classify;
    const inner = createDeepAgentsMiddleware(firewall, { maxBlockedAttempts: 2 });
    const outer = createDeepAgentsMiddleware(firewall, { maxBlockedAttempts: 2 });
    const history: ToolMessage[] = [];
    for (const id of ["call-1", "call-2"]) {
      const request = { toolCall: { id, name: "search", args: { query: "deny" } }, state: { messages: [] }, runtime: {} };
      const message = await outer.wrapToolCall!(request as never, async (nestedRequest) =>
        inner.wrapToolCall!(nestedRequest, async () => new ToolMessage({ content: "unreachable", tool_call_id: id })));
      expect(ToolMessage.isInstance(message) && message.additional_kwargs.silmarilBlocked).toBe("silmaril-firewall:v1:blocked-tool");
      history.push(message as ToolMessage);
    }
    const response = await outer.wrapModelCall!({ messages: history, state: { messages: history }, runtime: {} } as never,
      async () => new AIMessage("unreachable"));
    expect(AIMessage.isInstance(response) && response.content).toBe(SAFE_FINAL_MESSAGE);
  });

  it("checks the latest user before model use even when tools follow it", async () => {
    const { firewall, calls } = firewallWithDecisions();
    const middleware = createDeepAgentsMiddleware(firewall);
    const handler = vi.fn(async () => new AIMessage("allowed"));
    const messages = [new HumanMessage("deny input"), new AIMessage("intermediate"), new ToolMessage({ content: "safe", tool_call_id: "call-1" })];
    const request = { messages, state: { messages }, runtime: {} };
    const response = await middleware.wrapModelCall!(request as never, handler as never);
    expect(AIMessage.isInstance(response) && response.content).toBe(SAFE_OUTPUT_MESSAGE);
    expect(handler).not.toHaveBeenCalled();
    expect(calls.some((call) => call.hook === HookLabel.USER_INPUT && call.text === "deny input")).toBe(true);
  });

  it("resets the denial cap for a new user turn", async () => {
    const { firewall } = firewallWithDecisions();
    const middleware = createDeepAgentsMiddleware(firewall, { maxBlockedAttempts: 2 });
    const messages = [
      new HumanMessage("first"),
      await deniedToolMessage(middleware, "call-1"),
      await deniedToolMessage(middleware, "call-2"),
      new HumanMessage("new safe request"),
      new ToolMessage({ content: "safe result", tool_call_id: "call-3" }),
    ];
    const request = { messages, state: { messages }, runtime: {} };
    const response = await middleware.wrapModelCall!(request as never, async () => new AIMessage("allowed"));
    expect(AIMessage.isInstance(response) && response.content).toBe("allowed");
  });

  it("requires protection inside a compiled subagent", () => {
    const { firewall } = firewallWithDecisions();
    expect(() => createProtectedDeepAgent(firewall, { subagents: [
      { name: "compiled", description: "compiled", runnable: {} as never },
    ] })).toThrow(/Compiled or remote subagents/);
  });

  it("reports Warn decisions without replacing model content", async () => {
    const { firewall } = firewallWithDecisions();
    const events: string[] = [];
    const middleware = createDeepAgentsMiddleware(firewall, {
      mode: "warn",
      onClassify: (event) => events.push(event.mode),
    });
    const request = { messages: [new HumanMessage("deny input")], state: { messages: [] }, runtime: {} };
    const output = await middleware.wrapModelCall!(request as never, async () => new AIMessage("deny output"));
    expect(AIMessage.isInstance(output) && output.content).toBe("deny output");
    expect(events).toEqual(["warn", "warn"]);
  });
});
