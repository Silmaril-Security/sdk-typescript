// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

import { AIMessage } from "@langchain/core/messages";
import { FakeListChatModel } from "@langchain/core/utils/testing";
import { describe, expect, it } from "vitest";

import { FirewallBlockedException, HookLabel } from "../src/index.js";
import { createLangChainHandler, protectLangChainRunnable } from "../src/adapters/langchain.js";
import { gatedFirewall, heldFirewall, settleQueue } from "./held.js";

interface Handler {
  handleChainStart: (chain: unknown, inputs: unknown, runId: string, parentRunId?: string, tags?: string[], metadata?: Record<string, unknown>) => Promise<unknown>;
  handleChatModelStart: (llm: unknown, messages: unknown, runId: string, parentRunId?: string) => Promise<unknown>;
  handleLLMNewToken: (token: string, idx: unknown, runId: string) => Promise<unknown>;
  handleLLMEnd: (output: unknown, runId: string) => Promise<unknown>;
  handleLLMError: (error: unknown, runId: string) => Promise<unknown>;
  handleToolStart: (tool: unknown, input: string, runId: string, parentRunId?: string) => Promise<unknown>;
  handleToolEnd: (output: unknown, runId: string, parentRunId?: string, tags?: string[], kwargs?: { name?: string }) => Promise<unknown>;
}

const USER = [[{ role: "user", content: "question" }]];
const ANSWER = { generations: [[{ text: "answer" }]] };

async function handlerFor(held: ReturnType<typeof heldFirewall>, options = {}): Promise<Handler> {
  return (await createLangChainHandler(held.firewall, options)) as unknown as Handler;
}

describe("LangChain adapter defaults", () => {
  it("classifies model output without options", async () => {
    const held = heldFirewall();
    held.release();
    const handler = await handlerFor(held);

    await handler.handleChatModelStart({}, USER, "model");
    await handler.handleLLMEnd(ANSWER, "model");

    expect(held.calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT, HookLabel.LLM_OUTPUT]);
  });
});

describe("LangChain adapter with parallel", () => {
  it("joins the input check when the model ends", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    const handler = await handlerFor(held, { parallel: true });

    await handler.handleChatModelStart({}, USER, "model");
    await held.started;
    await handler.handleLLMNewToken("partial", 0, "model");

    held.release();
    await expect(handler.handleLLMEnd(ANSWER, "model")).rejects.toMatchObject({
      hook: HookLabel.USER_INPUT,
    });
    expect(held.calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT]);
  });

  it("raises a block at the next hook once it has landed", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    held.release();
    const handler = await handlerFor(held, { parallel: true });

    await handler.handleChatModelStart({}, USER, "model");
    await held.firewall.flush();

    await expect(handler.handleLLMNewToken("partial", 0, "model")).rejects.toBeInstanceOf(
      FirewallBlockedException,
    );
  });

  it("still waits for a tool-call verdict", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    held.release();
    const handler = await handlerFor(held, { parallel: true });

    await expect(handler.handleToolStart({ name: "delete_records" }, "all", "tool")).rejects.toMatchObject({
      hook: HookLabel.TOOL_CALL,
    });
  });

  it("joins a tool result before the next tool runs", async () => {
    const held = heldFirewall(["BENIGN", "MALICIOUS"]);
    held.release();
    const handler = await handlerFor(held, { parallel: true });

    await handler.handleChainStart({}, {}, "graph");
    await handler.handleToolStart({ name: "search" }, "query", "tool-1", "graph");
    await handler.handleToolEnd("poisoned result", "tool-1", "graph", [], { name: "search" });

    await expect(handler.handleToolStart({ name: "send_email" }, "body", "tool-2", "graph")).rejects.toMatchObject({
      hook: HookLabel.TOOL_RESPONSE,
    });
    expect(held.calls.map((call) => call.hook)).toEqual([HookLabel.TOOL_CALL, HookLabel.TOOL_RESPONSE]);
  });

  it("joins a tool result at the next model end and keeps conversation order", async () => {
    const held = heldFirewall(["BENIGN", "MALICIOUS"]);
    held.release();
    const handler = await handlerFor(held, { parallel: true });
    const thread = { thread_id: "conversation-1", langgraph_step: 1 };

    await handler.handleChainStart({}, {}, "graph", undefined, [], thread);
    await handler.handleToolStart({ name: "search" }, "query", "tool", "graph");
    await handler.handleToolEnd("poisoned result", "tool", "graph", [], { name: "search" });
    await handler.handleChatModelStart({}, USER, "model", "graph");

    await expect(handler.handleLLMEnd(ANSWER, "model")).rejects.toMatchObject({
      hook: HookLabel.TOOL_RESPONSE,
    });
    await held.firewall.flush();
    expect(held.calls.map((call) => call.hook)).toEqual([
      HookLabel.TOOL_CALL, HookLabel.TOOL_RESPONSE, HookLabel.USER_INPUT,
    ]);
    expect(held.calls.every((call) => call.conversationId === "conversation-1")).toBe(true);
  });

  it("makes every concurrent tool wait for the same input verdict", async () => {
    const gated = gatedFirewall();
    const handler = (await createLangChainHandler(gated.firewall, { parallel: true })) as unknown as Handler;

    await handler.handleChainStart({}, {}, "graph");
    await handler.handleChatModelStart({}, USER, "model", "graph");
    await gated.arrived(1);
    const first = handler.handleToolStart({ name: "send_email" }, "body", "tool-1", "graph");
    const second = handler.handleToolStart({ name: "delete_records" }, "all", "tool-2", "graph");
    first.catch(() => undefined);
    second.catch(() => undefined);
    await settleQueue();
    expect(gated.calls.map((call) => call.text)).toEqual(["question"]);

    gated.calls[0]!.resolve("MALICIOUS");
    await expect(first).rejects.toMatchObject({ hook: HookLabel.USER_INPUT });
    await expect(second).rejects.toMatchObject({ hook: HookLabel.USER_INPUT });
    expect(gated.calls).toHaveLength(1);
  });

  it("keeps raising a landed block until the run ends", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    held.release();
    const handler = await handlerFor(held, { parallel: true });

    await handler.handleChainStart({}, {}, "graph");
    await handler.handleChatModelStart({}, USER, "model", "graph");
    await held.firewall.flush();

    await expect(handler.handleLLMNewToken("partial", 0, "model")).rejects.toBeInstanceOf(FirewallBlockedException);
    await expect(handler.handleToolStart({ name: "send_email" }, "body", "tool", "graph")).rejects.toMatchObject({
      hook: HookLabel.USER_INPUT,
    });
    expect(held.calls).toHaveLength(1);
  });

  it("leaves nothing to join after a failed run", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    held.release();
    const handler = await handlerFor(held, { parallel: true });

    await handler.handleChatModelStart({}, USER, "model");
    await handler.handleLLMError(new Error("provider failed"), "model");
    await held.firewall.flush();

    await handler.handleChatModelStart({}, [[{ role: "assistant", content: "no user turn" }]], "model");
    await expect(handler.handleLLMNewToken("partial", 0, "model")).resolves.toBeDefined();
  });

  it("lets a protected model generate while its input is classified", async () => {
    const held = heldFirewall();
    class Model extends FakeListChatModel {
      override async _generate() {
        await held.started;
        held.release();
        return { generations: [{ text: "done", message: new AIMessage("done") }] };
      }
    }
    const model = await protectLangChainRunnable(held.firewall, new Model({ responses: ["done"] }), {
      parallel: true,
    });

    const result = await model.invoke("question", { configurable: { thread_id: "conversation-1" } });

    expect(result).toBeInstanceOf(AIMessage);
    expect(held.calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT, HookLabel.LLM_OUTPUT]);
    expect(held.calls.every((call) => call.conversationId === "conversation-1")).toBe(true);
  });

  it("withholds a protected model's output for a blocked input", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    held.release();
    const model = await protectLangChainRunnable(
      held.firewall, new FakeListChatModel({ responses: ["done"] }), { parallel: true },
    );

    await expect(model.invoke("attack")).rejects.toBeInstanceOf(FirewallBlockedException);
  });
});

describe("LangChain adapter in shadow mode", () => {
  it("classifies in the background unless failures must surface", async () => {
    const held = heldFirewall(["MALICIOUS"], { mode: "shadow" });
    const background = await handlerFor(held);

    await background.handleChatModelStart({}, USER, "model-1");
    await held.started;
    expect(held.calls).toHaveLength(1);

    held.release();
    await held.firewall.flush();
    const inline = await handlerFor(held, { failOpen: false });
    await inline.handleChatModelStart({}, USER, "model-2");
    expect(held.calls).toHaveLength(2);
  });
});
