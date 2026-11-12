// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { describe, expect, it, vi } from "vitest";

import { HookLabel } from "../src/index.js";
import {
  SAFE_FINAL_MESSAGE, SAFE_OUTPUT_MESSAGE, createDeepAgentsMiddleware,
} from "../src/adapters/deepagents.js";
import { gatedFirewall, heldFirewall } from "./held.js";

function modelRequest(messages: unknown[]) {
  return {
    messages,
    state: { messages },
    runtime: { configurable: { thread_id: "conversation-1" } },
  };
}

describe("Deep Agents middleware with parallel", () => {
  it("runs the model while its input is classified", async () => {
    const held = heldFirewall();
    const middleware = createDeepAgentsMiddleware(held.firewall, { parallel: true });

    const response = await middleware.wrapModelCall!(modelRequest([new HumanMessage("question")]) as never, (async () => {
      await held.started;
      held.release();
      return new AIMessage("answer");
    }) as never);

    expect(AIMessage.isInstance(response) && response.content).toBe("answer");
    expect(held.calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT, HookLabel.LLM_OUTPUT]);
    expect(held.calls.every((call) => call.conversationId === "conversation-1")).toBe(true);
  });

  it("withholds the model response for a blocked input", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    held.release();
    const middleware = createDeepAgentsMiddleware(held.firewall, { parallel: true });

    const response = await middleware.wrapModelCall!(
      modelRequest([new HumanMessage("attack")]) as never,
      (async () => new AIMessage("leak")) as never,
    );

    expect(AIMessage.isInstance(response) && response.content).toBe(SAFE_OUTPUT_MESSAGE);
    expect(held.calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT]);
  });

  it("does not wait for a model that fails after its input is blocked", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    held.release();
    const middleware = createDeepAgentsMiddleware(held.firewall, { parallel: true });

    const response = await middleware.wrapModelCall!(
      modelRequest([new HumanMessage("attack")]) as never,
      (async () => { throw new Error("provider failed"); }) as never,
    );

    expect(AIMessage.isInstance(response) && response.content).toBe(SAFE_OUTPUT_MESSAGE);
  });

  it("decides the blocked-attempt cap before the model runs", async () => {
    const held = heldFirewall(["MALICIOUS", "BENIGN"]);
    held.release();
    const middleware = createDeepAgentsMiddleware(held.firewall, { parallel: true, maxBlockedAttempts: 1 });
    const denied = await middleware.wrapToolCall!(
      { toolCall: { id: "call-1", name: "search", args: { query: "attack" } }, state: { messages: [] }, runtime: {} } as never,
      (async () => new ToolMessage({ content: "unreachable", tool_call_id: "call-1" })) as never,
    );
    const model = vi.fn(async () => new AIMessage("answer"));

    const response = await middleware.wrapModelCall!(
      modelRequest([new HumanMessage("question"), denied]) as never, model as never,
    );

    expect(AIMessage.isInstance(response) && response.content).toBe(SAFE_FINAL_MESSAGE);
    expect(model).not.toHaveBeenCalled();
  });
});

describe("Deep Agents middleware with a queued input check", () => {
  it("classifies the input as it was when the model call started", async () => {
    const gated = gatedFirewall({ maxConcurrent: 1 });
    const occupying = gated.firewall.pending.submit(() => gated.firewall.classify("occupying"));
    await gated.arrived(1);
    const middleware = createDeepAgentsMiddleware(gated.firewall, { parallel: true });
    const question = new HumanMessage("question");

    const response = middleware.wrapModelCall!(modelRequest([question]) as never, (async () => {
      question.content = "rewritten while the check was queued";
      gated.calls[0]!.resolve();
      return new AIMessage("answer");
    }) as never);
    await gated.arrived(2);
    gated.calls[1]!.resolve();
    await gated.arrived(3);
    gated.calls[2]!.resolve();

    expect(AIMessage.isInstance(await response)).toBe(true);
    expect(gated.calls[1]).toMatchObject({
      text: "question",
      options: { hook: HookLabel.USER_INPUT, metadata: { conversationId: "conversation-1" } },
    });
    await occupying;
  });
});

describe("Deep Agents middleware in shadow mode", () => {
  it("classifies an unchanged remote notification once across turns", async () => {
    const held = heldFirewall(["BENIGN"], { mode: "shadow" });
    held.release();
    const middleware = createDeepAgentsMiddleware(held.firewall);
    const notification = new HumanMessage({
      id: "notification-1",
      content: "background task finished",
      additional_kwargs: { lc_source: "async_subagent" },
    });
    const turn = (): Promise<unknown> => middleware.wrapModelCall!(
      modelRequest([notification]) as never, (async () => new AIMessage("answer")) as never,
    ) as Promise<unknown>;

    await turn();
    await held.firewall.flush();
    await turn();
    await held.firewall.flush();

    expect(held.calls.filter((call) => call.hook === HookLabel.TOOL_RESPONSE)).toHaveLength(1);
  });

  it("classifies in the background", async () => {
    const held = heldFirewall(["MALICIOUS"], { mode: "shadow" });
    const events: string[] = [];
    const middleware = createDeepAgentsMiddleware(held.firewall, {
      onClassify: (event) => events.push(event.hook),
    });

    const response = await middleware.wrapModelCall!(
      modelRequest([new HumanMessage("attack")]) as never,
      (async () => new AIMessage("answer")) as never,
    );

    expect(AIMessage.isInstance(response) && response.content).toBe("answer");
    expect(events).toEqual([]);
    held.release();
    await held.firewall.flush();
    expect(events).toEqual([HookLabel.USER_INPUT, HookLabel.LLM_OUTPUT]);
  });
});
