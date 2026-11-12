// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

import { afterEach, describe, expect, it, vi } from "vitest";

import { Firewall, FirewallBlockedException, HookLabel } from "../src/index.js";
import { gatedFirewall, heldFirewall, settleQueue } from "./held.js";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("Firewall.protect", () => {
  it("runs the operation while its input is classified", async () => {
    const held = heldFirewall();

    const answer = await held.firewall.protect(async () => {
      await held.started;
      held.release();
      return "answer";
    }, { text: "prompt", hook: HookLabel.USER_INPUT });

    expect(answer).toBe("answer");
    expect(held.calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT]);
  });

  it("withholds the result of a blocked input and aborts the operation", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    held.release();
    let aborted = false;

    const outcome = held.firewall.protect((signal) => new Promise<string>(() => {
      signal.addEventListener("abort", () => { aborted = true; });
    }), { text: "attack", hook: HookLabel.USER_INPUT });

    await expect(outcome).rejects.toBeInstanceOf(FirewallBlockedException);
    expect(aborted).toBe(true);
  });

  it("classifies extracted output before returning it", async () => {
    const held = heldFirewall(["BENIGN", "MALICIOUS"]);
    held.release();

    const outcome = held.firewall.protect(async () => "leaked secret", {
      text: "prompt",
      hook: HookLabel.USER_INPUT,
      output: (result) => result,
    });

    await expect(outcome).rejects.toMatchObject({ hook: HookLabel.LLM_OUTPUT });
    expect(held.calls.map((call) => call.text)).toEqual(["prompt", "leaked secret"]);
  });

  it("returns before the verdict in shadow mode", async () => {
    const held = heldFirewall(["MALICIOUS"], { mode: "shadow" });

    await expect(held.firewall.protect(async () => "answer", { text: "attack" })).resolves.toBe("answer");

    held.release();
    await held.firewall.flush();
    expect(held.calls).toHaveLength(1);
  });

  it("propagates an operation failure", async () => {
    const held = heldFirewall();
    held.release();

    await expect(held.firewall.protect(async () => {
      throw new Error("model unavailable");
    }, { text: "prompt" })).rejects.toThrow("model unavailable");
    await held.firewall.flush();
  });
});

describe("background classifications", () => {
  it("are sent in order within one conversation", async () => {
    const held = heldFirewall(["BENIGN"], { mode: "shadow" });
    const metadata = { conversationId: "conversation-1" };

    await held.firewall.protect(async () => "answer", {
      text: "prompt",
      hook: HookLabel.USER_INPUT,
      metadata,
      output: (result) => result,
    });
    await held.started;
    expect(held.calls.map((call) => call.text)).toEqual(["prompt"]);

    held.release();
    await held.firewall.flush();
    expect(held.calls.map((call) => call.text)).toEqual(["prompt", "answer"]);
    expect(held.calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT, HookLabel.LLM_OUTPUT]);
  });

  it("are dropped once a conversation queue is full", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const held = heldFirewall(["BENIGN"], { mode: "shadow", maxQueued: 1 });
    const metadata = { conversationId: "conversation-1" };

    await held.firewall.protect(async () => undefined, { text: "first", metadata });
    await held.firewall.protect(async () => undefined, { text: "dropped", metadata });
    held.release();
    await held.firewall.flush();

    expect(held.calls.map((call) => call.text)).toEqual(["first"]);
    expect(warn).toHaveBeenCalledOnce();
  });

  it("retry once and never reject", async () => {
    vi.useFakeTimers();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const fetchMock = vi.fn(async () => new Response("slow down", { status: 429 }));
    vi.stubGlobal("fetch", fetchMock);
    const firewall = new Firewall({ apiKey: "sk-test", apiUrl: "https://api.test.invalid/classify" });

    const observed = firewall.observe("background");
    await vi.runAllTimersAsync();

    await expect(observed).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(warn).toHaveBeenCalledOnce();
  });

  it("respect the in-flight limit", async () => {
    const held = heldFirewall(["BENIGN"], { mode: "shadow", maxConcurrent: 1 });

    void held.firewall.observe("first");
    void held.firewall.observe("second");
    await held.started;
    await Promise.resolve();
    expect(held.calls.map((call) => call.text)).toEqual(["first"]);

    held.release();
    await held.firewall.flush();
    expect(held.calls.map((call) => call.text)).toEqual(["first", "second"]);
  });
});

describe("queued classifications", () => {
  it("send the output check through the queue, within the in-flight limit", async () => {
    const gated = gatedFirewall({ maxConcurrent: 1 });

    const answer = gated.firewall.protect(async () => "generated", {
      text: "prompt",
      output: (result) => result,
    });
    await gated.arrived(1);
    const other = gated.firewall.pending.submit(() => gated.firewall.classify("other"));
    gated.calls[0]!.resolve();
    await gated.arrived(2);
    await settleQueue();
    expect(gated.calls.map((call) => call.text)).toEqual(["prompt", "other"]);

    gated.calls[1]!.resolve();
    await gated.arrived(3);
    expect(gated.calls[2]).toMatchObject({ text: "generated", options: { hook: HookLabel.LLM_OUTPUT } });
    gated.calls[2]!.resolve();
    await expect(answer).resolves.toBe("generated");
    await other;
  });

  it("run one check at a time across concurrent protect calls at an in-flight limit of one", async () => {
    const gated = gatedFirewall({ maxConcurrent: 1 });

    const answers = ["a", "b", "c"].map((name) => gated.firewall.protect(async () => `${name}-out`, {
      text: `${name}-in`,
      output: (result) => result,
    }));
    for (let count = 1; count <= 6; count++) {
      await gated.arrived(count);
      await settleQueue();
      expect(gated.calls).toHaveLength(count);
      gated.calls[count - 1]!.resolve();
    }

    await expect(Promise.all(answers)).resolves.toEqual(["a-out", "b-out", "c-out"]);
    expect(gated.calls.map((call) => call.text).sort()).toEqual([
      "a-in", "a-out", "b-in", "b-out", "c-in", "c-out",
    ]);
  });

  it("keep input and output of concurrent protect calls in order within one conversation", async () => {
    const gated = gatedFirewall();
    const metadata = { conversationId: "conversation-1" };

    const answers = ["a", "b"].map((name) => gated.firewall.protect(async () => `${name}-out`, {
      text: `${name}-in`,
      metadata,
      output: (result) => result,
    }));
    for (let count = 1; count <= 4; count++) {
      await gated.arrived(count);
      await settleQueue();
      expect(gated.calls).toHaveLength(count);
      gated.calls[count - 1]!.resolve();
    }

    await Promise.all(answers);
    expect(gated.calls.map((call) => call.text)).toEqual(["a-in", "b-in", "a-out", "b-out"]);
  });

  it("let the remaining queued callers run in turn after one of them aborts", async () => {
    const gated = gatedFirewall({ maxConcurrent: 1 });
    const controller = new AbortController();
    const untilAborted = (signal: AbortSignal): Promise<string> => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(signal.reason));
    });

    const first = gated.firewall.protect(async () => "first-out", { text: "first" });
    await gated.arrived(1);
    const second = gated.firewall.protect(async () => "second-out", { text: "second" });
    const aborted = gated.firewall.protect(untilAborted, { text: "aborted", signal: controller.signal });
    const last = gated.firewall.protect(async () => "last-out", { text: "last" });
    await settleQueue();
    controller.abort(new Error("caller went away"));
    await expect(aborted).rejects.toThrow("caller went away");

    for (let count = 1; count <= 3; count++) {
      await gated.arrived(count);
      await settleQueue();
      expect(gated.calls).toHaveLength(count);
      gated.calls[count - 1]!.resolve();
    }
    await expect(Promise.all([first, second, last])).resolves.toEqual(["first-out", "second-out", "last-out"]);
    expect(gated.calls.map((call) => call.text)).toEqual(["first", "second", "last"]);
  });

  it("never read caller-owned request data after the caller continues", async () => {
    const gated = gatedFirewall();
    const metadata = { conversationId: "conversation-1", trace: { step: "first" } };
    const governance = { agent: "assistant", resource: { kind: "tool" as const, id: "search" } };

    const answer = gated.firewall.protect(async () => {
      metadata.conversationId = "conversation-2";
      metadata.trace.step = "changed";
      governance.resource.id = "delete_records";
      return "generated";
    }, { text: "prompt", metadata, governance, output: (result) => result });
    await gated.arrived(1);
    gated.calls[0]!.resolve();
    await gated.arrived(2);
    gated.calls[1]!.resolve();
    await answer;

    const sent = { conversationId: "conversation-1", trace: { step: "first" } };
    expect(gated.calls[0]!.options).toMatchObject({
      metadata: sent,
      governance: { agent: "assistant", resource: { kind: "tool", id: "search" } },
    });
    expect(gated.calls[1]!.options?.metadata).toEqual(sent);
  });

  it("copy background request data and detach it from the caller's signal", async () => {
    const gated = gatedFirewall({ mode: "shadow" });
    const metadata = { conversationId: "conversation-1", trace: { step: "first" } };
    const controller = new AbortController();

    await gated.firewall.protect(async () => "answer", { text: "prompt", metadata, signal: controller.signal });
    metadata.trace.step = "changed";
    controller.abort();
    await gated.arrived(1);

    expect(gated.calls[0]!.options?.metadata).toEqual({ conversationId: "conversation-1", trace: { step: "first" } });
    expect(gated.calls[0]!.options?.signal).toBeUndefined();
    gated.calls[0]!.resolve();
    await gated.firewall.flush();
  });

  it("cap background classifications from concurrent callers across conversations", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const gated = gatedFirewall({ mode: "shadow", maxConcurrent: 2, maxQueued: 2 });

    const results = await Promise.all(Array.from({ length: 7 }, (_unused, index) => gated.firewall.protect(
      async () => index,
      { text: `prompt-${index}`, ...(index % 2 === 0 ? {} : { metadata: { conversationId: `conversation-${index}` } }) },
    )));
    expect(results).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(warn).toHaveBeenCalledTimes(3);

    for (let count = 1; count <= 4; count++) {
      await gated.arrived(count);
      gated.calls[count - 1]!.resolve();
    }
    await gated.firewall.flush();
    expect(gated.calls.map((call) => call.text)).toEqual(["prompt-0", "prompt-1", "prompt-2", "prompt-3"]);
  });

  it("cap background classifications across all conversations", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const gated = gatedFirewall({ mode: "shadow", maxConcurrent: 1, maxQueued: 2 });

    void gated.firewall.observe("first");
    void gated.firewall.observe("second", { metadata: { conversationId: "conversation-1" } });
    await expect(gated.firewall.observe("dropped")).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalledOnce();

    await gated.arrived(1);
    gated.calls[0]!.resolve();
    await gated.arrived(2);
    gated.calls[1]!.resolve();
    await gated.firewall.flush();
    expect(gated.calls.map((call) => call.text)).toEqual(["first", "second"]);
  });

  it("stop waiting for a slot when the caller aborts", async () => {
    const gated = gatedFirewall({ maxConcurrent: 1 });
    const occupying = gated.firewall.pending.submit(() => gated.firewall.classify("occupying"));
    await gated.arrived(1);
    const controller = new AbortController();
    let operationAborted = false;

    const answer = gated.firewall.protect((signal) => new Promise<string>((_resolve, reject) => {
      signal.addEventListener("abort", () => {
        operationAborted = true;
        reject(signal.reason);
      });
    }), { text: "prompt", signal: controller.signal });
    await settleQueue();
    controller.abort(new Error("caller went away"));

    await expect(answer).rejects.toThrow("caller went away");
    expect(operationAborted).toBe(true);
    expect(gated.calls.map((call) => call.text)).toEqual(["occupying"]);
    gated.calls[0]!.resolve();
    await occupying;
  });

  it("keep conversation order after a queued classification is cancelled", async () => {
    const gated = gatedFirewall();
    const conversation = "conversation-1";
    const first = gated.firewall.pending.submit(() => gated.firewall.classify("first"), conversation);
    await gated.arrived(1);
    const controller = new AbortController();
    const cancelled = gated.firewall.pending.submit(
      () => gated.firewall.classify("cancelled"), conversation, controller.signal,
    );
    const last = gated.firewall.pending.submit(() => gated.firewall.classify("last"), conversation);

    controller.abort(new Error("caller went away"));
    await expect(cancelled).rejects.toThrow("caller went away");
    await settleQueue();
    expect(gated.calls.map((call) => call.text)).toEqual(["first"]);

    gated.calls[0]!.resolve();
    await gated.arrived(2);
    expect(gated.calls.map((call) => call.text)).toEqual(["first", "last"]);
    gated.calls[1]!.resolve();
    await Promise.all([first, last]);
  });

  it("report a background request that cannot be copied instead of throwing", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const gated = gatedFirewall({ mode: "shadow" });
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;

    await expect(gated.firewall.observe("background", { metadata: cyclic })).resolves.toBeUndefined();

    expect(gated.calls).toHaveLength(0);
    expect(warn).toHaveBeenCalledOnce();
  });
});

describe("limits", () => {
  it.each(["maxConcurrent", "maxQueued"] as const)("rejects a non-positive %s", (option) => {
    expect(() => new Firewall({
      apiKey: "sk-test",
      apiUrl: "https://api.test.invalid/classify",
      [option]: 0,
    })).toThrow(`${option} must be a positive integer`);
  });
});
