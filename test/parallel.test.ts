// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

import { afterEach, describe, expect, it, vi } from "vitest";

import { Firewall, FirewallBlockedException, HookLabel } from "../src/index.js";
import { heldFirewall } from "./held.js";

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

describe("limits", () => {
  it.each(["maxConcurrent", "maxQueued"] as const)("rejects a non-positive %s", (option) => {
    expect(() => new Firewall({
      apiKey: "sk-test",
      apiUrl: "https://api.test.invalid/classify",
      [option]: 0,
    })).toThrow(`${option} must be a positive integer`);
  });
});
