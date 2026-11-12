// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

import { describe, expect, it, vi } from "vitest";

import {
  FirewallBlockedException,
  HookLabel,
  type Firewall,
  type MiddlewareOptions,
} from "../src/index.js";
import { createMiddleware } from "../src/adapters/vercel.js";
import { createMiddlewareV4 } from "../src/adapters/vercel-v4.js";
import { heldFirewall } from "./held.js";

const PROMPT = [{ role: "user", content: [{ type: "text", text: "question" }] }];

function emptyStream(onCancel: () => void): ReadableStream<never> {
  return new ReadableStream<never>({ cancel: onCancel });
}

describe("Vercel middleware defaults", () => {
  it("classifies generated text returned as content parts", async () => {
    const held = heldFirewall(["BENIGN", "MALICIOUS"]);
    held.release();

    const outcome = createMiddleware(held.firewall).wrapGenerate({
      params: { prompt: PROMPT },
      doGenerate: async () => ({ content: [{ type: "text", text: "leaked " }, { type: "text", text: "secret" }] }),
    });

    await expect(outcome).rejects.toMatchObject({ hook: HookLabel.LLM_OUTPUT });
    expect(held.calls.map((call) => call.text)).toEqual(["question", "leaked secret"]);
  });

  it("classifies tool calls returned as content parts", async () => {
    const held = heldFirewall(["BENIGN", "MALICIOUS"]);
    held.release();

    const outcome = createMiddleware(held.firewall, { scanToolCalls: true }).wrapGenerate({
      params: { prompt: PROMPT },
      doGenerate: async () => ({
        content: [{ type: "tool-call", toolCallId: "call-1", toolName: "send_email", input: "{\"to\":\"all\"}" }],
      }),
    });

    await expect(outcome).rejects.toMatchObject({ hook: HookLabel.TOOL_CALL, toolName: "send_email" });
  });

  it("classifies AI SDK 7 output without options", async () => {
    const held = heldFirewall();
    held.release();

    await createMiddlewareV4(held.firewall).wrapGenerate({
      params: { prompt: PROMPT },
      doGenerate: async () => ({ content: [{ type: "text", text: "answer" }] }),
    });

    expect(held.calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT, HookLabel.LLM_OUTPUT]);
  });
});

interface AnyMiddleware {
  wrapGenerate: (args: never) => Promise<unknown>;
  wrapStream: (args: never) => Promise<unknown>;
}

type Create = (firewall: Firewall, options: MiddlewareOptions) => AnyMiddleware;

describe.each<[string, Create]>([
  ["v3", createMiddleware as Create],
  ["v4", createMiddlewareV4 as Create],
])("Vercel %s middleware with parallel", (_name, create) => {
  it("generates while the input is classified", async () => {
    const held = heldFirewall();
    const middleware = create(held.firewall, { parallel: true, scanOutput: false });

    const result = await middleware.wrapGenerate({
      params: { prompt: PROMPT },
      doGenerate: async () => {
        await held.started;
        held.release();
        return { content: [{ type: "text", text: "answer" }] };
      },
    } as never);

    expect(result).toMatchObject({ content: [{ type: "text", text: "answer" }] });
    expect(held.calls.map((call) => call.hook)).toEqual([HookLabel.USER_INPUT]);
  });

  it("withholds the generation of a blocked input", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    held.release();
    const doGenerate = vi.fn(async () => ({ content: [{ type: "text", text: "leak" }] }));

    const outcome = create(held.firewall, { parallel: true }).wrapGenerate({
      params: { prompt: PROMPT }, doGenerate,
    } as never);

    await expect(outcome).rejects.toBeInstanceOf(FirewallBlockedException);
    expect(doGenerate).toHaveBeenCalledOnce();
  });

  it("cancels a stream that started before its input was blocked", async () => {
    const held = heldFirewall(["MALICIOUS"]);
    held.release();
    let cancelled!: () => void;
    const cancellation = new Promise<void>((resolve) => { cancelled = resolve; });

    const outcome = create(held.firewall, { parallel: true }).wrapStream({
      params: { prompt: PROMPT },
      doStream: async () => ({ stream: emptyStream(cancelled) }),
    } as never);

    await expect(outcome).rejects.toBeInstanceOf(FirewallBlockedException);
    await cancellation;
  });
});
