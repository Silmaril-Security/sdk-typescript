import { describe, expect, it, vi } from "vitest";

import { Firewall, HookLabel } from "../src/index.js";
import {
  VercelV4BufferLimitError,
  createMiddlewareV4,
} from "../src/adapters/vercel-v4.js";

interface StreamPart {
  type: string;
  id?: string;
  delta?: string;
  toolName?: string;
  toolCallId?: string;
  input?: string;
  inputEncoding?: "json" | "text";
  error?: unknown;
  [key: string]: unknown;
}

function makeFirewall(
  decide: (text: string) => "BENIGN" | "MALICIOUS" = () => "BENIGN",
) {
  const firewall = new Firewall({
    apiKey: "sk",
    apiUrl: "https://example.com/classify",
  });
  firewall.classify = vi.fn(async (text) => ({
    prediction: decide(text),
    score: decide(text) === "MALICIOUS" ? 0.9 : 0.1,
    threshold: 0.5,
    mode: "block",
  })) as typeof firewall.classify;
  return firewall;
}

function partStream(parts: readonly StreamPart[]): ReadableStream<StreamPart> {
  return new ReadableStream({
    start(controller) {
      for (const part of parts) controller.enqueue(part);
      controller.close();
    },
  });
}

async function collect(stream: ReadableStream<StreamPart>): Promise<StreamPart[]> {
  const output: StreamPart[] = [];
  await collectInto(stream, output);
  return output;
}

async function collectInto(
  stream: ReadableStream<StreamPart>,
  output: StreamPart[],
): Promise<void> {
  const reader = stream.getReader();
  let result = await reader.read();
  while (!result.done) {
    output.push(result.value);
    result = await reader.read();
  }
}

const emptyPrompt = [{ role: "user", content: [{ type: "text", text: "" }] }];

describe("Vercel AI SDK 7 middleware", () => {
  it("uses v4 content parts for user input and generation output", async () => {
    const firewall = makeFirewall();
    const middleware = createMiddlewareV4(firewall, {
      scanOutput: true,
      scanToolCalls: true,
    });

    const result = {
      content: [
        { type: "reasoning", text: "private reasoning" },
        { type: "text", text: "hello " },
        { type: "text", text: "world" },
        {
          type: "tool-call",
          toolCallId: "call-1",
          toolName: "search",
          input: "{\"query\":\"safe\"}",
        },
      ],
    };
    const returned = await middleware.wrapGenerate({
      params: {
        prompt: [
          { role: "system", content: "system" },
          { role: "user", content: [{ type: "text", text: "latest user" }] },
        ],
      },
      doGenerate: async () => result,
    });

    expect(returned).toBe(result);
    expect(vi.mocked(firewall.classify).mock.calls.map(([text, options]) => [
      text,
      options?.hook,
      options?.toolName,
    ])).toEqual([
      ["latest user", HookLabel.USER_INPUT, undefined],
      ["hello world", HookLabel.LLM_OUTPUT, undefined],
      ["{\"query\":\"safe\"}", HookLabel.TOOL_CALL, "search"],
    ]);
    expect(vi.mocked(firewall.classify).mock.calls.flatMap(([text]) => text))
      .not.toContain("private reasoning");
  });

  it("classifies every tool result part in the latest prompt tool turn with its ID", async () => {
    const firewall = makeFirewall();
    const middleware = createMiddlewareV4(firewall);

    await middleware.wrapGenerate({
      params: {
        prompt: [
          { role: "user", content: [{ type: "text", text: "old user" }] },
          {
            role: "tool",
            content: [{
              type: "tool-result",
              toolCallId: "call-1",
              toolName: "search",
              output: { type: "text", value: "first result" },
            }],
          },
          {
            role: "tool",
            content: [{
              type: "tool-result",
              toolCallId: "call-2",
              toolName: "lookup",
              output: { type: "json", value: { answer: "second result" } },
            }],
          },
        ],
      },
      doGenerate: async () => ({ content: [] }),
    });

    expect(vi.mocked(firewall.classify).mock.calls.map(([text, options]) => [
      text,
      options?.hook,
      options?.toolName,
    ])).toEqual([
      ["first result", HookLabel.TOOL_RESPONSE, "search"],
      ["{\"answer\":\"second result\"}", HookLabel.TOOL_RESPONSE, "lookup"],
    ]);
  });

  it("buffers split and interleaved text IDs, then preserves every benign part by identity", async () => {
    const firewall = makeFirewall();
    const middleware = createMiddlewareV4(firewall, { scanOutput: true });
    const parts: StreamPart[] = [
      { type: "stream-start", warnings: [] },
      { type: "text-start", id: "a" },
      { type: "text-delta", id: "a", delta: "hel" },
      { type: "text-start", id: "b" },
      { type: "text-delta", id: "b", delta: "world" },
      { type: "text-end", id: "b" },
      { type: "text-delta", id: "a", delta: "lo" },
      { type: "text-end", id: "a" },
      {
        type: "finish",
        finishReason: { unified: "stop", raw: "stop" },
        usage: { inputTokens: {}, outputTokens: {} },
      },
    ];

    const result = await middleware.wrapStream({
      params: { prompt: emptyPrompt },
      doStream: async () => ({ stream: partStream(parts), request: { body: "kept" } }),
    });
    const output = await collect(result.stream);

    expect(result.request).toEqual({ body: "kept" });
    expect(output).toHaveLength(parts.length);
    output.forEach((part, index) => expect(part).toBe(parts[index]));
    expect(vi.mocked(firewall.classify).mock.calls.map(([text, options]) => [
      text,
      options?.hook,
    ])).toEqual([
      ["world", HookLabel.LLM_OUTPUT],
      ["hello", HookLabel.LLM_OUTPUT],
    ]);
  });

  it("does not release possible-Block text before its completed verdict", async () => {
    const firewall = makeFirewall();
    let release!: () => void;
    firewall.classify = vi.fn(() => new Promise((resolve) => {
      release = () => resolve({
        prediction: "BENIGN",
        score: 0.1,
        threshold: 0.5,
        mode: "block",
      });
    })) as typeof firewall.classify;
    const middleware = createMiddlewareV4(firewall, { scanOutput: true });
    const parts: StreamPart[] = [
      { type: "text-start", id: "a" },
      { type: "text-delta", id: "a", delta: "safe" },
      { type: "text-end", id: "a" },
    ];
    const result = await middleware.wrapStream({
      params: { prompt: emptyPrompt },
      doStream: async () => ({ stream: partStream(parts) }),
    });

    const reader = result.stream.getReader();
    let settled = false;
    const first = reader.read().then((value) => {
      settled = true;
      return value;
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(settled).toBe(false);
    release();
    await expect(first).resolves.toEqual({ done: false, value: parts[0] });
    await reader.cancel();
  });

  it("replaces blocked text with one valid error part and retains finish metadata", async () => {
    const firewall = makeFirewall((text) => text.includes("deny") ? "MALICIOUS" : "BENIGN");
    const middleware = createMiddlewareV4(firewall, { scanOutput: true });
    const finish = {
      type: "finish",
      finishReason: { unified: "content-filter", raw: "blocked" },
      usage: { inputTokens: {}, outputTokens: {} },
      providerMetadata: { provider: { trace: "kept" } },
    };
    const result = await middleware.wrapStream({
      params: { prompt: emptyPrompt },
      doStream: async () => ({
        stream: partStream([
          { type: "text-start", id: "a" },
          { type: "text-delta", id: "a", delta: "deny" },
          { type: "text-end", id: "a" },
          finish,
        ]),
      }),
    });

    const output = await collect(result.stream);
    expect(output).toHaveLength(2);
    expect(output[0]?.type).toBe("error");
    expect(output[0]?.error).toMatchObject({ name: "FirewallBlockedException" });
    expect(output[1]).toBe(finish);
    expect(output.some((part) => part.delta === "deny")).toBe(false);
  });

  it("buffers tool-input deltas, correlates the final call by ID, and never leaks blocked arguments", async () => {
    const firewall = makeFirewall((text) => text.includes("deny") ? "MALICIOUS" : "BENIGN");
    const middleware = createMiddlewareV4(firewall, { scanToolCalls: true });
    const finish = {
      type: "finish",
      finishReason: { unified: "tool-calls", raw: "tool_use" },
      usage: { inputTokens: {}, outputTokens: {} },
    };
    const result = await middleware.wrapStream({
      params: { prompt: emptyPrompt },
      doStream: async () => ({
        stream: partStream([
          { type: "tool-input-start", id: "call-1", toolName: "search" },
          { type: "tool-input-delta", id: "call-1", delta: "{\"query\":\"de" },
          { type: "tool-input-delta", id: "call-1", delta: "ny\"}" },
          { type: "tool-input-end", id: "call-1" },
          {
            type: "tool-call",
            toolCallId: "call-1",
            toolName: "search",
            input: "{\"query\":\"deny\"}",
          },
          finish,
        ]),
      }),
    });

    const output = await collect(result.stream);
    expect(output.map((part) => part.type)).toEqual(["error", "finish"]);
    expect(output[1]).toBe(finish);
    expect(vi.mocked(firewall.classify)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(firewall.classify).mock.calls[0]).toMatchObject([
      "{\"query\":\"deny\"}",
      { hook: HookLabel.TOOL_CALL, toolName: "search" },
    ]);
  });

  it("reclassifies changed final tool input and withholds a newly malicious call", async () => {
    const firewall = makeFirewall((text) => text.includes("deny") ? "MALICIOUS" : "BENIGN");
    const middleware = createMiddlewareV4(firewall, { scanToolCalls: true });
    const finalCall = {
      type: "tool-call",
      toolCallId: "call-1",
      toolName: "search",
      input: "{\"query\":\"deny\"}",
    };
    const result = await middleware.wrapStream({
      params: { prompt: emptyPrompt },
      doStream: async () => ({
        stream: partStream([
          { type: "tool-input-start", id: "call-1", toolName: "search" },
          { type: "tool-input-delta", id: "call-1", delta: "{\"query\":\"safe\"}" },
          { type: "tool-input-end", id: "call-1" },
          finalCall,
        ]),
      }),
    });

    const output = await collect(result.stream);
    expect(output.map((part) => part.type)).toEqual([
      "tool-input-start",
      "tool-input-delta",
      "tool-input-end",
      "error",
    ]);
    expect(output).not.toContain(finalCall);
    expect(vi.mocked(firewall.classify).mock.calls.map(([text]) => text))
      .toEqual(["{\"query\":\"safe\"}", "{\"query\":\"deny\"}"]);
  });

  it("keeps one verdict for byte-identical final input and rechecks changed whitespace", async () => {
    const firewall = makeFirewall();
    const middleware = createMiddlewareV4(firewall, { scanToolCalls: true });
    const streamOnce = async (finalInput: string): Promise<StreamPart[]> => {
      const result = await middleware.wrapStream({
        params: { prompt: emptyPrompt },
        doStream: async () => ({
          stream: partStream([
            { type: "tool-input-start", id: "call-1", toolName: "search" },
            { type: "tool-input-delta", id: "call-1", delta: "{\"query\":\"safe\"}" },
            { type: "tool-input-end", id: "call-1" },
            {
              type: "tool-call",
              toolCallId: "call-1",
              toolName: "search",
              input: finalInput,
            },
          ]),
        }),
      });
      return collect(result.stream);
    };

    const exact = await streamOnce("{\"query\":\"safe\"}");
    expect(exact.at(-1)?.type).toBe("tool-call");
    expect(vi.mocked(firewall.classify)).toHaveBeenCalledTimes(1);

    vi.mocked(firewall.classify).mockClear();
    const whitespace = await streamOnce("{ \"query\": \"safe\" }");
    expect(whitespace.at(-1)?.type).toBe("tool-call");
    expect(vi.mocked(firewall.classify).mock.calls.map(([text]) => text))
      .toEqual(["{\"query\":\"safe\"}", "{ \"query\": \"safe\" }"]);
  });

  it("classifies incomplete text buffers at stream flush", async () => {
    const firewall = makeFirewall();
    const middleware = createMiddlewareV4(firewall, { scanOutput: true });
    const parts: StreamPart[] = [
      { type: "text-start", id: "a" },
      { type: "text-delta", id: "a", delta: "incomplete" },
    ];
    const result = await middleware.wrapStream({
      params: { prompt: emptyPrompt },
      doStream: async () => ({ stream: partStream(parts) }),
    });

    const output = await collect(result.stream);
    expect(output[0]).toBe(parts[0]);
    expect(output[1]).toBe(parts[1]);
    expect(vi.mocked(firewall.classify)).toHaveBeenCalledWith(
      "incomplete",
      expect.objectContaining({ hook: HookLabel.LLM_OUTPUT }),
    );
  });

  it("errors without releasing pending content on infrastructure failure", async () => {
    const firewall = makeFirewall();
    firewall.classify = vi.fn(async () => {
      throw new Error("classifier unavailable");
    }) as typeof firewall.classify;
    const middleware = createMiddlewareV4(firewall, { scanOutput: true });
    const result = await middleware.wrapStream({
      params: { prompt: emptyPrompt },
      doStream: async () => ({
        stream: partStream([
          { type: "text-start", id: "a" },
          { type: "text-delta", id: "a", delta: "held" },
          { type: "text-end", id: "a" },
        ]),
      }),
    });

    const observed: StreamPart[] = [];
    await expect(collectInto(result.stream, observed))
      .rejects.toThrow("classifier unavailable");
    expect(observed).toEqual([]);
  });

  it("fails safely when the bounded Block-mode buffer is exceeded", async () => {
    const firewall = makeFirewall();
    const middleware = createMiddlewareV4(firewall, {
      scanOutput: true,
      maxBufferedBytes: 128,
    });
    const result = await middleware.wrapStream({
      params: { prompt: emptyPrompt },
      doStream: async () => ({
        stream: partStream([
          { type: "text-start", id: "a" },
          { type: "text-delta", id: "a", delta: "x".repeat(256) },
          { type: "text-end", id: "a" },
        ]),
      }),
    });

    const observed: StreamPart[] = [];
    await expect(collectInto(result.stream, observed))
      .rejects.toBeInstanceOf(VercelV4BufferLimitError);
    expect(observed).toEqual([]);
  });
});
