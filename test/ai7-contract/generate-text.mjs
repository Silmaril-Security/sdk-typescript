import assert from "node:assert/strict";

import {
  generateText,
  simulateReadableStream,
  stepCountIs,
  streamText,
  tool,
  wrapLanguageModel,
} from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { z } from "zod";

import { Firewall, HookLabel } from "../../dist/index.js";
import { createMiddlewareV4 } from "../../dist/adapters/vercel-v4.js";

const usage = {
  inputTokens: {
    total: 10,
    noCache: 10,
    cacheRead: undefined,
    cacheWrite: undefined,
  },
  outputTokens: {
    total: 5,
    text: 5,
    reasoning: undefined,
  },
};

const model = new MockLanguageModelV4({
  doGenerate: [
    {
      content: [{
        type: "tool-call",
        toolCallId: "call-1",
        toolName: "lookup",
        input: "{\"query\":\"safe\"}",
      }],
      finishReason: { unified: "tool-calls", raw: undefined },
      usage,
      warnings: [],
    },
    {
      content: [{ type: "text", text: "final text" }],
      finishReason: { unified: "stop", raw: undefined },
      usage,
      warnings: [],
    },
  ],
});

const calls = [];
const firewall = new Firewall({
  apiKey: "contract-only",
  apiUrl: "https://example.invalid/classify",
});
firewall.classify = async (text, options) => {
  calls.push({ text, hook: options?.hook, toolName: options?.toolName });
  return {
    prediction: "BENIGN",
    score: 0.1,
    threshold: 0.5,
    mode: "block",
  };
};

const wrapped = wrapLanguageModel({
  model,
  middleware: createMiddlewareV4(firewall, {
    scanOutput: true,
    scanToolCalls: true,
  }),
});

const result = await generateText({
  model: wrapped,
  prompt: "user text",
  tools: {
    lookup: tool({
      description: "Look up a value",
      inputSchema: z.object({ query: z.string() }),
      execute: async ({ query }) => ({ answer: query }),
    }),
  },
  stopWhen: stepCountIs(2),
});

assert.equal(result.text, "final text");
assert.equal(result.steps[0]?.toolCalls[0]?.toolCallId, "call-1");
assert.deepEqual(result.steps[0]?.toolResults[0]?.output, { answer: "safe" });
assert.deepEqual(calls, [
  { text: "user text", hook: HookLabel.USER_INPUT, toolName: undefined },
  { text: "{\"query\":\"safe\"}", hook: HookLabel.TOOL_CALL, toolName: "lookup" },
  {
    text: "{\"answer\":\"safe\"}",
    hook: HookLabel.TOOL_RESPONSE,
    toolName: "lookup",
  },
  { text: "final text", hook: HookLabel.LLM_OUTPUT, toolName: undefined },
]);

async function exerciseChangedFinalInput(finalInput) {
  const streamCalls = [];
  let executions = 0;
  const streamFirewall = new Firewall({
    apiKey: "contract-only",
    apiUrl: "https://example.invalid/classify",
  });
  streamFirewall.classify = async (text, options) => {
    streamCalls.push({ text, hook: options?.hook, toolName: options?.toolName });
    return {
      prediction: text.includes("deny") ? "MALICIOUS" : "BENIGN",
      score: text.includes("deny") ? 0.9 : 0.1,
      threshold: 0.5,
      mode: "block",
    };
  };
  const streamModel = new MockLanguageModelV4({
    doStream: async () => ({
      stream: simulateReadableStream({
        chunks: [
          { type: "stream-start", warnings: [] },
          { type: "tool-input-start", id: "call-stream", toolName: "lookup" },
          {
            type: "tool-input-delta",
            id: "call-stream",
            delta: "{\"query\":\"safe\"}",
          },
          { type: "tool-input-end", id: "call-stream" },
          {
            type: "tool-call",
            toolCallId: "call-stream",
            toolName: "lookup",
            input: finalInput,
          },
          {
            type: "finish",
            finishReason: { unified: "tool-calls", raw: undefined },
            usage,
          },
        ],
      }),
    }),
  });
  const streamResult = streamText({
    model: wrapLanguageModel({
      model: streamModel,
      middleware: createMiddlewareV4(streamFirewall, {
        scanInput: false,
        scanToolCalls: true,
      }),
    }),
    prompt: "stream a tool",
    onError: () => undefined,
    tools: {
      lookup: tool({
        description: "Look up a value",
        inputSchema: z.object({ query: z.string() }),
        execute: async () => {
          executions++;
          return { ok: true };
        },
      }),
    },
  });
  const chunks = [];
  for await (const chunk of streamResult.fullStream) chunks.push(chunk);
  return { chunks, executions, streamCalls };
}

const changedMalicious = await exerciseChangedFinalInput(
  "{\"query\":\"deny\"}",
);
assert.equal(changedMalicious.executions, 0);
assert.equal(
  changedMalicious.chunks.some((chunk) => chunk.type === "tool-call"),
  false,
);
assert.equal(
  changedMalicious.chunks.some((chunk) => chunk.type === "error"),
  true,
);
assert.deepEqual(
  changedMalicious.streamCalls.map(({ text }) => text),
  ["{\"query\":\"safe\"}", "{\"query\":\"deny\"}"],
);

const exactInput = await exerciseChangedFinalInput(
  "{\"query\":\"safe\"}",
);
assert.equal(exactInput.executions, 1);
assert.deepEqual(
  exactInput.streamCalls.map(({ text }) => text),
  ["{\"query\":\"safe\"}"],
);

const changedWhitespace = await exerciseChangedFinalInput(
  "{ \"query\": \"safe\" }",
);
assert.equal(changedWhitespace.executions, 1);
assert.deepEqual(
  changedWhitespace.streamCalls.map(({ text }) => text),
  ["{\"query\":\"safe\"}", "{ \"query\": \"safe\" }"],
);
