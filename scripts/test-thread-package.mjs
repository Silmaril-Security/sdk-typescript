import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { HumanMessage } from "@langchain/core/messages";
import { FakeListChatModel } from "@langchain/core/utils/testing";
import { END, MessagesAnnotation, START, StateGraph } from "@langchain/langgraph";
import { ALL_HOOKS, Firewall } from "@silmaril-security/sdk";
import { createLangChainHandler, protectLangChainRunnable } from "@silmaril-security/sdk/adapters/langchain";
import { createProtectedDeepAgent } from "@silmaril-security/sdk/adapters/deepagents";

const require = createRequire(import.meta.url);
const cjs = require("@silmaril-security/sdk");
const cjsLangChain = require("@silmaril-security/sdk/adapters/langchain");
const cjsDeepAgents = require("@silmaril-security/sdk/adapters/deepagents");
const originalFetch = globalThis.fetch;

async function verify(suite) {
  const payloads = [];
  globalThis.fetch = async (_url, request) => {
    payloads.push(JSON.parse(request.body));
    return new Response(JSON.stringify({ prediction: "BENIGN", score: 0, threshold: 0.5, mode: "block" }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  };
  const fw = new suite.Firewall({ apiKey: "package-test", apiUrl: "https://package.test.invalid/classify" });
  const handler = await suite.createLangChainHandler(fw, { hooks: ALL_HOOKS });
  const model = new FakeListChatModel({ responses: ["answer"] });
  const graph = new StateGraph(MessagesAnnotation).addNode("work", async (state) => ({
    messages: [await model.invoke(state.messages)],
  })).addEdge(START, "work").addEdge("work", END).compile();
  for (const thread of ["first", "second", undefined]) {
    const first = payloads.length;
    await graph.invoke({ messages: [new HumanMessage("hello")] }, {
      callbacks: [handler], ...(thread === undefined ? {} : { configurable: { thread_id: thread } }),
    });
    const events = payloads.slice(first);
    assert.equal(events.length, 2);
    assert.ok(events.every((event) => event.metadata.conversationId === thread));
  }
  const protectedModel = await suite.protectLangChainRunnable(fw, model, { hooks: ALL_HOOKS });
  const first = payloads.length;
  await protectedModel.withListeners({ onEnd: () => {} }).invoke("root", {
    configurable: { thread_id: "bound-root" }, metadata: { thread_id: "wrong" },
  });
  assert.equal(payloads.length - first, 2);
  assert.ok(payloads.slice(first).every((event) => event.metadata.conversationId === "bound-root"));

  const agent = suite.createProtectedDeepAgent(fw, { model: new FakeListChatModel({ responses: ["done"] }) });
  const deepFirst = payloads.length;
  await agent.invoke({ messages: [new HumanMessage("research")] }, { configurable: { thread_id: "deep-native" } });
  assert.ok(payloads.length - deepFirst >= 2);
  assert.ok(payloads.slice(deepFirst).every((event) => event.metadata.conversationId === "deep-native"));
  assert.equal(new Set(payloads.map((event) => event.metadata.silmaril.request_id)).size, payloads.length);
  assert.ok(payloads.every((event) => event.metadata.silmaril.sdk_version === "0.8.0"));
  console.log(`${suite.name}: built native-thread graph, runnable, Deep Agents and request-ID checks passed`);
}

try {
  await verify({ name: "ESM", Firewall, createLangChainHandler, protectLangChainRunnable, createProtectedDeepAgent });
  await verify({ name: "CJS", Firewall: cjs.Firewall, ...cjsLangChain, ...cjsDeepAgents });
} finally {
  globalThis.fetch = originalFetch;
}
