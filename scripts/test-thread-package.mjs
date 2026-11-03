import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { RunnableBinding, RunnableLambda } from "@langchain/core/runnables";
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

  const callbackParent = RunnableLambda.from(async (_input, config) => model.invoke("callback child", {
    ...config,
    configurable: { ...config?.configurable, thread_id: "callback-child" },
  }));
  const callbackFirst = payloads.length;
  await callbackParent.invoke("callback parent", {
    callbacks: [handler],
    configurable: { thread_id: "callback-parent" },
    metadata: { thread_id: "callback-parent" },
  });
  assert.equal(payloads.length - callbackFirst, 2);
  assert.deepEqual(payloads.slice(callbackFirst).map((event) => event.hook), ["user_input", "llm_output"]);
  assert.ok(payloads.slice(callbackFirst).every((event) => event.metadata.conversationId === undefined));

  const protectedModel = await suite.protectLangChainRunnable(fw, model, { hooks: ALL_HOOKS });
  const protectedParent = RunnableLambda.from(async (_input, config) => protectedModel.invoke("protected child", {
    ...config,
    configurable: { ...config?.configurable, thread_id: "protected-child" },
  }));
  const protectedChildFirst = payloads.length;
  await protectedParent.invoke("protected parent", {
    configurable: { thread_id: "protected-parent" },
    metadata: { thread_id: "protected-parent" },
  });
  assert.equal(payloads.length - protectedChildFirst, 2);
  assert.deepEqual(payloads.slice(protectedChildFirst).map((event) => event.hook), ["user_input", "llm_output"]);
  assert.ok(payloads.slice(protectedChildFirst).every((event) => event.metadata.conversationId === "protected-child"));

  const protectedOuter = await suite.protectLangChainRunnable(fw, RunnableLambda.from(async (_input, config) => {
    return model.invoke("bare child", {
      ...config,
      configurable: { ...config?.configurable, thread_id: "bare-child" },
    });
  }), { hooks: ALL_HOOKS });
  const protectedOuterFirst = payloads.length;
  await protectedOuter.invoke("protected outer", {
    configurable: { thread_id: "protected-outer" },
    metadata: { thread_id: "protected-outer" },
  });
  assert.equal(payloads.length - protectedOuterFirst, 2);
  assert.deepEqual(payloads.slice(protectedOuterFirst).map((event) => event.hook), ["user_input", "llm_output"]);
  assert.ok(payloads.slice(protectedOuterFirst).every((event) => event.metadata.conversationId === undefined));

  const first = payloads.length;
  await protectedModel.withListeners({ onEnd: () => {} }).invoke("root", {
    configurable: { thread_id: "bound-root" }, metadata: { thread_id: "wrong" },
  });
  assert.equal(payloads.length - first, 2);
  assert.ok(payloads.slice(first).every((event) => event.metadata.conversationId === "bound-root"));

  const saved = await suite.protectLangChainRunnable(fw, model.withConfig({ configurable: { thread_id: "saved-native" } }), { hooks: ALL_HOOKS });
  const savedFirst = payloads.length;
  await saved.invoke("saved root");
  assert.equal(payloads.length - savedFirst, 2);
  assert.ok(payloads.slice(savedFirst).every((event) => event.metadata.conversationId === "saved-native"));

  const savedBatchFirst = payloads.length;
  await saved.batch(["saved batch", "native override"], [{}, { configurable: { thread_id: "batch-override" } }]);
  assert.equal(payloads.length - savedBatchFirst, 4);
  assert.deepEqual(new Set(payloads.slice(savedBatchFirst).map((event) => event.metadata.conversationId)), new Set(["saved-native", "batch-override"]));
  const savedStreamFirst = payloads.length;
  const savedStream = await saved.stream("saved streaming");
  for await (const _chunk of savedStream) { /* consume */ }
  assert.ok(payloads.length > savedStreamFirst);
  assert.ok(payloads.slice(savedStreamFirst).every((event) => event.metadata.conversationId === "saved-native"));
  let nativeFactoryCalls = 0;
  const dynamic = new RunnableBinding({ bound: model, config: {}, configFactories: [() => {
    nativeFactoryCalls++;
    return { configurable: { thread_id: "dynamic-native" } };
  }] });
  const protectedDynamic = await suite.protectLangChainRunnable(fw, dynamic, { hooks: ALL_HOOKS });
  const dynamicFirst = payloads.length;
  await protectedDynamic.invoke("dynamic config");
  assert.equal(nativeFactoryCalls, 1);
  assert.equal(payloads.length - dynamicFirst, 2);
  assert.ok(payloads.slice(dynamicFirst).every((event) => event.metadata.conversationId === "dynamic-native"));

  for (const configured of [
    protectedDynamic.withConfig({ tags: ["after-protection"] }),
    protectedDynamic.withRetry({ stopAfterAttempt: 2 }),
    protectedDynamic.withListeners({ onEnd: () => {} }),
  ]) {
    const factoryBefore = nativeFactoryCalls;
    const firstEvent = payloads.length;
    await configured.invoke("composed dynamic config");
    assert.equal(nativeFactoryCalls, factoryBefore + 1);
    assert.equal(payloads.length - firstEvent, 2);
    assert.ok(payloads.slice(firstEvent).every((event) => event.metadata.conversationId === "dynamic-native"));
  }

  const agent = suite.createProtectedDeepAgent(fw, { model: new FakeListChatModel({ responses: ["done"] }) });
  const deepFirst = payloads.length;
  await agent.invoke({ messages: [new HumanMessage("research")] }, { configurable: { thread_id: "deep-native" } });
  assert.ok(payloads.length - deepFirst >= 2);
  assert.ok(payloads.slice(deepFirst).every((event) => event.metadata.conversationId === "deep-native"));
  assert.equal(new Set(payloads.map((event) => event.metadata.silmaril.request_id)).size, payloads.length);
  assert.ok(payloads.every((event) => event.metadata.silmaril.sdk_version === "0.8.2"));
  console.log(`${suite.name}: built native-thread graph, runnable, Deep Agents and request-ID checks passed`);
}

try {
  await verify({ name: "ESM", Firewall, createLangChainHandler, protectLangChainRunnable, createProtectedDeepAgent });
  await verify({ name: "CJS", Firewall: cjs.Firewall, ...cjsLangChain, ...cjsDeepAgents });
} finally {
  globalThis.fetch = originalFetch;
}
