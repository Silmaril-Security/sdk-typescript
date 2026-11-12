// This suite intentionally imports only LangChain core. It also runs against
// the supported minimum core version without LangGraph or Deep Agents APIs.
import { AIMessage } from "@langchain/core/messages";
import { FakeListChatModel } from "@langchain/core/utils/testing";
import { RunnableBinding, RunnableLambda } from "@langchain/core/runnables";
import { describe, expect, it, vi } from "vitest";

import { ALL_HOOKS, Firewall } from "../src/index.js";
import { protectLangChainRunnable } from "../src/adapters/langchain.js";

describe("minimum LangChain compatibility", () => {
  it("keeps native identity across reusable nested runnable/model executions", async () => {
    const fw = new Firewall({ apiKey: "test", apiUrl: "https://test.invalid/classify" });
    const ids: unknown[] = [];
    fw.classify = vi.fn(async (_text, options) => {
      ids.push(options?.metadata?.conversationId);
      return { prediction: "BENIGN", score: 0, threshold: 0.5, mode: "block" };
    }) as typeof fw.classify;
    class Model extends FakeListChatModel {
      override async _generate() {
        return { generations: [{ text: "result", message: new AIMessage("result") }] };
      }
    }
    const model = await protectLangChainRunnable(fw, new Model({ responses: ["result"] }), { hooks: ALL_HOOKS });
    const runnable = RunnableLambda.from(async (input: string, config) => model.invoke(input, config));
    for (const thread of ["a", "b", undefined]) {
      const first = ids.length;
      const result = await runnable.invoke("hello", {
        ...(thread === undefined ? {} : { configurable: { thread_id: thread } }),
      });
      expect(result).toBeInstanceOf(AIMessage);
      expect(ids.slice(first)).toEqual([thread, thread]);
    }
  });
});


it("resolves saved native defaults and dynamic factories before protection on minimum core", async () => {
  const fw = new Firewall({ apiKey: "test", apiUrl: "https://test.invalid/classify" });
  const ids: unknown[] = [];
  fw.classify = vi.fn(async (_text, options) => {
    ids.push(options?.metadata?.conversationId);
    return { prediction: "BENIGN", score: 0, threshold: 0.5, mode: "block" };
  }) as typeof fw.classify;
  const native = new FakeListChatModel({ responses: ["result"] });
  const saved = await protectLangChainRunnable(fw, native.withConfig({ configurable: { thread_id: "saved" } }));
  await saved.invoke("hello");
  expect(ids).toEqual(["saved", "saved"]);
  const factory = vi.fn(() => ({ configurable: { thread_id: "dynamic" } }));
  const dynamic = await protectLangChainRunnable(fw, new RunnableBinding({ bound: native, config: {}, configFactories: [factory] }));
  await dynamic.invoke("hello");
  expect(ids).toEqual(["saved", "saved", "dynamic", "dynamic"]);
  expect(factory).toHaveBeenCalledTimes(1);
});
