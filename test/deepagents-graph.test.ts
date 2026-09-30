import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { fakeModel } from "@langchain/core/testing";
import { tool } from "@langchain/core/tools";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { Firewall } from "../src/index.js";
import {
  SAFE_FINAL_MESSAGE, SAFE_OUTPUT_MESSAGE, SAFE_TOOL_MESSAGE,
  createProtectedCompiledSubagent, createProtectedDeepAgent,
} from "../src/adapters/deepagents.js";

function makeFirewall() {
  const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
  firewall.classify = vi.fn(async (text) => ({
    prediction: text.includes("deny") ? "MALICIOUS" : "BENIGN",
    score: text.includes("deny") ? 0.9 : 0.1,
    threshold: 0.5,
    mode: "block",
  })) as typeof firewall.classify;
  return firewall;
}

describe("protected Deep Agents graph", () => {
  it("continues to an allowed tool after denying a tool call", async () => {
    const firewall = makeFirewall();
    const called: string[] = [];
    const search = tool(async ({ query }) => {
      called.push(query);
      return "safe result";
    }, { name: "search", description: "Search", schema: z.object({ query: z.string() }) });
    const model = fakeModel()
      .respondWithTools([{ name: "search", args: { query: "deny" }, id: "call-1" }])
      .respondWithTools([{ name: "search", args: { query: "safe" }, id: "call-2" }])
      .respond(new AIMessage("done"));
    const agent = createProtectedDeepAgent(firewall, { model, tools: [search] });
    const output = await agent.invoke({ messages: [new HumanMessage("hello")] });
    expect(called).toEqual(["safe"]);
    expect(output.messages.filter(ToolMessage.isInstance).map((message: ToolMessage) => [message.tool_call_id, message.content]))
      .toEqual([["call-1", SAFE_TOOL_MESSAGE], ["call-2", "safe result"]]);
  });

  it("ends the current turn after repeated denied tool calls", async () => {
    const firewall = makeFirewall();
    const called: string[] = [];
    const search = tool(async ({ query }) => {
      called.push(query);
      return "safe result";
    }, { name: "search", description: "Search", schema: z.object({ query: z.string() }) });
    const model = fakeModel()
      .respondWithTools([{ name: "search", args: { query: "deny first" }, id: "call-1" }])
      .respondWithTools([{ name: "search", args: { query: "deny second" }, id: "call-2" }])
      .respond(new AIMessage("unreachable"));
    const agent = createProtectedDeepAgent(firewall, { model, tools: [search], silmaril: { maxBlockedAttempts: 2 } });
    const output = await agent.invoke({ messages: [new HumanMessage("hello")] });
    expect(called).toEqual([]);
    expect(output.messages.at(-1)?.content).toBe(SAFE_FINAL_MESSAGE);
  });

  it.each(["general-purpose", "research", "compiled"])("protects %s subagent output", async (name) => {
    const firewall = makeFirewall();
    const root = fakeModel().respondWithTools([{ name: "task", args: { description: "safe task", subagent_type: name }, id: "call-1" }]);
    const compiled = name === "compiled"
      ? [createProtectedCompiledSubagent(firewall, {
        name: "compiled", description: "Compiled",
        model: fakeModel().respond(new AIMessage("deny output")),
      })]
      : [];
    if (name !== "compiled") root.respond(new AIMessage("deny output"));
    root.respond(new AIMessage("done"));
    const agent = createProtectedDeepAgent(firewall, {
      model: root,
      subagents: [{ name: "research", description: "Research" }],
      protectedCompiledSubagents: compiled,
    });
    const output = await agent.invoke({ messages: [new HumanMessage("hello")] });
    expect(output.messages.filter(ToolMessage.isInstance).map((message: ToolMessage) => message.content))
      .toEqual([SAFE_OUTPUT_MESSAGE]);
  });
});
