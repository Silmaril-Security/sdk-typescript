import { describe, expect, it, vi } from "vitest";
import { AIMessage } from "@langchain/core/messages";
import { fakeModel } from "@langchain/core/testing";

vi.mock("deepagents", () => ({
  GENERAL_PURPOSE_SUBAGENT: { name: "general-purpose", description: "General" },
  createDeepAgent: vi.fn((options) => options),
}));

import { Firewall } from "../src/index.js";
import { createProtectedCompiledSubagent, createProtectedDeepAgent } from "../src/adapters/deepagents.js";

describe("protected Deep Agents constructor", () => {
  it("installs middleware on root, general-purpose, and declarative subagents", () => {
    const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    const compiled = createProtectedCompiledSubagent(firewall, {
      name: "compiled", description: "protected separately",
      model: fakeModel().respond(new AIMessage("ok")),
    });
    const agent = createProtectedDeepAgent(firewall, {
      subagents: [{ name: "research", description: "Research" }],
      protectedCompiledSubagents: [compiled],
    });
    const built = agent as unknown as { middleware: Array<{ name: string }>; subagents: Array<{ name: string; middleware?: Array<{ name: string }> }> };
    expect(built.middleware.at(-1)?.name).toBe("SilmarilDeepAgentsMiddleware");
    expect(built.subagents.find((subagent) => subagent.name === "general-purpose")?.middleware?.at(-1)?.name).toBe("SilmarilDeepAgentsMiddleware");
    expect(built.subagents.find((subagent) => subagent.name === "research")?.middleware?.at(-1)?.name).toBe("SilmarilDeepAgentsMiddleware");
    expect(built.subagents.find((subagent) => subagent.name === "compiled")).toBe(compiled);
  });

  it("rejects forged, substituted, and foreign-client compiled graphs", () => {
    const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    const other = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    const compiled = createProtectedCompiledSubagent(firewall, {
      name: "compiled", description: "protected",
      model: fakeModel().respond(new AIMessage("ok")),
    });
    const forged = { name: "forged", description: "forged", runnable: {} as never };
    expect(() => createProtectedDeepAgent(firewall, { protectedCompiledSubagents: [forged] })).toThrow(/createProtectedCompiledSubagent/);
    expect(() => createProtectedDeepAgent(firewall, { protectedCompiledSubagents: [{ ...compiled, runnable: {} as never }] })).toThrow(/createProtectedCompiledSubagent/);
    expect(() => createProtectedDeepAgent(other, { protectedCompiledSubagents: [compiled] })).toThrow(/this Firewall client/);
  });
});
