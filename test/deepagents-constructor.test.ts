import { afterEach, describe, expect, it, vi } from "vitest";
import { AIMessage } from "@langchain/core/messages";
import { fakeModel } from "@langchain/core/testing";
import { tool } from "@langchain/core/tools";
import { ChatAnthropic } from "@langchain/anthropic";
import { ChatOpenAI } from "@langchain/openai";
import { createMiddleware } from "langchain";
import { ConfigurableModel } from "langchain/chat_models/universal";
import { z } from "zod";

vi.mock("deepagents", () => ({
  EMPTY_HARNESS_PROFILE: {
    baseSystemPrompt: undefined,
    systemPromptSuffix: undefined,
    toolDescriptionOverrides: {},
    excludedTools: new Set(),
    excludedMiddleware: new Set(),
    extraMiddleware: [],
    generalPurposeSubagent: undefined,
  },
  GENERAL_PURPOSE_SUBAGENT: {
    name: "general-purpose",
    description: "General",
    systemPrompt: "Default prompt",
  },
  getHarnessProfile: vi.fn(() => undefined),
  createDeepAgent: vi.fn((options) => options),
}));

import { getHarnessProfile } from "deepagents";
import { Firewall } from "../src/index.js";
import { createProtectedCompiledSubagent, createProtectedDeepAgent } from "../src/adapters/deepagents.js";

function profile(
  overrides: Partial<NonNullable<ReturnType<typeof getHarnessProfile>>> = {},
): NonNullable<ReturnType<typeof getHarnessProfile>> {
  return {
    baseSystemPrompt: undefined,
    systemPromptSuffix: undefined,
    toolDescriptionOverrides: {},
    excludedTools: new Set(),
    excludedMiddleware: new Set(),
    extraMiddleware: [],
    generalPurposeSubagent: undefined,
    ...overrides,
  };
}

afterEach(() => {
  vi.mocked(getHarnessProfile).mockReset();
  vi.mocked(getHarnessProfile).mockReturnValue(undefined);
});

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

  it("honors released disabled and customized string profiles without duplication", () => {
    const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    vi.mocked(getHarnessProfile).mockReturnValueOnce(profile({
      generalPurposeSubagent: { enabled: false },
    }));
    const disabled = createProtectedDeepAgent(firewall, { model: "test:disabled" });
    expect((disabled as unknown as { subagents: Array<{ name: string }> }).subagents)
      .toEqual([]);

    vi.mocked(getHarnessProfile).mockReturnValueOnce(profile({
      baseSystemPrompt: "Profile base",
      systemPromptSuffix: "Profile suffix",
      generalPurposeSubagent: { description: "Custom description" },
    }));
    const customized = createProtectedDeepAgent(firewall, { model: "test:custom" });
    const specs = (customized as unknown as {
      subagents: Array<{
        name: string;
        description: string;
        systemPrompt: string;
        middleware: Array<{ name: string }>;
      }>;
    }).subagents;
    expect(specs).toHaveLength(1);
    expect(specs[0]).toMatchObject({
      name: "general-purpose",
      description: "Custom description",
      systemPrompt: "Profile base\n\nProfile suffix",
    });
    expect(specs[0]?.middleware.at(-1)?.name)
      .toBe("SilmarilDeepAgentsMiddleware");
    expect(getHarnessProfile).toHaveBeenCalledWith("test:custom");
  });

  it("matches the released model-object exact, spec, and provider fallback order", () => {
    const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    const disabled = profile({
      generalPurposeSubagent: { enabled: false },
    });
    vi.mocked(getHarnessProfile).mockImplementation(
      (spec) => spec === "openai:gpt-exact" ? disabled : undefined,
    );
    const exact = createProtectedDeepAgent(firewall, {
      model: {
        getName: () => "ChatOpenAI",
        modelName: "gpt-exact",
      } as never,
    });
    expect((exact as unknown as { subagents: unknown[] }).subagents).toEqual([]);
    expect(vi.mocked(getHarnessProfile).mock.calls.map(([spec]) => spec))
      .toEqual(["openai:gpt-exact"]);

    vi.mocked(getHarnessProfile).mockReset();
    vi.mocked(getHarnessProfile).mockImplementation(
      (spec) => spec === "openai"
        ? profile({ generalPurposeSubagent: { description: "Provider profile" } })
        : undefined,
    );
    const fallback = createProtectedDeepAgent(firewall, {
      model: {
        getName: () => "ConfigurableModel",
        _defaultConfig: { modelProvider: "openai", model: "gpt-fallback" },
      } as never,
    });
    expect(vi.mocked(getHarnessProfile).mock.calls.map(([spec]) => spec))
      .toEqual(["openai:gpt-fallback", "openai"]);
    expect((fallback as unknown as {
      subagents: Array<{ description: string }>;
    }).subagents[0]?.description).toBe("Provider profile");

    vi.mocked(getHarnessProfile).mockReset();
    vi.mocked(getHarnessProfile).mockImplementation(
      (spec) => spec === "anthropic:qualified"
        ? profile({ generalPurposeSubagent: { enabled: false } })
        : undefined,
    );
    createProtectedDeepAgent(firewall, {
      model: {
        getName: () => "UnknownModel",
        model_name: "anthropic:qualified",
      } as never,
    });
    expect(vi.mocked(getHarnessProfile).mock.calls.map(([spec]) => spec))
      .toEqual(["anthropic:qualified"]);
  });

  it("resolves actual known and configurable model instances without inference", () => {
    const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    const disabled = profile({
      generalPurposeSubagent: { enabled: false },
    });

    vi.mocked(getHarnessProfile).mockImplementation(
      (spec) => spec === "openai" ? disabled : undefined,
    );
    createProtectedDeepAgent(firewall, {
      model: new ChatOpenAI({ apiKey: "fixture", model: "gpt-profile" }),
    });
    expect(vi.mocked(getHarnessProfile).mock.calls.map(([spec]) => spec))
      .toEqual(["openai"]);

    vi.mocked(getHarnessProfile).mockReset();
    vi.mocked(getHarnessProfile).mockImplementation(
      (spec) => spec === "anthropic:claude-profile" ? disabled : undefined,
    );
    createProtectedDeepAgent(firewall, {
      model: new ChatAnthropic({
        apiKey: "fixture",
        model: "claude-profile",
      }),
    });
    expect(vi.mocked(getHarnessProfile).mock.calls.map(([spec]) => spec))
      .toEqual(["anthropic:claude-profile"]);

    vi.mocked(getHarnessProfile).mockReset();
    vi.mocked(getHarnessProfile).mockImplementation(
      (spec) => spec === "openai:gpt-configurable" ? disabled : undefined,
    );
    createProtectedDeepAgent(firewall, {
      model: new ConfigurableModel({
        defaultConfig: {
          modelProvider: "openai",
          model: "gpt-configurable",
        },
      }),
    });
    expect(vi.mocked(getHarnessProfile).mock.calls.map(([spec]) => spec))
      .toEqual(["openai:gpt-configurable"]);
  });

  it("rejects invalid model-object hint shapes instead of ignoring profiles", () => {
    const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    expect(() => createProtectedDeepAgent(firewall, {
      model: {
        getName: () => "ConfigurableModel",
        _defaultConfig: "invalid",
      } as never,
    })).toThrow(/_defaultConfig must be an object/);
    expect(() => createProtectedDeepAgent(firewall, {
      model: {
        getName: () => "ChatOpenAI",
        modelName: 42,
      } as never,
    })).toThrow(/modelName profile hint must be a string/);
  });

  it("preserves parent tools, skills, prototypes, and matching GP middleware slots", () => {
    const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    const search = tool(async () => "ok", {
      name: "search",
      description: "Original description",
      schema: z.object({ query: z.string() }),
    });
    const summarization = createMiddleware({ name: "SummarizationMiddleware" });
    const profileOverride = createMiddleware({ name: "ProfileMiddleware" });
    const novel = createMiddleware({ name: "NovelRootMiddleware" });
    vi.mocked(getHarnessProfile).mockReturnValueOnce(profile({
      toolDescriptionOverrides: { search: "Profile description" },
      excludedTools: new Set(["excluded"]),
      extraMiddleware: [createMiddleware({ name: "ProfileMiddleware" })],
    }));

    const agent = createProtectedDeepAgent(firewall, {
      model: "test:inheritance",
      tools: [search],
      skills: ["/skills/"],
      middleware: [summarization, profileOverride, novel],
    });
    const built = agent as unknown as {
      middleware: Array<{ name: string }>;
      subagents: Array<{
        name: string;
        tools: Array<{ description: string }>;
        skills: string[];
        middleware: Array<{ name: string }>;
      }>;
    };
    const generalPurpose = built.subagents.find(
      (subagent) => subagent.name === "general-purpose",
    )!;
    expect(generalPurpose.skills).toEqual(["/skills/"]);
    expect(generalPurpose.tools[0]).not.toBe(search);
    expect(Object.getPrototypeOf(generalPurpose.tools[0]))
      .toBe(Object.getPrototypeOf(search));
    expect(generalPurpose.tools[0]?.description).toBe("Profile description");
    expect(generalPurpose.middleware.map((entry) => entry.name)).toEqual([
      "SummarizationMiddleware",
      "ProfileMiddleware",
      "SilmarilDeepAgentsMiddleware",
    ]);
    expect(built.middleware.map((entry) => entry.name)).toEqual([
      "SummarizationMiddleware",
      "ProfileMiddleware",
      "NovelRootMiddleware",
      "SilmarilDeepAgentsMiddleware",
    ]);
  });

  it("fails before silently losing root overrides behind a profile middleware factory", () => {
    const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    const factory = vi.fn(() => [createMiddleware({ name: "DynamicProfileMiddleware" })]);
    vi.mocked(getHarnessProfile).mockReturnValue(profile({
      extraMiddleware: factory,
    }));
    expect(() => createProtectedDeepAgent(firewall, {
      model: "test:factory",
      middleware: [createMiddleware({ name: "SummarizationMiddleware" })],
    })).toThrow(/extraMiddleware factory/);
    expect(factory).not.toHaveBeenCalled();
  });

  it.each(["isolated", "fork"] as const)("puts compiled %s mode on the spec", (mode) => {
    const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    const compiled = createProtectedCompiledSubagent(firewall, {
      name: "compiled", description: "protected", mode,
      model: fakeModel().respond(new AIMessage("ok")),
    });
    expect(compiled.mode).toBe(mode);
    const parent = createProtectedDeepAgent(firewall, {
      protectedCompiledSubagents: [compiled],
    });
    const passed = (parent as unknown as {
      subagents: Array<{ name: string; mode?: "isolated" | "fork" }>;
    }).subagents.find((subagent) => subagent.name === "compiled");
    expect(passed).toBe(compiled);
    expect(passed?.mode).toBe(mode);
  });

  it("omits unspecified compiled mode and rejects mode mutation", () => {
    const firewall = new Firewall({ apiKey: "sk", apiUrl: "https://example.com/classify" });
    const compiled = createProtectedCompiledSubagent(firewall, {
      name: "compiled", description: "protected",
      model: fakeModel().respond(new AIMessage("ok")),
    });
    expect(Object.hasOwn(compiled, "mode")).toBe(false);
    Reflect.set(compiled, "mode", "invalid");
    expect(() => createProtectedDeepAgent(firewall, {
      protectedCompiledSubagents: [compiled],
    })).toThrow(/createProtectedCompiledSubagent/);

    const changed = createProtectedCompiledSubagent(firewall, {
      name: "changed", description: "protected", mode: "isolated",
      model: fakeModel().respond(new AIMessage("ok")),
    });
    Reflect.set(changed, "mode", "fork");
    expect(() => createProtectedDeepAgent(firewall, {
      protectedCompiledSubagents: [changed],
    })).toThrow(/createProtectedCompiledSubagent/);
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
