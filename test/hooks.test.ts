// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { describe, expect, it } from "vitest";
import {
  ALL_HOOKS,
  DEFAULT_HOOKS,
  FIREWALL_HOOK_TO_LABEL,
  FirewallBlockedException,
  FirewallHook,
  HookLabel,
  INPUT_HOOKS,
  OUTPUT_HOOKS,
  prependHook,
  prependToolName,
  resolveHooks,
} from "../src/index.js";

describe("HookLabel values", () => {
  it("match Python wire values", () => {
    expect(HookLabel.USER_INPUT).toBe("user_input");
    expect(HookLabel.SYSTEM_PROMPT).toBe("system_prompt");
    expect(HookLabel.TOOL_CALL).toBe("tool_call");
    expect(HookLabel.TOOL_RESPONSE).toBe("tool_response");
    expect(HookLabel.LLM_OUTPUT).toBe("llm_output");
    expect(HookLabel.UNKNOWN).toBe("unknown");
  });
});

describe("FirewallHook values", () => {
  it("match LangChain callback method names", () => {
    expect(FirewallHook.LLM_START).toBe("on_llm_start");
    expect(FirewallHook.CHAT_MODEL_START).toBe("on_chat_model_start");
    expect(FirewallHook.TOOL_START).toBe("on_tool_start");
    expect(FirewallHook.RETRIEVER_START).toBe("on_retriever_start");
    expect(FirewallHook.LLM_END).toBe("on_llm_end");
    expect(FirewallHook.TOOL_END).toBe("on_tool_end");
    expect(FirewallHook.RETRIEVER_END).toBe("on_retriever_end");
  });
});

describe("Hook sets", () => {
  it("DEFAULT_HOOKS contains chat_model_start and llm_start", () => {
    expect(DEFAULT_HOOKS.has(FirewallHook.CHAT_MODEL_START)).toBe(true);
    expect(DEFAULT_HOOKS.has(FirewallHook.LLM_START)).toBe(true);
    expect(DEFAULT_HOOKS.size).toBe(2);
  });

  it("INPUT_HOOKS and OUTPUT_HOOKS are disjoint", () => {
    for (const h of INPUT_HOOKS) {
      expect(OUTPUT_HOOKS.has(h)).toBe(false);
    }
  });

  it("ALL_HOOKS is the union of INPUT_HOOKS and OUTPUT_HOOKS", () => {
    expect(ALL_HOOKS.size).toBe(INPUT_HOOKS.size + OUTPUT_HOOKS.size);
    for (const h of INPUT_HOOKS) {
      expect(ALL_HOOKS.has(h)).toBe(true);
    }
    for (const h of OUTPUT_HOOKS) {
      expect(ALL_HOOKS.has(h)).toBe(true);
    }
  });
});

describe("FIREWALL_HOOK_TO_LABEL", () => {
  it("maps input hooks to user_input / tool_call", () => {
    expect(FIREWALL_HOOK_TO_LABEL[FirewallHook.CHAT_MODEL_START]).toBe(HookLabel.USER_INPUT);
    expect(FIREWALL_HOOK_TO_LABEL[FirewallHook.LLM_START]).toBe(HookLabel.USER_INPUT);
    expect(FIREWALL_HOOK_TO_LABEL[FirewallHook.TOOL_START]).toBe(HookLabel.TOOL_CALL);
    expect(FIREWALL_HOOK_TO_LABEL[FirewallHook.RETRIEVER_START]).toBe(HookLabel.TOOL_CALL);
  });

  it("maps output hooks to tool_response / llm_output", () => {
    expect(FIREWALL_HOOK_TO_LABEL[FirewallHook.TOOL_END]).toBe(HookLabel.TOOL_RESPONSE);
    expect(FIREWALL_HOOK_TO_LABEL[FirewallHook.RETRIEVER_END]).toBe(HookLabel.TOOL_RESPONSE);
    expect(FIREWALL_HOOK_TO_LABEL[FirewallHook.LLM_END]).toBe(HookLabel.LLM_OUTPUT);
  });
});

describe("resolveHooks", () => {
  it("undefined returns DEFAULT_HOOKS", () => {
    expect(resolveHooks(undefined)).toBe(DEFAULT_HOOKS);
  });

  it("string coercion works for valid hook values", () => {
    const resolved = resolveHooks(["on_llm_start", "on_tool_start"]);
    expect(resolved.has(FirewallHook.LLM_START)).toBe(true);
    expect(resolved.has(FirewallHook.TOOL_START)).toBe(true);
    expect(resolved.size).toBe(2);
  });

  it("throws on invalid hook value", () => {
    expect(() => resolveHooks(["on_nonsense"])).toThrow(/Invalid FirewallHook/);
  });
});

describe("prependHook", () => {
  it("prefixes [HOOK:<label>]", () => {
    expect(prependHook("hello", HookLabel.TOOL_RESPONSE)).toBe("[HOOK:tool_response] hello");
  });

  it("passes through on undefined", () => {
    expect(prependHook("hello", undefined)).toBe("hello");
  });

  it("passes through on unknown", () => {
    expect(prependHook("hello", HookLabel.UNKNOWN)).toBe("hello");
  });
});

describe("prependToolName", () => {
  it("prefixes [TOOL:<name>]", () => {
    expect(prependToolName("read file contents", "read_file")).toBe("[TOOL:read_file] read file contents");
  });

  it("passes through on undefined", () => {
    expect(prependToolName("x", undefined)).toBe("x");
  });
});

describe("FirewallBlockedException", () => {
  it("formats message with score and threshold", () => {
    const err = new FirewallBlockedException({
      score: 0.98765,
      threshold: 0.5,
      promptText: "bad prompt",
    });
    expect(err.name).toBe("FirewallBlockedException");
    expect(err.score).toBe(0.98765);
    expect(err.threshold).toBe(0.5);
    expect(err.message).toContain("score=0.9877");
    expect(err.message).toContain("threshold=0.5000");
    expect(err.message).toContain("'bad prompt'");
  });

  it("truncates long prompt text at 100 chars", () => {
    const longText = "a".repeat(200);
    const err = new FirewallBlockedException({
      score: 0.9,
      threshold: 0.5,
      promptText: longText,
    });
    expect(err.message).toContain("a".repeat(100) + "...");
    expect(err.message).not.toContain("a".repeat(101));
  });

  it("is instanceof Error and FirewallBlockedException", () => {
    const err = new FirewallBlockedException({ score: 0.9, threshold: 0.5, promptText: "x" });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(FirewallBlockedException);
  });
});
