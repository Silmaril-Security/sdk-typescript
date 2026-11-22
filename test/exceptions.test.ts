// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { describe, expect, it } from "vitest";
import {
  FirewallBlockedException,
  HookLabel,
  PromptBlockedException,
  SilmarilApiError,
} from "../src/index.js";

describe("SilmarilApiError", () => {
  it("composes a redacted message with status and statusText", () => {
    const err = new SilmarilApiError({
      status: 500,
      statusText: "Internal Server Error",
      body: "boom",
    });
    expect(err.message).toBe("Silmaril API error 500 Internal Server Error");
    expect(err.message).not.toContain("boom");
  });

  it("preserves status, statusText, and body as readable fields", () => {
    const err = new SilmarilApiError({
      status: 403,
      statusText: "Forbidden",
      body: '{"error":"bad api key"}',
    });
    expect(err.status).toBe(403);
    expect(err.statusText).toBe("Forbidden");
    expect(err.body).toBe('{"error":"bad api key"}');
    expect(err.name).toBe("SilmarilApiError");
  });

  it("remains an instanceof SilmarilApiError and Error across realms", () => {
    const err = new SilmarilApiError({ status: 0, statusText: "", body: "" });
    expect(err).toBeInstanceOf(SilmarilApiError);
    expect(err).toBeInstanceOf(Error);
  });

  it("tolerates an empty body string without changing the message format", () => {
    const err = new SilmarilApiError({ status: 429, statusText: "Too Many Requests", body: "" });
    expect(err.message).toBe("Silmaril API error 429 Too Many Requests");
  });
});

describe("FirewallBlockedException", () => {
  it.each([
    { name: "no result", params: {} },
    {
      name: "a model block",
      params: {
        result: {
          action: "block" as const,
          source: "model",
          confidence: "high" as const,
          severity: "moderate" as const,
          outcome: "control_abuse",
        },
      },
    },
    {
      name: "a model block that governance also blocks",
      params: {
        result: {
          action: "block" as const,
          source: "model",
          governance: { action: "block" as const, policyVersion: "v1" },
        },
      },
    },
  ])("formats the message for $name", ({ params }) => {
    const err = new FirewallBlockedException({ promptText: "hello", ...params });
    expect(err.message).toBe("Request blocked by Silmaril Firewall: 'hello'");
  });

  it("identifies a governance-policy denial", () => {
    const err = new FirewallBlockedException({
      promptText: "hello",
      result: {
        action: "block",
        source: "governance",
        governance: { action: "block", ruleId: "policy-rule", policyVersion: "v1" },
      },
    });
    expect(err.message).toBe(
      "Request blocked by Silmaril Firewall governance policy: 'hello'",
    );
  });

  it("includes the prompt text verbatim when under the display limit", () => {
    const err = new FirewallBlockedException({
      promptText: "short prompt",
    });
    expect(err.message).toContain("'short prompt'");
  });

  it("truncates prompt text over 100 chars with an ellipsis", () => {
    const longText = "x".repeat(150);
    const err = new FirewallBlockedException({
      promptText: longText,
    });
    expect(err.message).toContain(`'${"x".repeat(100)}...'`);
    expect(err.message).not.toContain(`'${"x".repeat(150)}'`);
  });

  it("does not truncate exactly at the 100-char boundary", () => {
    const exactText = "y".repeat(100);
    const err = new FirewallBlockedException({
      promptText: exactText,
    });
    expect(err.message).toContain(`'${exactText}'`);
    expect(err.message).not.toContain("...");
  });

  it("exposes blocking context as readable fields", () => {
    const result = Object.freeze({
      action: "block" as const,
      source: "model",
      mode: "block" as const,
    });
    const err = new FirewallBlockedException({
      promptText: "p",
      runId: "run-42",
      hook: HookLabel.TOOL_CALL,
      toolName: "execute",
      toolCallId: "tc-42",
      result,
    });
    expect(err).not.toHaveProperty("score");
    expect(err).not.toHaveProperty("threshold");
    expect(err.promptText).toBe("p");
    expect(err.runId).toBe("run-42");
    expect(err.hook).toBe(HookLabel.TOOL_CALL);
    expect(err.toolName).toBe("execute");
    expect(err.toolCallId).toBe("tc-42");
    expect(err.result).toBe(result);
    expect(err.name).toBe("FirewallBlockedException");
  });

  it("leaves runId undefined when not provided", () => {
    const err = new FirewallBlockedException({ promptText: "p" });
    expect(err.runId).toBeUndefined();
  });

  it("remains an instanceof FirewallBlockedException, deprecated alias, and Error", () => {
    const err = new FirewallBlockedException({ promptText: "p" });
    expect(PromptBlockedException).toBe(FirewallBlockedException);
    expect(err).toBeInstanceOf(FirewallBlockedException);
    expect(err).toBeInstanceOf(PromptBlockedException);
    expect(err).toBeInstanceOf(Error);
  });
});
