// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { describe, expect, it } from "vitest";
import { PromptBlockedException, SilmarilApiError } from "../src/index.js";

describe("SilmarilApiError", () => {
  it("composes a message with status, statusText, and body", () => {
    const err = new SilmarilApiError({
      status: 500,
      statusText: "Internal Server Error",
      body: "boom",
    });
    expect(err.message).toBe("Silmaril API error 500 Internal Server Error: boom");
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
    expect(err.message).toBe("Silmaril API error 429 Too Many Requests: ");
  });
});

describe("PromptBlockedException", () => {
  it("formats score and threshold to 4 decimals", () => {
    const err = new PromptBlockedException({
      score: 0.9876543,
      threshold: 0.5,
      promptText: "hello",
    });
    expect(err.message).toContain("score=0.9877");
    expect(err.message).toContain("threshold=0.5000");
  });

  it("includes the prompt text verbatim when under the display limit", () => {
    const err = new PromptBlockedException({
      score: 0.9,
      threshold: 0.5,
      promptText: "short prompt",
    });
    expect(err.message).toContain("'short prompt'");
  });

  it("truncates prompt text over 100 chars with an ellipsis", () => {
    const longText = "x".repeat(150);
    const err = new PromptBlockedException({
      score: 0.9,
      threshold: 0.5,
      promptText: longText,
    });
    expect(err.message).toContain(`'${"x".repeat(100)}...'`);
    expect(err.message).not.toContain(`'${"x".repeat(150)}'`);
  });

  it("does not truncate exactly at the 100-char boundary", () => {
    const exactText = "y".repeat(100);
    const err = new PromptBlockedException({
      score: 0.9,
      threshold: 0.5,
      promptText: exactText,
    });
    expect(err.message).toContain(`'${exactText}'`);
    expect(err.message).not.toContain("...");
  });

  it("exposes score, threshold, promptText, and runId as readable fields", () => {
    const err = new PromptBlockedException({
      score: 0.7,
      threshold: 0.5,
      promptText: "p",
      runId: "run-42",
    });
    expect(err.score).toBe(0.7);
    expect(err.threshold).toBe(0.5);
    expect(err.promptText).toBe("p");
    expect(err.runId).toBe("run-42");
    expect(err.name).toBe("PromptBlockedException");
  });

  it("leaves runId undefined when not provided", () => {
    const err = new PromptBlockedException({ score: 0.9, threshold: 0.5, promptText: "p" });
    expect(err.runId).toBeUndefined();
  });

  it("remains an instanceof PromptBlockedException and Error", () => {
    const err = new PromptBlockedException({ score: 0.9, threshold: 0.5, promptText: "p" });
    expect(err).toBeInstanceOf(PromptBlockedException);
    expect(err).toBeInstanceOf(Error);
  });
});
