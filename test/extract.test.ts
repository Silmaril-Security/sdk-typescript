// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { describe, expect, it } from "vitest";
import {
  extractTextFromDocuments,
  extractTextFromLLMResult,
  extractTextFromMessages,
  extractTextFromPrompts,
  extractTextFromToolInput,
} from "../src/utils/extract.js";

describe("extractTextFromPrompts", () => {
  it("returns empty string for an empty array", () => {
    expect(extractTextFromPrompts([])).toBe("");
  });

  it("joins multiple prompts with a newline", () => {
    expect(extractTextFromPrompts(["hello", "world"])).toBe("hello\nworld");
  });

  it("trims individual prompts and skips whitespace-only entries", () => {
    expect(extractTextFromPrompts(["  a  ", "\n", "b"])).toBe("a\nb");
  });

  it("returns empty string when every prompt is whitespace", () => {
    expect(extractTextFromPrompts(["   ", "\t", ""])).toBe("");
  });
});

describe("extractTextFromToolInput", () => {
  it("trims whitespace", () => {
    expect(extractTextFromToolInput("  payload  ")).toBe("payload");
  });

  it("returns empty string for whitespace-only input", () => {
    expect(extractTextFromToolInput("   ")).toBe("");
  });

  it("preserves JSON structure without modification", () => {
    expect(extractTextFromToolInput('{"x":1}')).toBe('{"x":1}');
  });
});

describe("extractTextFromLLMResult", () => {
  it("returns empty string when generations is missing", () => {
    expect(extractTextFromLLMResult({})).toBe("");
  });

  it("returns empty string for an empty generations array", () => {
    expect(extractTextFromLLMResult({ generations: [] })).toBe("");
  });

  it("concatenates nested generation text with newlines", () => {
    expect(
      extractTextFromLLMResult({
        generations: [
          [{ text: "first" }],
          [{ text: "second" }, { text: "third" }],
        ],
      }),
    ).toBe("first\nsecond\nthird");
  });

  it("skips generations with missing or whitespace-only text", () => {
    expect(
      extractTextFromLLMResult({
        generations: [[{ text: "  " }, { text: "real" }, {}]],
      }),
    ).toBe("real");
  });
});

describe("extractTextFromDocuments", () => {
  it("returns empty string for an empty array", () => {
    expect(extractTextFromDocuments([])).toBe("");
  });

  it("joins pageContent with newlines", () => {
    expect(
      extractTextFromDocuments([{ pageContent: "one" }, { pageContent: "two" }]),
    ).toBe("one\ntwo");
  });

  it("skips docs with missing or whitespace-only pageContent", () => {
    expect(
      extractTextFromDocuments([{}, { pageContent: "   " }, { pageContent: "doc" }]),
    ).toBe("doc");
  });
});

describe("extractTextFromMessages", () => {
  it("joins user messages with newlines", () => {
    expect(
      extractTextFromMessages([
        { role: "user", content: "hello" },
        { role: "user", content: "world" },
      ]),
    ).toBe("hello\nworld");
  });

  it("skips assistant/ai messages regardless of case", () => {
    expect(
      extractTextFromMessages([
        { role: "AI", content: "ignored" },
        { role: "Assistant", content: "also ignored" },
        { role: "user", content: "kept" },
      ]),
    ).toBe("kept");
  });

  it("excludes system messages when includeSystem=false", () => {
    expect(
      extractTextFromMessages(
        [
          { role: "system", content: "sys" },
          { role: "user", content: "u" },
        ],
        { includeSystem: false },
      ),
    ).toBe("u");
  });

  it("excludes tool/function messages when includeTool=false", () => {
    expect(
      extractTextFromMessages(
        [
          { role: "tool", content: "t" },
          { role: "function", content: "f" },
          { role: "user", content: "u" },
        ],
        { includeTool: false },
      ),
    ).toBe("u");
  });

  it("falls back to message.type when role is missing", () => {
    expect(
      extractTextFromMessages([{ type: "human", content: "hi" } as { type: string; content: string }]),
    ).toBe("hi");
  });

  it("flattens content arrays with text blocks and skips non-text parts", () => {
    expect(
      extractTextFromMessages([
        {
          role: "user",
          content: [
            { type: "text", text: "part one" },
            { type: "image_url" },
            { type: "text", text: "part two" },
          ],
        },
      ]),
    ).toBe("part one part two");
  });
});
