// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import { describe, expect, it } from "vitest";

import { sanitizeText } from "../src/sanitization.js";

describe("sanitizeText", () => {
  it("removes a lone high surrogate", () => {
    expect(sanitizeText("hello\ud800world")).toBe("helloworld");
  });

  it("removes a lone low surrogate", () => {
    expect(sanitizeText("hello\udc00world")).toBe("helloworld");
  });

  it("preserves a valid surrogate pair", () => {
    expect(sanitizeText("hello\ud83d\ude80world")).toBe("hello🚀world");
  });

  it("preserves an emoji ZWJ sequence", () => {
    expect(sanitizeText("developer 👩‍💻 ready")).toBe("developer 👩‍💻 ready");
  });
});
