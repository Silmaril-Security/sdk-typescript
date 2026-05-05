// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { describe, expect, it } from "vitest";
import {
  chunkText,
  CHUNK_OVERLAP,
  CHUNK_OVERLAP_CHARS,
  CHUNK_WINDOW,
  CHUNK_WINDOW_CHARS,
  MAX_INPUT_CHARS,
  MAX_INPUT_TOKENS,
  sanitizeText,
} from "../src/index.js";

function hasLoneSurrogate(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 >= text.length || text.charCodeAt(i + 1) < 0xdc00 || text.charCodeAt(i + 1) > 0xdfff) {
        return true;
      }
      i++;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

describe("chunking constants", () => {
  it("pins Python-compatible token/char budgets", () => {
    expect(MAX_INPUT_TOKENS).toBe(10_240);
    expect(CHUNK_WINDOW).toBe(400);
    expect(CHUNK_OVERLAP).toBe(64);
    expect(MAX_INPUT_CHARS).toBe(MAX_INPUT_TOKENS * 4);
    expect(CHUNK_WINDOW_CHARS).toBe(CHUNK_WINDOW * 4);
    expect(CHUNK_OVERLAP_CHARS).toBe(CHUNK_OVERLAP * 4);
  });
});

describe("chunkText — single-chunk fast path", () => {
  it("returns empty string in a single chunk", () => {
    expect(chunkText("")).toEqual([""]);
  });

  it("returns text ≤ CHUNK_WINDOW_CHARS as a single chunk", () => {
    const text = "a".repeat(CHUNK_WINDOW_CHARS);
    const chunks = chunkText(text);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toBe(text);
  });

  it("returns text far under the window unchanged", () => {
    const chunks = chunkText("hello world");
    expect(chunks).toEqual(["hello world"]);
  });
});

describe("chunkText — multi-chunk stride", () => {
  it("splits text just over the window into 2 chunks with overlap", () => {
    const text = "a".repeat(CHUNK_WINDOW_CHARS + 1);
    const chunks = chunkText(text);
    expect(chunks).toHaveLength(2);
    expect(chunks[0]!.length).toBe(CHUNK_WINDOW_CHARS);
    expect(chunks[1]!.length).toBe(
      CHUNK_WINDOW_CHARS + 1 - (CHUNK_WINDOW_CHARS - CHUNK_OVERLAP_CHARS),
    );
  });

  it("each chunk is ≤ CHUNK_WINDOW_CHARS", () => {
    const text = "x".repeat(CHUNK_WINDOW_CHARS * 3 + 17);
    const chunks = chunkText(text);
    for (const c of chunks) {
      expect(c.length).toBeLessThanOrEqual(CHUNK_WINDOW_CHARS);
    }
  });

  it("adjacent chunks share exactly CHUNK_OVERLAP_CHARS characters", () => {
    // Use a positional marker so we can verify overlap boundaries precisely.
    const text = Array.from({ length: CHUNK_WINDOW_CHARS * 2 }, (_, i) =>
      String.fromCharCode(97 + (i % 26)),
    ).join("");
    const chunks = chunkText(text);
    expect(chunks.length).toBeGreaterThan(1);
    for (let i = 1; i < chunks.length; i++) {
      const prevTail = chunks[i - 1]!.slice(-CHUNK_OVERLAP_CHARS);
      const currHead = chunks[i]!.slice(0, CHUNK_OVERLAP_CHARS);
      expect(currHead).toBe(prevTail);
    }
  });

  it("chunk count follows the stride formula for long inputs", () => {
    const L = CHUNK_WINDOW_CHARS * 4;
    const stride = CHUNK_WINDOW_CHARS - CHUNK_OVERLAP_CHARS;
    const expected = Math.ceil((L - CHUNK_OVERLAP_CHARS) / stride);
    const chunks = chunkText("q".repeat(L));
    expect(chunks).toHaveLength(expected);
  });

  it("does not split an emoji at the chunk window boundary", () => {
    const text = `${"a".repeat(CHUNK_WINDOW_CHARS - 1)}😀tail`;
    const chunks = chunkText(text);
    expect(chunks.length).toBeGreaterThan(1);
    expect(chunks.every((chunk) => !hasLoneSurrogate(chunk))).toBe(true);
    expect(chunks.join("|")).toContain("😀");
  });

  it("does not start a chunk with the low half of an emoji at the stride boundary", () => {
    const stride = CHUNK_WINDOW_CHARS - CHUNK_OVERLAP_CHARS;
    const text = `${"a".repeat(stride - 1)}😀${"b".repeat(CHUNK_WINDOW_CHARS)}`;
    const chunks = chunkText(text);
    expect(chunks.length).toBeGreaterThan(1);
    expect(chunks.every((chunk) => !hasLoneSurrogate(chunk))).toBe(true);
  });
});

describe("sanitizeText", () => {
  it("drops lone surrogate halves and preserves valid pairs", () => {
    expect(sanitizeText(`a${"\ud83d"}b${"\ude00"}c😀`)).toBe("abc😀");
  });

  it("preserves valid unusual Unicode", () => {
    const text = "family: 👨‍👩‍👧‍👦 cafe\u0301 null:\0";
    expect(sanitizeText(text)).toBe(text);
    expect(chunkText(text)).toEqual([text]);
  });
});

describe("chunkText — MAX_INPUT_CHARS boundary", () => {
  it("accepts text exactly at MAX_INPUT_CHARS", () => {
    const text = "a".repeat(MAX_INPUT_CHARS);
    expect(() => chunkText(text)).not.toThrow();
  });

  it("throws when text exceeds MAX_INPUT_CHARS by a single character", () => {
    const text = "a".repeat(MAX_INPUT_CHARS + 1);
    expect(() => chunkText(text)).toThrow(/tokens.*chars/);
  });

  it("error message reports actual and max token/char counts", () => {
    const text = "a".repeat(MAX_INPUT_CHARS + 100);
    try {
      chunkText(text);
      throw new Error("expected chunkText to throw");
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toContain(String(MAX_INPUT_TOKENS));
      expect(message).toContain(String(MAX_INPUT_CHARS));
    }
  });
});
