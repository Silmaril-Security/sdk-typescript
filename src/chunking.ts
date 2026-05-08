// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

const CHARS_PER_TOKEN = 4;

export const MAX_INPUT_TOKENS = 81_920;
export const CHUNK_WINDOW = 400;
export const CHUNK_OVERLAP = 64;

export const MAX_INPUT_CHARS = MAX_INPUT_TOKENS * CHARS_PER_TOKEN;
export const CHUNK_WINDOW_CHARS = CHUNK_WINDOW * CHARS_PER_TOKEN;
export const CHUNK_OVERLAP_CHARS = CHUNK_OVERLAP * CHARS_PER_TOKEN;
const CHUNK_STRIDE_CHARS = CHUNK_WINDOW_CHARS - CHUNK_OVERLAP_CHARS;

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

export function sanitizeText(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (isHighSurrogate(code)) {
      if (i + 1 < text.length && isLowSurrogate(text.charCodeAt(i + 1))) {
        out += text[i]!;
        out += text[i + 1]!;
        i++;
      }
      continue;
    }
    if (isLowSurrogate(code)) {
      continue;
    }
    out += text[i]!;
  }
  return out;
}

function safeChunkStart(text: string, start: number): number {
  if (
    start > 0 &&
    start < text.length &&
    isLowSurrogate(text.charCodeAt(start)) &&
    isHighSurrogate(text.charCodeAt(start - 1))
  ) {
    return start + 1;
  }
  return start;
}

function safeChunkEnd(text: string, end: number): number {
  if (
    end > 0 &&
    end < text.length &&
    isHighSurrogate(text.charCodeAt(end - 1)) &&
    isLowSurrogate(text.charCodeAt(end))
  ) {
    return end - 1;
  }
  return end;
}

export function chunkText(text: string): string[] {
  text = sanitizeText(text);
  const n = text.length;
  if (n > MAX_INPUT_CHARS) {
    throw new Error(
      `Input has ~${Math.floor(n / CHARS_PER_TOKEN)} tokens (${n} chars); ` +
        `max is ${MAX_INPUT_TOKENS} tokens (${MAX_INPUT_CHARS} chars)`,
    );
  }
  if (n <= CHUNK_WINDOW_CHARS) {
    return [text];
  }
  const chunks: string[] = [];
  for (let start = 0; start < n; start += CHUNK_STRIDE_CHARS) {
    const safeStart = safeChunkStart(text, start);
    if (safeStart >= n) {
      break;
    }
    const end = safeChunkEnd(text, safeStart + CHUNK_WINDOW_CHARS);
    chunks.push(text.slice(safeStart, end));
    if (end >= n) {
      break;
    }
  }
  return chunks;
}
