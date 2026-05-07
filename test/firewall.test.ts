// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_CHUNK_CONCURRENCY,
  DEFAULT_TIMEOUT_MS,
  Firewall,
  HookLabel,
  SilmarilApiError,
} from "../src/index.js";
import { adaptiveThreshold } from "../src/firewall.js";

const TEST_API_URL = "https://api.test.invalid/classify";
const ERROR_BODY_CAP = 1 << 16;

interface MockCall {
  url: string;
  init: RequestInit;
  body: unknown;
}

function mockFetch(responses: Array<{ status: number; body: unknown }>): {
  calls: MockCall[];
} {
  const calls: MockCall[] = [];
  let i = 0;
  const impl = async (url: string | URL, init: RequestInit): Promise<Response> => {
    const parsed = init.body ? JSON.parse(init.body as string) : undefined;
    calls.push({ url: String(url), init, body: parsed });
    const idx = Math.min(i, responses.length - 1);
    i++;
    const r = responses[idx]!;
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      statusText: `status-${r.status}`,
      json: async () => r.body,
      text: async () => (typeof r.body === "string" ? r.body : JSON.stringify(r.body)),
    } as unknown as Response;
  };
  globalThis.fetch = impl as unknown as typeof fetch;
  return { calls };
}

describe("Firewall constructor", () => {
  it("requires apiKey", () => {
    expect(() => new Firewall({ apiKey: "", apiUrl: TEST_API_URL })).toThrow(
      /apiKey is required/,
    );
  });

  it("requires apiUrl", () => {
    expect(() => new Firewall({ apiKey: "sk-test", apiUrl: "" })).toThrow(
      /apiUrl is required/,
    );
  });

  it("computes the adaptive threshold schedule", () => {
    expect(adaptiveThreshold(1)).toBe(0.5);
    expect(adaptiveThreshold(2)).toBeCloseTo(0.6661087830919008);
    expect(adaptiveThreshold(5)).toBeCloseTo(0.8327747955407889);
    expect(adaptiveThreshold(10)).toBe(0.9);
    expect(adaptiveThreshold(100)).toBe(0.9);
    expect(() => adaptiveThreshold(0)).toThrow(/scoringOpportunityCount/);
  });

  it("applies defaults for timeoutMs", () => {
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    expect(fw.apiUrl).toBe(TEST_API_URL);
    expect(fw.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    expect(fw.chunkConcurrency).toBe(DEFAULT_CHUNK_CONCURRENCY);
    expect(fw.shadowMode).toBe(false);
  });

  it("accepts overrides", () => {
    const fw = new Firewall({
      apiKey: "sk-test",
      apiUrl: "https://example.test/classify",
      timeoutMs: 5000,
      chunkConcurrency: 3,
      shadowMode: true,
    });
    expect(fw.apiUrl).toBe("https://example.test/classify");
    expect(fw.timeoutMs).toBe(5000);
    expect(fw.chunkConcurrency).toBe(3);
    expect(fw.shadowMode).toBe(true);
  });

  it("rejects invalid chunkConcurrency", () => {
    expect(() => new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, chunkConcurrency: 0 }))
      .toThrow(/chunkConcurrency must be an integer >= 1/);
    expect(() => new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, chunkConcurrency: 1.5 }))
      .toThrow(/chunkConcurrency must be an integer >= 1/);
  });

  it("rejects invalid timeoutMs", () => {
    expect(() => new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, timeoutMs: -1 }))
      .toThrow(/timeoutMs must be a finite non-negative number/);
    expect(() =>
      new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, timeoutMs: Number.NaN }),
    ).toThrow(/timeoutMs must be a finite non-negative number/);
  });
});

describe("Firewall.classify", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("POSTs the correct wire shape and returns a BlockResult", async () => {
    const { calls } = mockFetch([{ status: 200, body: { prediction: "BENIGN", score: 0.12 } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const result = await fw.classify("hello world");
    expect(result).toEqual({ prediction: "BENIGN", score: 0.12, threshold: 0.5 });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(TEST_API_URL);
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.redirect).toBe("error");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers["x-api-key"]).toBe("sk-test");
    expect(headers["content-type"]).toBe("application/json");
    expect(calls[0]!.body).toEqual({ text: "hello world", threshold: 0.5 });
  });

  it("decodes optional Sapphire outcome fields", async () => {
    mockFetch([
      {
        status: 200,
        body: {
          prediction: "MALICIOUS",
          score: 0.91,
          primary_outcome: "secret_exposure",
          outcome_scores: { secret_exposure: 0.8 },
          detector_scores: { secret_exposure: 1.0 },
          detector_counts: { secret_exposure: 2 },
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const result = await fw.classify("leak token");

    expect(result).toEqual({
      prediction: "MALICIOUS",
      score: 0.91,
      threshold: 0.5,
      primaryOutcome: "secret_exposure",
      outcomeScores: { secret_exposure: 0.8 },
      detectorScores: { secret_exposure: 1.0 },
      detectorCounts: { secret_exposure: 2 },
    });
  });

  it("includes hook and tool_name wire keys when provided", async () => {
    const { calls } = mockFetch([{ status: 200, body: { prediction: "MALICIOUS", score: 0.97 } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const result = await fw.classify("suspicious email body", {
      hook: HookLabel.TOOL_RESPONSE,
      toolName: "read_email",
    });
    expect(result.prediction).toBe("MALICIOUS");
    expect(calls[0]!.body).toEqual({
      text: "suspicious email body",
      threshold: 0.5,
      hook: "tool_response",
      tool_name: "read_email",
    });
  });

  it("includes metadata as a separate wire key when provided", async () => {
    const { calls } = mockFetch([{ status: 200, body: { prediction: "BENIGN", score: 0.2 } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await fw.classify("hello", {
      hook: HookLabel.USER_INPUT,
      metadata: {
        run_id: "run-123",
        secret_candidate: "sk-test-secret",
      },
    });
    expect(calls[0]!.body).toEqual({
      text: "hello",
      threshold: 0.5,
      hook: "user_input",
      metadata: {
        run_id: "run-123",
        secret_candidate: "sk-test-secret",
      },
    });
  });

  it("throws SilmarilApiError on non-2xx non-429", async () => {
    mockFetch([{ status: 500, body: "boom" }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(fw.classify("x")).rejects.toBeInstanceOf(SilmarilApiError);
  });

  it("retries on 429 with exponential backoff and succeeds", async () => {
    vi.useFakeTimers();
    try {
      const { calls } = mockFetch([
        { status: 429, body: "rate limited" },
        { status: 429, body: "rate limited" },
        { status: 200, body: { prediction: "BENIGN", score: 0.01 } },
      ]);
      const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
      const promise = fw.classify("x");
      // Advance through the backoff waits: 2^0=1s, 2^1=2s.
      await vi.advanceTimersByTimeAsync(1_000);
      await vi.advanceTimersByTimeAsync(2_000);
      const result = await promise;
      expect(result.prediction).toBe("BENIGN");
      expect(calls).toHaveLength(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("throws on final 429 after exhausting retries", async () => {
    vi.useFakeTimers();
    try {
      mockFetch([
        { status: 429, body: "rl" },
        { status: 429, body: "rl" },
        { status: 429, body: "rl" },
        { status: 429, body: "rl" },
        { status: 429, body: "rl" },
        { status: 429, body: "rl" },
      ]);
      const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
      const promise = fw.classify("x");
      promise.catch(() => {
        // swallow so the unhandled rejection handler doesn't fire during timer advancing
      });
      // 5 backoffs of up to 30s each — advance generously.
      await vi.advanceTimersByTimeAsync(100_000);
      await expect(promise).rejects.toBeInstanceOf(SilmarilApiError);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("Firewall.classifyBatch", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("POSTs texts and returns BlockResults in order", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: {
          predictions: [
            { prediction: "BENIGN", score: 0.01 },
            { prediction: "MALICIOUS", score: 0.9 },
          ],
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const results = await fw.classifyBatch(["a", "b"]);
    expect(results).toHaveLength(2);
    expect(results[0]!.prediction).toBe("BENIGN");
    expect(results[1]!.prediction).toBe("MALICIOUS");
    expect(results[0]!.threshold).toBe(adaptiveThreshold(2));
    expect(results[1]!.threshold).toBe(adaptiveThreshold(2));
    expect(calls[0]!.body).toEqual({ texts: ["a", "b"], threshold: adaptiveThreshold(2) });
  });

  it("sanitizes lone surrogates before sending batch payloads", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: {
          predictions: [
            { prediction: "BENIGN", score: 0.01 },
            { prediction: "BENIGN", score: 0.02 },
          ],
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await fw.classifyBatch([`bad ${"\ud83d"} value`, `ok 😀 ${"\ude00"}`]);
    expect(calls[0]!.body).toEqual({ texts: ["bad  value", "ok 😀 "], threshold: adaptiveThreshold(2) });
  });

  it("decodes optional Sapphire batch outcome fields", async () => {
    mockFetch([
      {
        status: 200,
        body: {
          predictions: [
            { prediction: "BENIGN", score: 0.01 },
            {
              prediction: "MALICIOUS",
              score: 0.9,
              primary_outcome: "system_compromise",
              outcome_scores: { system_compromise: 0.92 },
              detector_scores: { information_disclosure: 0.85 },
              detector_counts: { information_disclosure: 1 },
            },
          ],
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const results = await fw.classifyBatch(["a", "b"]);

    expect(results[0]).toEqual({ prediction: "BENIGN", score: 0.01, threshold: adaptiveThreshold(2) });
    expect(results[1]).toEqual({
      prediction: "MALICIOUS",
      score: 0.9,
      threshold: adaptiveThreshold(2),
      primaryOutcome: "system_compromise",
      outcomeScores: { system_compromise: 0.92 },
      detectorScores: { information_disclosure: 0.85 },
      detectorCounts: { information_disclosure: 1 },
    });
  });

  it("serializes hooks and tool_names when provided", async () => {
    const { calls } = mockFetch([
      { status: 200, body: { predictions: [{ prediction: "BENIGN", score: 0 }] } },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await fw.classifyBatch(["a"], {
      hooks: [HookLabel.TOOL_RESPONSE],
      toolNames: ["read_file"],
    });
    expect(calls[0]!.body).toEqual({
      texts: ["a"],
      threshold: 0.5,
      hooks: ["tool_response"],
      tool_names: ["read_file"],
    });
  });

  it("serializes metadata when provided", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: {
          predictions: [
            { prediction: "BENIGN", score: 0 },
            { prediction: "BENIGN", score: 0 },
          ],
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await fw.classifyBatch(["a", "b"], {
      metadata: [{ run_id: "run-a" }, undefined],
    });
    expect(calls[0]!.body).toEqual({
      texts: ["a", "b"],
      threshold: adaptiveThreshold(2),
      metadata: [{ run_id: "run-a" }, null],
    });
  });

  it("converts undefined tool names to null on the wire", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: { predictions: [{ prediction: "BENIGN", score: 0 }, { prediction: "BENIGN", score: 0 }] },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await fw.classifyBatch(["a", "b"], { toolNames: ["read_file", undefined] });
    expect(calls[0]!.body).toEqual({
      texts: ["a", "b"],
      threshold: adaptiveThreshold(2),
      tool_names: ["read_file", null],
    });
  });

  it("adapts batch threshold by batch size and caps at 10 texts", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: {
          predictions: Array.from({ length: 5 }, () => ({ prediction: "BENIGN", score: 0 })),
        },
      },
      {
        status: 200,
        body: {
          predictions: Array.from({ length: 10 }, () => ({ prediction: "BENIGN", score: 0 })),
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await fw.classifyBatch(["a", "b", "c", "d", "e"]);
    await fw.classifyBatch(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]);
    expect((calls[0]!.body as { threshold: number }).threshold).toBeCloseTo(adaptiveThreshold(5));
    expect((calls[1]!.body as { threshold: number }).threshold).toBe(0.9);
  });

  it("rejects empty batches before sending", async () => {
    const { calls } = mockFetch([{ status: 200, body: { predictions: [] } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(fw.classifyBatch([])).rejects.toThrow(/texts must not be empty/);
    expect(calls).toHaveLength(0);
  });

  it("rejects hooks length mismatches before sending", async () => {
    const { calls } = mockFetch([{ status: 200, body: { predictions: [] } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(
      fw.classifyBatch(["a", "b"], { hooks: [HookLabel.USER_INPUT] }),
    ).rejects.toThrow(/hooks length 1 does not match texts length 2/);
    expect(calls).toHaveLength(0);
  });

  it("rejects metadata length mismatches before sending", async () => {
    const { calls } = mockFetch([{ status: 200, body: { predictions: [] } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(fw.classifyBatch(["a", "b"], { metadata: [{ run_id: "run-a" }] })).rejects.toThrow(
      /metadata length 1 does not match texts length 2/,
    );
    expect(calls).toHaveLength(0);
  });

  it("rejects toolNames length mismatches before sending", async () => {
    const { calls } = mockFetch([{ status: 200, body: { predictions: [] } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(fw.classifyBatch(["a", "b"], { toolNames: ["read_file"] })).rejects.toThrow(
      /toolNames length 1 does not match texts length 2/,
    );
    expect(calls).toHaveLength(0);
  });
});

describe("Firewall.classify — chunking", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("sends a single text when input is within one chunk", async () => {
    const { calls } = mockFetch([{ status: 200, body: { prediction: "BENIGN", score: 0.1 } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await fw.classify("short");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.body).toEqual({ text: "short", threshold: 0.5 });
  });

  it("fans out chunk requests and aggregates the max score across chunks", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: { prediction: "BENIGN", score: 0.2 },
      },
      {
        status: 200,
        body: { prediction: "MALICIOUS", score: 0.95 },
      },
      {
        status: 200,
        body: { prediction: "BENIGN", score: 0.4 },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    // 1600 chars/window, 256 overlap -> 1344 stride. 4001 chars makes 3 chunks.
    const longText = "a".repeat(4001);
    const result = await fw.classify(longText);
    expect(result.prediction).toBe("MALICIOUS");
    expect(result.score).toBe(0.95);
    expect(result.threshold).toBeCloseTo(adaptiveThreshold(3));
    expect(calls).toHaveLength(3);
    for (const call of calls) {
      expect(call.body).toHaveProperty("text");
      expect(call.body).not.toHaveProperty("texts");
      expect((call.body as { threshold: number }).threshold).toBeCloseTo(adaptiveThreshold(3));
    }
  });

  it("propagates the hook to every chunk request", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: { prediction: "BENIGN", score: 0.1 },
      },
      {
        status: 200,
        body: { prediction: "BENIGN", score: 0.2 },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const text = "b".repeat(2000);
    await fw.classify(text, { hook: HookLabel.TOOL_RESPONSE });
    expect(calls.length).toBeGreaterThan(1);
    for (const call of calls) {
      expect(call.body).toMatchObject({ hook: "tool_response", threshold: adaptiveThreshold(calls.length) });
      expect(call.body).not.toHaveProperty("texts");
    }
  });

  it("propagates metadata to every chunk request", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: { prediction: "BENIGN", score: 0.1 },
      },
      {
        status: 200,
        body: { prediction: "BENIGN", score: 0.2 },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const text = "d".repeat(2000);
    const metadata = { run_id: "run-chunked", secret_candidate: "sk-test-secret" };
    await fw.classify(text, { hook: HookLabel.TOOL_RESPONSE, metadata });
    expect(calls.length).toBeGreaterThan(1);
    for (const call of calls) {
      expect(call.body).toMatchObject({ hook: "tool_response", metadata, threshold: adaptiveThreshold(calls.length) });
      expect(call.body).not.toHaveProperty("texts");
    }
  });

  it("limits chunk fanout concurrency", async () => {
    let active = 0;
    let maxActive = 0;
    let calls = 0;
    globalThis.fetch = (async (_url: string | URL, init: RequestInit): Promise<Response> => {
      JSON.parse(init.body as string);
      calls += 1;
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, 10));
      active -= 1;
      return {
        ok: true,
        status: 200,
        statusText: "status-200",
        json: async () => ({ prediction: "BENIGN", score: 0.1 }),
        text: async () => "",
      } as unknown as Response;
    }) as unknown as typeof fetch;
    const fw = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      chunkConcurrency: 2,
    });
    await fw.classify("e".repeat(8000));
    expect(calls).toBeGreaterThan(2);
    expect(maxActive).toBeLessThanOrEqual(2);
  });

  it("propagates chunk request errors", async () => {
    const { calls } = mockFetch([
      { status: 500, body: "boom" },
      { status: 200, body: { prediction: "BENIGN", score: 0.1 } },
      { status: 200, body: { prediction: "BENIGN", score: 0.1 } },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(fw.classify("f".repeat(4001))).rejects.toBeInstanceOf(SilmarilApiError);
    expect(calls).toHaveLength(3);
  });

  it("throws when input exceeds MAX_INPUT_CHARS", async () => {
    mockFetch([{ status: 200, body: { prediction: "BENIGN", score: 0 } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const tooLong = "c".repeat(10_240 * 4 + 1);
    await expect(fw.classify(tooLong)).rejects.toThrow(/tokens.*chars/);
  });
});

describe("Firewall — error handling", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("propagates fetch network errors unchanged", async () => {
    globalThis.fetch = (async () => {
      throw new TypeError("network down");
    }) as unknown as typeof fetch;
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(fw.classify("x")).rejects.toThrow(/network down/);
  });

  it("wraps 4xx responses with a plain-text body into SilmarilApiError", async () => {
    mockFetch([{ status: 400, body: "bad request body text" }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    let caught: unknown;
    try {
      await fw.classify("x");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(SilmarilApiError);
    const err = caught as SilmarilApiError;
    expect(err.status).toBe(400);
    expect(err.statusText).toBe("status-400");
    expect(err.body).toBe("bad request body text");
    expect(err.message).toBe("Silmaril API error 400 status-400");
  });

  it("wraps 4xx responses with a JSON body into SilmarilApiError", async () => {
    mockFetch([{ status: 401, body: { error: "bad key" } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    let caught: unknown;
    try {
      await fw.classify("x");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(SilmarilApiError);
    const err = caught as SilmarilApiError;
    expect(err.status).toBe(401);
    expect(err.body).toBe('{"error":"bad key"}');
    expect(err.message).not.toContain("bad key");
  });

  it("wraps redirect responses into SilmarilApiError", async () => {
    const { calls } = mockFetch([{ status: 302, body: "redirect" }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    let caught: unknown;
    try {
      await fw.classify("x");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(SilmarilApiError);
    const err = caught as SilmarilApiError;
    expect(calls[0]!.init.redirect).toBe("error");
    expect(err.status).toBe(302);
    expect(err.body).toBe("redirect");
  });

  it("caps API error bodies and keeps them out of the default message", async () => {
    const body = "x".repeat(ERROR_BODY_CAP + 1024);
    mockFetch([{ status: 400, body }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    let caught: unknown;
    try {
      await fw.classify("x");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(SilmarilApiError);
    const err = caught as SilmarilApiError;
    expect(err.body).toBe(body.slice(0, ERROR_BODY_CAP));
    expect(err.body).toHaveLength(ERROR_BODY_CAP);
    expect(err.message).not.toContain(body.slice(0, 128));
  });

  it("parses malformed-input diagnostic details from JSON error bodies", async () => {
    mockFetch([
      {
        status: 400,
        body: {
          error: "MalformedInput",
          message: "Input contains malformed text that could not be tokenized",
          details: {
            field: "texts[0]",
            inputIndex: 0,
            charOffset: 12,
            malformedToken: "\\uD83D",
            codePoint: "U+D83D",
            reason: "lone_high_surrogate",
          },
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    let caught: unknown;
    try {
      await fw.classify("x");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(SilmarilApiError);
    const err = caught as SilmarilApiError;
    expect(err.error).toBe("MalformedInput");
    expect(err.apiMessage).toBe("Input contains malformed text that could not be tokenized");
    expect(err.details).toEqual({
      field: "texts[0]",
      inputIndex: 0,
      charOffset: 12,
      malformedToken: "\\uD83D",
      codePoint: "U+D83D",
      reason: "lone_high_surrogate",
    });
  });

  it("still throws SilmarilApiError when response.text() rejects", async () => {
    globalThis.fetch = (async () =>
      ({
        ok: false,
        status: 502,
        statusText: "Bad Gateway",
        text: async () => {
          throw new Error("stream closed");
        },
        json: async () => ({}),
      } as unknown as Response)) as unknown as typeof fetch;
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    let caught: unknown;
    try {
      await fw.classify("x");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(SilmarilApiError);
    const err = caught as SilmarilApiError;
    expect(err.status).toBe(502);
    expect(err.body).toBe("");
  });

  it("propagates response.json() rejection on a 2xx response", async () => {
    globalThis.fetch = (async () =>
      ({
        ok: true,
        status: 200,
        statusText: "OK",
        text: async () => "",
        json: async () => {
          throw new SyntaxError("unexpected token");
        },
      } as unknown as Response)) as unknown as typeof fetch;
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(fw.classify("x")).rejects.toThrow(/unexpected token/);
  });

  it("surfaces AbortSignal.timeout when the request runs past timeoutMs", async () => {
    // Real fetch would honor AbortSignal.timeout; emulate by throwing the
    // AbortError that Node emits when a timed-out signal fires.
    globalThis.fetch = (async (_url: unknown, init: RequestInit | undefined) => {
      const signal = init?.signal;
      await new Promise<void>((_resolve, reject) => {
        const check = (): void => {
          if (signal?.aborted) {
            const abort = new Error("The operation was aborted due to timeout");
            abort.name = "TimeoutError";
            reject(abort);
          }
        };
        signal?.addEventListener("abort", check);
        setTimeout(check, 10);
      });
      throw new Error("unreachable");
    }) as unknown as typeof fetch;
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, timeoutMs: 1 });
    await expect(fw.classify("x")).rejects.toThrow(/aborted|timeout/i);
  });
});
