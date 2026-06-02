// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_CHUNK_CONCURRENCY,
  DEFAULT_TIMEOUT_MS,
  Firewall,
  HookLabel,
  MAX_INPUT_CHARS,
  Outcome,
  SilmarilApiError,
} from "../src/index.js";

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
    const body = withDefaultThresholds(r.body);
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      statusText: `status-${r.status}`,
      json: async () => body,
      text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
    } as unknown as Response;
  };
  globalThis.fetch = impl as unknown as typeof fetch;
  return { calls };
}

function withDefaultThresholds(body: unknown): unknown {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return body;
  }
  const data = body as Record<string, unknown>;
  if (typeof data.prediction === "string" && data.threshold === undefined) {
    return { ...data, threshold: 0.5 };
  }
  if (Array.isArray(data.predictions)) {
    return {
      ...data,
      predictions: data.predictions.map((item) =>
        item && typeof item === "object" && !Array.isArray(item)
          ? { threshold: 0.5, ...(item as Record<string, unknown>) }
          : item,
      ),
    };
  }
  return body;
}

function silmarilMetadata(
  requestId: string,
  inputIndex: number,
  chunkIndex: number,
  chunkCount: number,
): Record<string, unknown> {
  return {
    sdk_language: "typescript",
    sdk_version: "0.4.1",
    request_id: requestId,
    input_index: inputIndex,
    chunk_index: chunkIndex,
    chunk_count: chunkCount,
  };
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

  it("applies defaults for timeoutMs", () => {
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    expect(fw.apiUrl).toBe(TEST_API_URL);
    expect(fw.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    expect(fw.chunkConcurrency).toBe(DEFAULT_CHUNK_CONCURRENCY);
    expect(fw.shadowMode).toBe(false);
  });

  it("accepts option values", () => {
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
    const result = await fw.classify("hello world", { requestId: "req-single" });
    expect(result).toEqual({ prediction: "BENIGN", score: 0.12, threshold: 0.5 });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(TEST_API_URL);
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.redirect).toBe("error");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers["x-api-key"]).toBe("sk-test");
    expect(headers["content-type"]).toBe("application/json");
    expect(calls[0]!.body).toEqual({
      text: "hello world",
      metadata: { silmaril: silmarilMetadata("req-single", 0, 0, 1) },
    });
  });

  it("decodes optional Sapphire outcome fields", async () => {
    mockFetch([
      {
        status: 200,
        body: {
          prediction: "MALICIOUS",
          score: 0.91,
          primary_outcome: Outcome.SecretExposure,
          outcome_scores: { [Outcome.SecretExposure]: 0.8 },
          detector_scores: { [Outcome.SecretExposure]: 1.0 },
          detector_counts: { [Outcome.SecretExposure]: 2 },
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const result = await fw.classify("leak token");

    expect(result).toEqual({
      prediction: "MALICIOUS",
      score: 0.91,
      threshold: 0.5,
      primaryOutcome: Outcome.SecretExposure,
      outcomeScores: { [Outcome.SecretExposure]: 0.8 },
      detectorScores: { [Outcome.SecretExposure]: 1.0 },
      detectorCounts: { [Outcome.SecretExposure]: 2 },
    });
  });

  it("rejects unknown Sapphire outcome fields", async () => {
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    mockFetch([
      {
        status: 200,
        body: {
          prediction: "MALICIOUS",
          score: 0.91,
          primary_outcome: "unknown_outcome",
        },
      },
    ]);
    await expect(fw.classify("x")).rejects.toThrow(/invalid primary_outcome/);

    mockFetch([
      {
        status: 200,
        body: {
          prediction: "MALICIOUS",
          score: 0.91,
          outcome_scores: { unknown_outcome: 0.8 },
        },
      },
    ]);
    await expect(fw.classify("x")).rejects.toThrow(/invalid outcome_scores key/);

    mockFetch([
      {
        status: 200,
        body: {
          prediction: "MALICIOUS",
          score: 0.91,
          detector_scores: { unknown_outcome: 0.8 },
        },
      },
    ]);
    await expect(fw.classify("x")).rejects.toThrow(/invalid detector_scores key/);

    mockFetch([
      {
        status: 200,
        body: {
          prediction: "MALICIOUS",
          score: 0.91,
          detector_counts: { unknown_outcome: 1 },
        },
      },
    ]);
    await expect(fw.classify("x")).rejects.toThrow(/invalid detector_counts key/);
  });

  it("includes hook and tool_name wire keys when provided", async () => {
    const { calls } = mockFetch([{ status: 200, body: { prediction: "MALICIOUS", score: 0.97 } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const result = await fw.classify("suspicious email body", {
      hook: HookLabel.TOOL_RESPONSE,
      toolName: "read_email",
      requestId: "req-hook",
    });
    expect(result.prediction).toBe("MALICIOUS");
    expect(calls[0]!.body).toEqual({
      text: "suspicious email body",
      hook: "tool_response",
      tool_name: "read_email",
      metadata: { silmaril: silmarilMetadata("req-hook", 0, 0, 1) },
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
      requestId: "req-meta",
    });
    expect(calls[0]!.body).toEqual({
      text: "hello",
      hook: "user_input",
      metadata: {
        run_id: "run-123",
        secret_candidate: "sk-test-secret",
        silmaril: silmarilMetadata("req-meta", 0, 0, 1),
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
    const results = await fw.classifyBatch(["a", "b"], { requestId: "batch-req" });
    expect(results).toHaveLength(2);
    expect(results[0]!.prediction).toBe("BENIGN");
    expect(results[1]!.prediction).toBe("MALICIOUS");
    expect(results[0]!.threshold).toBe(0.5);
    expect(results[1]!.threshold).toBe(0.5);
    expect(calls[0]!.body).toEqual({
      texts: ["a", "b"],
      metadata: [
        { silmaril: silmarilMetadata("batch-req", 0, 0, 1) },
        { silmaril: silmarilMetadata("batch-req", 1, 0, 1) },
      ],
    });
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
    await fw.classifyBatch([`bad ${"\ud83d"} value`, `ok 😀 ${"\ude00"}`], {
      requestId: "sanitize-req",
    });
    expect(calls[0]!.body).toEqual({
      texts: ["bad  value", "ok 😀 "],
      metadata: [
        { silmaril: silmarilMetadata("sanitize-req", 0, 0, 1) },
        { silmaril: silmarilMetadata("sanitize-req", 1, 0, 1) },
      ],
    });
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
              primary_outcome: Outcome.SystemCompromise,
              outcome_scores: { [Outcome.SystemCompromise]: 0.92 },
              detector_scores: { [Outcome.InformationDisclosure]: 0.85 },
              detector_counts: { [Outcome.InformationDisclosure]: 1 },
            },
          ],
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const results = await fw.classifyBatch(["a", "b"]);

    expect(results[0]).toEqual({ prediction: "BENIGN", score: 0.01, threshold: 0.5 });
    expect(results[1]).toEqual({
      prediction: "MALICIOUS",
      score: 0.9,
      threshold: 0.5,
      primaryOutcome: Outcome.SystemCompromise,
      outcomeScores: { [Outcome.SystemCompromise]: 0.92 },
      detectorScores: { [Outcome.InformationDisclosure]: 0.85 },
      detectorCounts: { [Outcome.InformationDisclosure]: 1 },
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
      requestId: "hooks-req",
    });
    expect(calls[0]!.body).toEqual({
      texts: ["a"],
      hooks: ["tool_response"],
      tool_names: ["read_file"],
      metadata: [{ silmaril: silmarilMetadata("hooks-req", 0, 0, 1) }],
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
      requestId: "metadata-req",
    });
    expect(calls[0]!.body).toEqual({
      texts: ["a", "b"],
      metadata: [
        { run_id: "run-a", silmaril: silmarilMetadata("metadata-req", 0, 0, 1) },
        { silmaril: silmarilMetadata("metadata-req", 1, 0, 1) },
      ],
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
    await fw.classifyBatch(["a", "b"], {
      toolNames: ["read_file", undefined],
      requestId: "tools-req",
    });
    expect(calls[0]!.body).toEqual({
      texts: ["a", "b"],
      tool_names: ["read_file", null],
      metadata: [
        { silmaril: silmarilMetadata("tools-req", 0, 0, 1) },
        { silmaril: silmarilMetadata("tools-req", 1, 0, 1) },
      ],
    });
  });

  it("does not send thresholds for batch requests", async () => {
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
    expect(calls[0]!.body).not.toHaveProperty("threshold");
    expect(calls[1]!.body).not.toHaveProperty("threshold");
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
    await fw.classify("short", { requestId: "short-req" });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.body).toEqual({
      text: "short",
      metadata: { silmaril: silmarilMetadata("short-req", 0, 0, 1) },
    });
  });

  it("fans out chunk requests and aggregates the max score across chunks", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: { prediction: "BENIGN", score: 0.2, threshold: 0.75 },
      },
      {
        status: 200,
        body: { prediction: "MALICIOUS", score: 0.95, threshold: 0.75 },
      },
      {
        status: 200,
        body: { prediction: "BENIGN", score: 0.4, threshold: 0.75 },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    // 1600 chars/window, 256 overlap -> 1344 stride. 4001 chars makes 3 chunks.
    const longText = "a".repeat(4001);
    const result = await fw.classify(longText, { requestId: "chunk-req" });
    expect(result.prediction).toBe("MALICIOUS");
    expect(result.score).toBe(0.95);
    expect(result.threshold).toBe(0.75);
    expect(calls).toHaveLength(3);
    for (const [index, call] of calls.entries()) {
      expect(call.body).toHaveProperty("text");
      expect(call.body).not.toHaveProperty("texts");
      expect(call.body).not.toHaveProperty("threshold");
      expect((call.body as { metadata: { silmaril: unknown } }).metadata.silmaril).toEqual(
        silmarilMetadata("chunk-req", 0, index, 3),
      );
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
    await fw.classify(text, { hook: HookLabel.TOOL_RESPONSE, requestId: "hook-chunk-req" });
    expect(calls.length).toBeGreaterThan(1);
    for (const [index, call] of calls.entries()) {
      expect(call.body).toMatchObject({ hook: "tool_response" });
      expect(call.body).not.toHaveProperty("threshold");
      expect((call.body as { metadata: { silmaril: unknown } }).metadata.silmaril).toEqual(
        silmarilMetadata("hook-chunk-req", 0, index, calls.length),
      );
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
    await fw.classify(text, {
      hook: HookLabel.TOOL_RESPONSE,
      metadata,
      requestId: "metadata-chunk-req",
    });
    expect(calls.length).toBeGreaterThan(1);
    for (const [index, call] of calls.entries()) {
      expect(call.body).toMatchObject({ hook: "tool_response" });
      expect((call.body as { metadata: Record<string, unknown> }).metadata.run_id).toBe(
        "run-chunked",
      );
      expect((call.body as { metadata: Record<string, unknown> }).metadata.secret_candidate).toBe(
        "sk-test-secret",
      );
      expect((call.body as { metadata: { silmaril: unknown } }).metadata.silmaril).toEqual(
        silmarilMetadata("metadata-chunk-req", 0, index, calls.length),
      );
      expect(call.body).not.toHaveProperty("threshold");
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
        json: async () => ({ prediction: "BENIGN", score: 0.1, threshold: 0.5 }),
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
    const tooLong = "c".repeat(MAX_INPUT_CHARS + 1);
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
