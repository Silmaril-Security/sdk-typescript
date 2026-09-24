// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { readFileSync } from "node:fs";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_TIMEOUT_MS,
  Firewall,
  HookLabel,
  Outcome,
  SilmarilApiError,
} from "../src/index.js";
import { SDK_VERSION } from "../src/firewall.js";

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
    return { mode: "block", ...data, threshold: 0.5 };
  }
  if (typeof data.prediction === "string" && data.mode === undefined) {
    return { mode: "block", ...data };
  }
  if (Array.isArray(data.predictions)) {
    return {
      ...data,
      predictions: data.predictions.map((item) =>
        item && typeof item === "object" && !Array.isArray(item)
          ? { threshold: 0.5, mode: "block", ...(item as Record<string, unknown>) }
          : item,
      ),
    };
  }
  return body;
}

function silmarilMetadata(requestId: string, inputIndex?: number): Record<string, unknown> {
  return {
    sdk_language: "typescript",
    sdk_version: SDK_VERSION,
    request_id: requestId,
    ...(inputIndex === undefined ? {} : { input_index: inputIndex }),
  };
}

describe("SDK release metadata", () => {
  it("keeps the runtime SDK version aligned with package metadata", () => {
    const packageJson = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as { version: string };

    expect(SDK_VERSION).toBe(packageJson.version);
  });
});

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
    expect(fw.shadowMode).toBe(false);
    expect(fw.mode).toBeUndefined();
  });

  it("accepts option values", () => {
    const fw = new Firewall({
      apiKey: "sk-test",
      apiUrl: "https://example.test/classify",
      timeoutMs: 5000,
      shadowMode: true,
    });
    expect(fw.apiUrl).toBe("https://example.test/classify");
    expect(fw.timeoutMs).toBe(5000);
    expect(fw.shadowMode).toBe(true);
    expect(fw.mode).toBe("shadow");
  });

  it("maps legacy shadowMode and gives explicit mode precedence", () => {
    expect(new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      shadowMode: false,
    }).mode).toBe("block");
    expect(new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      mode: "warn",
      shadowMode: true,
    }).mode).toBe("warn");
  });

  it("rejects invalid timeoutMs", () => {
    expect(() => new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, timeoutMs: -1 }))
      .toThrow(/timeoutMs must be a finite non-negative number/);
    expect(() =>
      new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, timeoutMs: Number.NaN }),
    ).toThrow(/timeoutMs must be a finite non-negative number/);
  });

  it("rejects a timeoutMs a timer cannot represent", () => {
    // 2^31-1 is the largest delay setTimeout keeps; anything larger silently
    // collapses to 1 ms and would abort almost immediately.
    const fw = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      timeoutMs: 2_147_483_647,
    });
    expect(fw.timeoutMs).toBe(2_147_483_647);

    expect(
      () => new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, timeoutMs: 2_147_483_648 }),
    ).toThrow(/timeoutMs must be at most 2147483647 ms, got 2147483648/);
    expect(
      () => new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, timeoutMs: 4_000_000_000 }),
    ).toThrow(/timeoutMs must be at most 2147483647 ms, got 4000000000/);
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
    expect(result).toEqual({
      prediction: "BENIGN",
      score: 0.12,
      threshold: 0.5,
      mode: "block",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(TEST_API_URL);
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.redirect).toBe("error");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers["x-api-key"]).toBe("sk-test");
    expect(headers["content-type"]).toBe("application/json");
    expect(calls[0]!.body).toEqual({
      text: "hello world",
      metadata: { silmaril: silmarilMetadata("req-single") },
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
      mode: "block",
      primaryOutcome: Outcome.SecretExposure,
      outcomeScores: { [Outcome.SecretExposure]: 0.8 },
      detectorScores: { [Outcome.SecretExposure]: 1.0 },
      detectorCounts: { [Outcome.SecretExposure]: 2 },
    });
  });

  it("requires a valid backend prediction", async () => {
    mockFetch([{ status: 200, body: { score: 0.99, threshold: 0.5 } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    await expect(fw.classify("missing prediction")).rejects.toThrow(
      /response prediction must be BENIGN or MALICIOUS/,
    );
  });

  it("decodes future Sapphire outcome labels", async () => {
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    mockFetch([
      {
        status: 200,
        body: {
          prediction: "MALICIOUS",
          score: 0.91,
          primary_outcome: "data_exfiltration",
          outcome_scores: { data_exfiltration: 0.8 },
          detector_scores: { data_exfiltration: 0.7 },
          detector_counts: { data_exfiltration: 1 },
        },
      },
    ]);
    await expect(fw.classify("x")).resolves.toEqual({
      prediction: "MALICIOUS",
      score: 0.91,
      threshold: expect.any(Number),
      mode: "block",
      primaryOutcome: "data_exfiltration",
      outcomeScores: { data_exfiltration: 0.8 },
      detectorScores: { data_exfiltration: 0.7 },
      detectorCounts: { data_exfiltration: 1 },
    });
  });

  it("rejects malformed Sapphire outcome fields", async () => {
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    mockFetch([{ status: 200, body: { prediction: "MALICIOUS", score: 0.91, primary_outcome: 42 } }]);
    await expect(fw.classify("x")).rejects.toThrow(/invalid primary_outcome/);

    mockFetch([
      {
        status: 200,
        body: { prediction: "MALICIOUS", score: 0.91, outcome_scores: { [Outcome.Benign]: 0.8 } },
      },
    ]);
    await expect(fw.classify("x")).rejects.toThrow(/invalid outcome_scores key/);

    mockFetch([
      {
        status: 200,
        body: {
          prediction: "MALICIOUS",
          score: 0.91,
          detector_scores: { [Outcome.SecretExposure]: "high" },
        },
      },
    ]);
    await expect(fw.classify("x")).rejects.toThrow(/invalid detector_scores value/);
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
      metadata: { silmaril: silmarilMetadata("req-hook") },
    });
  });

  it("serializes governance context under existing Silmaril metadata", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: {
          prediction: "BENIGN",
          score: 0.1,
          governance: {
            action: "block",
            rule_id: "block-unapproved-mcp",
            policy_version: "pwc-v1",
          },
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const result = await fw.classify("create issue", {
      toolName: "create_issue",
      governance: {
        agent: "cursor",
        resource: { kind: "mcp_tool", id: "create_issue", parentId: "github" },
      },
      metadata: { run_id: "run-123", silmaril: { host: "cursor" } },
      requestId: "req-governance",
    });

    expect(calls[0]!.body).toEqual({
      text: "create issue",
      tool_name: "create_issue",
      metadata: {
        run_id: "run-123",
        silmaril: {
          host: "cursor",
          ...silmarilMetadata("req-governance"),
          governance: {
            agent: "cursor",
            resource: {
              kind: "mcp_tool",
              id: "create_issue",
              parent_id: "github",
            },
          },
        },
      },
    });
    expect(result.governance).toEqual({
      action: "block",
      ruleId: "block-unapproved-mcp",
      policyVersion: "pwc-v1",
    });
  });

  it("accepts legacy responses without governance and rejects malformed decisions", async () => {
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    mockFetch([{ status: 200, body: { prediction: "BENIGN", score: 0.1 } }]);
    await expect(fw.classify("legacy")).resolves.not.toHaveProperty("governance");

    mockFetch([
      {
        status: 200,
        body: {
          prediction: "BENIGN",
          score: 0.1,
          governance: { action: "warn", policy_version: "v1" },
        },
      },
    ]);
    await expect(fw.classify("invalid")).rejects.toThrow(
      /governance action must be allow or block/,
    );
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
        silmaril: silmarilMetadata("req-meta"),
      },
    });
  });

  it("keeps an explicit request override authoritative across a mixed backend rollout", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: { prediction: "MALICIOUS", score: 0.9, threshold: 0.5, mode: "warn" },
      },
    ]);
    const fw = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      mode: "shadow",
    });

    const result = await fw.classify("payload", {
      mode: "block",
      requestId: "req-mode",
    });

    expect(calls[0]!.body).toEqual({
      text: "payload",
      mode: "block",
      metadata: { silmaril: silmarilMetadata("req-mode") },
    });
    expect(result.mode).toBe("block");
  });

  it("rejects an invalid backend effective mode", async () => {
    mockFetch([
      {
        status: 200,
        body: { prediction: "BENIGN", score: 0.1, threshold: 0.5, mode: "enforce" },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    await expect(fw.classify("payload")).rejects.toThrow(
      /response mode must be shadow, warn, or block/,
    );
  });

  it("preserves absence for a backend-controlled mode-less response", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: {
          prediction: "MALICIOUS",
          score: 0.9,
          threshold: 0.5,
          mode: undefined,
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    const result = await fw.classify("payload", { requestId: "req-legacy" });

    expect(calls[0]!.body).not.toHaveProperty("mode");
    expect(result.mode).toBeUndefined();
  });

  it("preserves an explicit Shadow override when a legacy backend omits mode", async () => {
    mockFetch([
      {
        status: 200,
        body: { prediction: "MALICIOUS", score: 0.9, threshold: 0.5 },
      },
    ]);
    const fw = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      shadowMode: true,
    });

    const result = await fw.classify("payload");

    expect(result.mode).toBe("shadow");
  });

  it("does not escalate an explicit Shadow override when a mixed backend reports Block", async () => {
    mockFetch([
      {
        status: 200,
        body: {
          prediction: "MALICIOUS",
          score: 0.9,
          threshold: 0.5,
          mode: "block",
        },
      },
    ]);
    const fw = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      mode: "shadow",
    });

    const result = await fw.classify("payload");

    expect(result.mode).toBe("shadow");
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
        { silmaril: silmarilMetadata("batch-req", 0) },
        { silmaril: silmarilMetadata("batch-req", 1) },
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
        { silmaril: silmarilMetadata("sanitize-req", 0) },
        { silmaril: silmarilMetadata("sanitize-req", 1) },
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

    expect(results[0]).toEqual({
      prediction: "BENIGN",
      score: 0.01,
      threshold: 0.5,
      mode: "block",
    });
    expect(results[1]).toEqual({
      prediction: "MALICIOUS",
      score: 0.9,
      threshold: 0.5,
      mode: "block",
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
      metadata: [{ silmaril: silmarilMetadata("hooks-req", 0) }],
    });
  });

  it("serializes aligned governance context for batch requests", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: {
          predictions: [
            { prediction: "BENIGN", score: 0, governance: { action: "allow", policy_version: "v1" } },
            { prediction: "BENIGN", score: 0, governance: { action: "block", policy_version: "v1" } },
          ],
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const results = await fw.classifyBatch(["a", "b"], {
      governance: [
        { agent: "codex", resource: { kind: "tool", id: "shell" } },
        { agent: "cursor", resource: { kind: "mcp_server", id: "github" } },
      ],
      requestId: "governance-batch",
    });

    expect(calls[0]!.body).toEqual({
      texts: ["a", "b"],
      metadata: [
        {
          silmaril: {
            ...silmarilMetadata("governance-batch", 0),
            governance: { agent: "codex", resource: { kind: "tool", id: "shell" } },
          },
        },
        {
          silmaril: {
            ...silmarilMetadata("governance-batch", 1),
            governance: { agent: "cursor", resource: { kind: "mcp_server", id: "github" } },
          },
        },
      ],
    });
    expect(results.map((result) => result.governance?.action)).toEqual(["allow", "block"]);
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
        { run_id: "run-a", silmaril: silmarilMetadata("metadata-req", 0) },
        { silmaril: silmarilMetadata("metadata-req", 1) },
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
        { silmaril: silmarilMetadata("tools-req", 0) },
        { silmaril: silmarilMetadata("tools-req", 1) },
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

  it("rejects governance length mismatches before sending", async () => {
    const { calls } = mockFetch([{ status: 200, body: { predictions: [] } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(
      fw.classifyBatch(["a", "b"], { governance: [{ agent: "codex" }] }),
    ).rejects.toThrow(/governance length 1 does not match texts length 2/);
    expect(calls).toHaveLength(0);
  });
});

describe("Firewall.classify — complete events", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("sends an event above the former chunk boundary exactly once", async () => {
    const { calls } = mockFetch([
      { status: 200, body: { prediction: "BENIGN", score: 0.2, threshold: 0.75 } },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const longText = "a".repeat(4001);
    const result = await fw.classify(longText, { requestId: "long-event" });

    expect(result).toEqual({
      prediction: "BENIGN",
      score: 0.2,
      threshold: 0.75,
      mode: "block",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.body).toEqual({
      text: longText,
      metadata: { silmaril: silmarilMetadata("long-event") },
    });
  });

  it("preserves exact conversationId and emits no chunk metadata", async () => {
    const { calls } = mockFetch([
      { status: 200, body: { prediction: "BENIGN", score: 0.1 } },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await fw.classify("d".repeat(2000), {
      hook: HookLabel.TOOL_RESPONSE,
      toolName: "search_workspace",
      metadata: { conversationId: "conversation-123", conversation_id: "inert" },
      requestId: "event-uuid",
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.body).toMatchObject({
      hook: "tool_response",
      tool_name: "search_workspace",
      metadata: {
        conversationId: "conversation-123",
        conversation_id: "inert",
        silmaril: silmarilMetadata("event-uuid"),
      },
    });
    expect(JSON.stringify(calls[0]!.body)).not.toContain("chunk_");
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

interface PendingCall {
  readonly body: Record<string, unknown>;
  readonly signal: AbortSignal | undefined;
  settle(status: number, body: unknown): void;
  bodyReleased(): boolean;
}

/**
 * Fetch mock whose responses are settled explicitly, so a test can interleave
 * concurrent calls and complete them out of order. Aborting a request signal
 * rejects that call with the signal's reason, like the platform fetch does.
 */
function controlledFetch(): { calls: PendingCall[] } {
  const calls: PendingCall[] = [];
  const impl = (url: string | URL, init: RequestInit): Promise<Response> => {
    void url;
    let deliver!: (response: Response) => void;
    let fail!: (error: unknown) => void;
    const pending = new Promise<Response>((resolve, reject) => {
      deliver = resolve;
      fail = reject;
    });
    const signal = init.signal ?? undefined;
    let released = false;
    signal?.addEventListener("abort", () => fail(signal.reason), { once: true });
    calls.push({
      body: JSON.parse(init.body as string) as Record<string, unknown>,
      signal,
      settle: (status, body) =>
        deliver(
          controlledResponse(status, withDefaultThresholds(body), () => {
            released = true;
          }),
        ),
      bodyReleased: () => released,
    });
    return pending;
  };
  globalThis.fetch = impl as unknown as typeof fetch;
  return { calls };
}

function controlledResponse(status: number, payload: unknown, onRelease: () => void): Response {
  const text = typeof payload === "string" ? payload : JSON.stringify(payload);
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: `status-${status}`,
    body: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(text));
        controller.close();
      },
      cancel() {
        onRelease();
      },
    }),
    json: async () => (typeof payload === "string" ? JSON.parse(text) : payload),
    text: async () => {
      onRelease();
      return text;
    },
  } as unknown as Response;
}

/**
 * Fetch mock that delivers response headers immediately and leaves the body
 * read pending until the request signal aborts, at which point the read fails
 * with `bodyFailure`. Native fetch surfaces a generic `AbortError` here, which
 * is how a caller's abort reason gets lost during `json()` or an error read.
 */
function pendingBodyFetch(
  status: number,
  bodyFailure: unknown,
): { calls: { signal: AbortSignal }[] } {
  const calls: { signal: AbortSignal }[] = [];
  const impl = (url: string | URL, init: RequestInit): Promise<Response> => {
    void url;
    const signal = init.signal as AbortSignal;
    calls.push({ signal });
    const pendingRead = <T,>(): Promise<T> =>
      new Promise<T>((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(bodyFailure), { once: true });
      });
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      statusText: `status-${status}`,
      json: () => pendingRead<unknown>(),
      text: () => pendingRead<string>(),
    } as unknown as Response);
  };
  globalThis.fetch = impl as unknown as typeof fetch;
  return { calls };
}

function genericAbortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

/** Lets queued microtasks run without advancing wall-clock or fake timers. */
async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await Promise.resolve();
  }
}

describe("Firewall — concurrent reuse", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("resolves overlapping calls with their own out-of-order responses", async () => {
    const { calls } = controlledFetch();
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    const first = fw.classify("first", { requestId: "req-1" });
    const second = fw.classify("second", { requestId: "req-2" });
    const third = fw.classifyBatch(["third-a", "third-b"], { requestId: "req-3" });
    await flush();

    expect(calls).toHaveLength(3);
    calls[2]!.settle(200, {
      predictions: [
        { prediction: "MALICIOUS", score: 0.93 },
        { prediction: "BENIGN", score: 0.03 },
      ],
    });
    calls[1]!.settle(200, { prediction: "MALICIOUS", score: 0.88 });
    calls[0]!.settle(200, { prediction: "BENIGN", score: 0.11 });

    const [firstResult, secondResult, thirdResult] = await Promise.all([first, second, third]);

    expect(firstResult.score).toBe(0.11);
    expect(secondResult.score).toBe(0.88);
    expect(thirdResult.map((result) => result.score)).toEqual([0.93, 0.03]);
  });

  it("keeps per-call modes, metadata, and request IDs isolated on one client", async () => {
    const { calls } = controlledFetch();
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, mode: "block" });

    const shadow = fw.classify("shadow text", {
      mode: "shadow",
      hook: HookLabel.USER_INPUT,
      metadata: { run_id: "run-shadow" },
      requestId: "req-shadow",
    });
    const warn = fw.classify("warn text", {
      mode: "warn",
      toolName: "read_file",
      metadata: { run_id: "run-warn" },
      requestId: "req-warn",
    });
    const inherited = fw.classify("inherited text", { requestId: "req-inherited" });
    await flush();

    expect(calls[0]!.body).toEqual({
      text: "shadow text",
      mode: "shadow",
      hook: "user_input",
      metadata: { run_id: "run-shadow", silmaril: silmarilMetadata("req-shadow") },
    });
    expect(calls[1]!.body).toEqual({
      text: "warn text",
      mode: "warn",
      tool_name: "read_file",
      metadata: { run_id: "run-warn", silmaril: silmarilMetadata("req-warn") },
    });
    expect(calls[2]!.body).toEqual({
      text: "inherited text",
      mode: "block",
      metadata: { silmaril: silmarilMetadata("req-inherited") },
    });

    calls[1]!.settle(200, { prediction: "MALICIOUS", score: 0.7, mode: "warn" });
    calls[0]!.settle(200, { prediction: "MALICIOUS", score: 0.8, mode: "shadow" });
    calls[2]!.settle(200, { prediction: "BENIGN", score: 0.1, mode: "block" });

    expect((await shadow).mode).toBe("shadow");
    expect((await warn).mode).toBe("warn");
    expect((await inherited).mode).toBe("block");

    // The client carries no per-request state, so it stays reusable.
    expect(fw.mode).toBe("block");
    expect(fw.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    const reused = fw.classify("after", { requestId: "req-after" });
    await flush();
    calls[3]!.settle(200, { prediction: "BENIGN", score: 0.02 });
    expect((await reused).score).toBe(0.02);
  });
});

describe("Firewall — cancellation", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("sends no request when the caller signal is already aborted", async () => {
    const { calls } = controlledFetch();
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const reason = new Error("already gone");

    await expect(
      fw.classify("x", { signal: AbortSignal.abort(reason) }),
    ).rejects.toBe(reason);
    await expect(
      fw.classifyBatch(["x"], { signal: AbortSignal.abort(reason) }),
    ).rejects.toBe(reason);
    expect(calls).toHaveLength(0);
  });

  it("aborts an in-flight fetch with the caller reason", async () => {
    const { calls } = controlledFetch();
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const controller = new AbortController();
    const reason = new Error("client disconnected");

    const promise = fw.classify("x", { signal: controller.signal });
    await flush();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.signal?.aborted).toBe(false);

    controller.abort(reason);

    await expect(promise).rejects.toBe(reason);
    expect(calls[0]!.signal?.aborted).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it("uses the platform AbortError when the caller aborts without a reason", async () => {
    controlledFetch();
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const controller = new AbortController();

    const promise = fw.classifyBatch(["x"], { signal: controller.signal });
    await flush();
    controller.abort();

    const error = await promise.catch((e: unknown) => e);
    expect((error as Error).name).toBe("AbortError");
  });

  it("aborts during the 429 retry wait without sending another request", async () => {
    vi.useFakeTimers();
    try {
      const { calls } = controlledFetch();
      const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
      const controller = new AbortController();
      const reason = new Error("cancelled during backoff");

      const promise = fw.classify("x", { signal: controller.signal });
      promise.catch(() => {
        // Keep the unhandled-rejection handler quiet while we drive timers.
      });
      await vi.advanceTimersByTimeAsync(0);
      expect(calls).toHaveLength(1);

      calls[0]!.settle(429, "rate limited");
      await vi.advanceTimersByTimeAsync(0);
      // The retried response is released before the SDK starts waiting.
      expect(calls[0]!.bodyReleased()).toBe(true);

      controller.abort(reason);

      await expect(promise).rejects.toBe(reason);
      expect(calls).toHaveLength(1);
      // Both the backoff timer and the attempt timeout timer are cleared.
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("discards a retried 429 body before backing off and then succeeds", async () => {
    vi.useFakeTimers();
    try {
      const { calls } = controlledFetch();
      const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

      const promise = fw.classify("x", { requestId: "req-retry" });
      await vi.advanceTimersByTimeAsync(0);
      calls[0]!.settle(429, "rate limited");
      await vi.advanceTimersByTimeAsync(0);

      expect(calls[0]!.bodyReleased()).toBe(true);
      expect(calls).toHaveLength(1);

      await vi.advanceTimersByTimeAsync(1_000);
      expect(calls).toHaveLength(2);
      calls[1]!.settle(200, { prediction: "BENIGN", score: 0.05 });

      await expect(promise).resolves.toMatchObject({ score: 0.05 });
    } finally {
      vi.useRealTimers();
    }
  });

  it("resends the payload captured at call time after a 429", async () => {
    vi.useFakeTimers();
    try {
      const { calls } = controlledFetch();
      const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
      // Nested caller objects are shared by reference with the request
      // payload, so only serializing once keeps them out of later attempts.
      const nested: Record<string, unknown> = { run_id: "run-original" };
      const metadata: Record<string, unknown> = { langgraph: nested };

      const promise = fw.classify("x", { metadata, requestId: "req-frozen" });
      await vi.advanceTimersByTimeAsync(0);
      calls[0]!.settle(429, "rate limited");

      // A caller that mutates its own objects mid-flight must not change the
      // logical event the SDK already accepted.
      nested.run_id = "run-mutated";
      nested.injected = true;
      metadata.extra = "late";

      await vi.advanceTimersByTimeAsync(1_000);
      calls[1]!.settle(200, { prediction: "BENIGN", score: 0.04 });
      await promise;

      expect(calls[1]!.body).toEqual(calls[0]!.body);
      expect(calls[1]!.body).toEqual({
        text: "x",
        metadata: {
          langgraph: { run_id: "run-original" },
          silmaril: silmarilMetadata("req-frozen"),
        },
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("leaves sibling calls unaffected when one call is aborted", async () => {
    const { calls } = controlledFetch();
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const controller = new AbortController();
    const shared = new AbortController();

    const cancelled = fw.classify("cancelled", { signal: controller.signal });
    const survivor = fw.classify("survivor", { signal: shared.signal });
    const unsignalled = fw.classify("unsignalled");
    await flush();
    expect(calls).toHaveLength(3);

    controller.abort(new Error("only this one"));
    await expect(cancelled).rejects.toThrow(/only this one/);

    expect(calls[1]!.signal?.aborted).toBe(false);
    expect(calls[2]!.signal?.aborted).toBe(false);
    calls[1]!.settle(200, { prediction: "BENIGN", score: 0.21 });
    calls[2]!.settle(200, { prediction: "MALICIOUS", score: 0.99 });

    expect((await survivor).score).toBe(0.21);
    expect((await unsignalled).score).toBe(0.99);
    expect(shared.signal.aborted).toBe(false);
  });

  it("still enforces the per-attempt timeout when a caller signal is supplied", async () => {
    const { calls } = controlledFetch();
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, timeoutMs: 5 });
    const controller = new AbortController();

    const error = await fw
      .classify("x", { signal: controller.signal })
      .catch((e: unknown) => e);

    expect((error as Error).name).toBe("TimeoutError");
    expect(calls).toHaveLength(1);
    // The timeout is per attempt and must not abort the caller's own signal.
    expect(controller.signal.aborted).toBe(false);
  });

  it("keeps the caller reason when the abort lands during the JSON body read", async () => {
    const { calls } = pendingBodyFetch(200, genericAbortError());
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const controller = new AbortController();
    const reason = new Error("client disconnected mid-body");

    const promise = fw.classify("x", { signal: controller.signal });
    await flush();
    expect(calls).toHaveLength(1);

    controller.abort(reason);

    await expect(promise).rejects.toBe(reason);
  });

  it("keeps the caller reason when the abort lands during the error-body read", async () => {
    const { calls } = pendingBodyFetch(500, genericAbortError());
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const controller = new AbortController();
    const reason = new Error("client disconnected mid-error-body");

    const promise = fw.classifyBatch(["x"], { signal: controller.signal });
    await flush();
    expect(calls).toHaveLength(1);

    controller.abort(reason);

    const error = await promise.catch((e: unknown) => e);
    expect(error).toBe(reason);
    expect(error).not.toBeInstanceOf(SilmarilApiError);
  });

  it("keeps the timeout reason when the attempt times out during the body read", async () => {
    pendingBodyFetch(200, genericAbortError());
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, timeoutMs: 5 });

    const error = await fw.classify("x").catch((e: unknown) => e);

    expect((error as Error).name).toBe("TimeoutError");
    expect((error as Error).message).toMatch(/timeout/i);
  });

  it("leaves a decode failure unchanged when the caller has aborted", async () => {
    pendingBodyFetch(200, new SyntaxError("unexpected token"));
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const controller = new AbortController();

    const promise = fw.classify("x", { signal: controller.signal });
    await flush();
    controller.abort(new Error("caller reason"));

    const error = await promise.catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SyntaxError);
    expect((error as Error).message).toBe("unexpected token");
  });

  it("rejects with the cancellation reason instead of a serialization failure", async () => {
    const { calls } = controlledFetch();
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const cyclic: Record<string, unknown> = { run_id: "run-cyclic" };
    cyclic.self = cyclic;
    const reason = new Error("cancelled before serialization");

    await expect(
      fw.classify("x", { metadata: cyclic, signal: AbortSignal.abort(reason) }),
    ).rejects.toBe(reason);
    expect(calls).toHaveLength(0);

    // Without cancellation the serialization failure still surfaces.
    await expect(fw.classify("x", { metadata: cyclic })).rejects.toBeInstanceOf(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("does not leak abort listeners onto a reused caller signal", async () => {
    const { calls } = controlledFetch();
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const controller = new AbortController();
    const added: string[] = [];
    const removed: string[] = [];
    const signal = controller.signal;
    const realAdd = signal.addEventListener.bind(signal);
    const realRemove = signal.removeEventListener.bind(signal);
    signal.addEventListener = ((type: string, ...rest: unknown[]) => {
      added.push(type);
      return (realAdd as (...args: unknown[]) => void)(type, ...rest);
    }) as typeof signal.addEventListener;
    signal.removeEventListener = ((type: string, ...rest: unknown[]) => {
      removed.push(type);
      return (realRemove as (...args: unknown[]) => void)(type, ...rest);
    }) as typeof signal.removeEventListener;

    for (let i = 0; i < 3; i++) {
      const promise = fw.classify(`x-${i}`, { signal });
      await flush();
      calls[i]!.settle(200, { prediction: "BENIGN", score: 0.01 });
      await promise;
    }

    expect(added.filter((type) => type === "abort")).toHaveLength(3);
    expect(removed.filter((type) => type === "abort")).toHaveLength(3);
  });
});
