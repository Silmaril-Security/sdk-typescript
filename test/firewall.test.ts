// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { Socket } from "node:net";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_TIMEOUT_MS,
  Firewall,
  FirewallBlockedException,
  HookLabel,
  SilmarilApiError,
} from "../src/index.js";
import { SDK_VERSION } from "../src/firewall.js";
import { allowed, blocked, decisions } from "./wire.js";

const TEST_API_URL = "https://api.test.invalid/classify";
const VERSION_2_URL = "https://api.test.invalid/v2/classify";
const ERROR_BODY_CAP = 1 << 16;
const NATIVE_FETCH = globalThis.fetch;

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
    const body = r.body;
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

function silmarilMetadata(requestId: string, inputIndex?: number): Record<string, unknown> {
  return {
    sdk_language: "typescript",
    sdk_version: SDK_VERSION,
    request_id: requestId,
    ...(inputIndex === undefined ? {} : { input_index: inputIndex }),
  };
}

async function listenOnLoopback(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      reject(error);
    };
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", onError);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Expected a loopback TCP address");
  }
  return `http://127.0.0.1:${address.port}`;
}

function trackServerSockets(server: Server): Set<Socket> {
  const sockets = new Set<Socket>();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  return sockets;
}

async function closeLoopbackServer(server: Server, sockets: Set<Socket>): Promise<void> {
  const closed = server.listening
    ? new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      })
    : Promise.resolve();
  server.closeAllConnections();
  for (const socket of sockets) {
    socket.destroy();
  }
  await closed;
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

describe("Firewall decision parsing", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each([
    { reason: "a missing action", item: '{"source":null}' },
    { reason: "a null action", item: '{"action":null}' },
    { reason: "a numeric action", item: '{"action":1}' },
    { reason: "a boolean action", item: '{"action":true}' },
    { reason: "a null result", item: "null" },
    { reason: "a string result", item: '"allow"' },
  ])("rejects $reason in single and batch responses", async ({ item }) => {
    const fetchDecision = vi.fn(async () => new Response(`{"results":[${item}]}`));
    vi.stubGlobal("fetch", fetchDecision);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const error = "response result action must be a string";

    await expect(fw.classify("hello")).rejects.toThrow(error);
    await expect(fw.classifyBatch(["hello"])).rejects.toThrow(error);
    expect(fetchDecision).toHaveBeenCalledTimes(2);
  });

  it.each([
    { reason: "null", body: '{"results":null}' },
    { reason: "an object", body: '{"results":{"action":"allow"}}' },
    { reason: "a string", body: '{"results":"allow"}' },
    {
      reason: "null beside a version 1 verdict",
      body: '{"results":null,"prediction":"BENIGN","score":0,"threshold":0.5}',
    },
  ])("rejects results when $reason", async ({ body }) => {
    const fetchDecision = vi.fn(async () => new Response(body));
    vi.stubGlobal("fetch", fetchDecision);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    await expect(fw.classify("hello")).rejects.toThrow("response results must be an array");
    await expect(fw.classifyBatch(["hello"])).rejects.toThrow("response results must be an array");
    expect(fetchDecision).toHaveBeenCalledTimes(2);
  });

  it.each([
    { reason: "an empty object", body: "{}", error: "response prediction must be BENIGN or MALICIOUS" },
    {
      reason: "an error detail",
      body: '{"detail":"unavailable"}',
      error: "response prediction must be BENIGN or MALICIOUS",
    },
    {
      reason: "a bare decision",
      body: '{"action":"allow"}',
      error: "response prediction must be BENIGN or MALICIOUS",
    },
    { reason: "an array", body: '[{"action":"allow"}]', error: "response prediction must be an object" },
    { reason: "a string", body: '"allow"', error: "response prediction must be an object" },
    { reason: "null", body: "null", error: "response prediction must be an object" },
    { reason: "null predictions", body: '{"predictions":null}', error: "response predictions must be an array" },
  ])("rejects a body that is neither version: $reason", async ({ body, error }) => {
    const fetchDecision = vi.fn(async (_url: string | URL) => new Response(body));
    vi.stubGlobal("fetch", fetchDecision);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const operation = vi.fn(async () => "answer");

    await expect(fw.classify("hello")).rejects.toThrow(error);
    await expect(fw.classifyBatch(["hello"])).rejects.toThrow(error);
    await expect(fw.protect(operation, { text: "hello" })).rejects.toThrow(error);
    expect(fetchDecision.mock.calls.map(([url]) => String(url))).toEqual([
      VERSION_2_URL,
      VERSION_2_URL,
      VERSION_2_URL,
    ]);
  });

  it.each([0, 2])("rejects %d results for a single classification", async (count) => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(
      decisions(...Array.from({ length: count }, () => allowed())),
    ))));
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    await expect(fw.classify("hello")).rejects.toThrow(
      `response results length ${count} does not match submitted texts length 1`,
    );
  });

  it("surfaces every decision field and ignores unknown fields", async () => {
    const body = {
      ...decisions({
        ...blocked({
          confidence: "high",
          severity: "moderate",
          outcome: "control_abuse",
          model_id: "silmaril-cascade-1-6",
        }),
        score: 0.99,
        prediction: "BENIGN",
        mode: "shadow",
        assessment: { summary: "ignored" },
      }),
      model_id: "ignored",
    };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(body))));
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const result = {
      action: "block",
      source: "model",
      confidence: "high",
      severity: "moderate",
      outcome: "control_abuse",
      modelId: "silmaril-cascade-1-6",
    };

    await expect(fw.classify("hello")).resolves.toEqual(result);
    await expect(fw.classifyBatch(["hello"])).resolves.toEqual([result]);
  });

  it.each([
    { reason: "a model identifier", model_id: "silmaril-cascade-1-6", provenance: { modelId: "silmaril-cascade-1-6" } },
    { reason: "a null model identifier", model_id: null, provenance: {} },
    { reason: "a non-string model identifier", model_id: 16, provenance: {} },
  ])("reports $reason as provenance without changing enforcement", async ({ model_id, provenance }) => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(decisions(
      allowed({ model_id }),
      blocked({ model_id }),
    )))));
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    await expect(fw.classifyBatch(["first", "second"])).resolves.toEqual([
      { action: "allow", ...provenance },
      { action: "block", source: "model", ...provenance },
    ]);
  });

  it("surfaces unfamiliar evidence values without changing enforcement", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(decisions(
      allowed({ source: "reviewer", confidence: "certain", severity: "extreme", outcome: "data_exfiltration" }),
      blocked({ source: 7, confidence: {}, severity: [], outcome: false }),
    )))));
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    await expect(fw.classifyBatch(["first", "second"])).resolves.toEqual([
      {
        action: "allow",
        source: "reviewer",
        confidence: "certain",
        severity: "extreme",
        outcome: "data_exfiltration",
      },
      { action: "block" },
    ]);
  });

  it.each(["block", "quarantine", "ALLOW", ""])("blocks on action %j", async (action) => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(decisions({ action })))));
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const operation = vi.fn(async () => "answer");

    await expect(fw.classify("hello")).resolves.toEqual({ action: "block" });
    await expect(fw.protect(operation, { text: "hello" })).rejects.toBeInstanceOf(
      FirewallBlockedException,
    );
  });

  it("returns frozen results", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(decisions(allowed())))));
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    expect(Object.isFrozen(await fw.classify("hello"))).toBe(true);
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
    const { calls } = mockFetch([{ status: 200, body: decisions(allowed()) }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const result = await fw.classify("hello world", { requestId: "req-single" });
    expect(result).toEqual({ action: "allow" });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(VERSION_2_URL);
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

  it("includes hook and tool_name wire keys when provided", async () => {
    const { calls } = mockFetch([{ status: 200, body: decisions(blocked()) }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const result = await fw.classify("suspicious email body", {
      hook: HookLabel.TOOL_RESPONSE,
      toolName: "read_email",
      requestId: "req-hook",
    });
    expect(result.action).toBe("block");
    expect(calls[0]!.body).toEqual({
      text: "suspicious email body",
      hook: "tool_response",
      tool_name: "read_email",
      metadata: { silmaril: silmarilMetadata("req-hook") },
    });
  });

  it("serializes governance resources for the runtime and preserves attribution metadata", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: decisions(blocked({
          source: "governance",
          governance: {
            action: "block",
            rule_id: "block-unapproved-mcp",
            policy_version: "pwc-v1",
          },
        })),
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
      resource: { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
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
    expect(result).toEqual({
      action: "block",
      source: "governance",
      governance: {
        action: "block",
        ruleId: "block-unapproved-mcp",
        policyVersion: "pwc-v1",
      },
    });
  });

  it("accepts responses without governance and rejects malformed decisions", async () => {
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    mockFetch([{ status: 200, body: decisions(allowed()) }]);
    await expect(fw.classify("ungoverned")).resolves.not.toHaveProperty("governance");

    mockFetch([
      {
        status: 200,
        body: decisions(allowed({ governance: { action: "warn", policy_version: "v1" } })),
      },
    ]);
    await expect(fw.classify("invalid")).rejects.toThrow(
      /governance action must be allow or block/,
    );
  });

  it("includes metadata as a separate wire key when provided", async () => {
    const { calls } = mockFetch([{ status: 200, body: decisions(allowed()) }]);
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

  it("reports the requested mode and no mode when none is requested", async () => {
    const { calls } = mockFetch([{ status: 200, body: decisions(blocked()) }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, mode: "shadow" });

    const overridden = await fw.classify("payload", { mode: "block", requestId: "req-mode" });
    const inherited = await fw.classify("payload");
    const unset = await new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL })
      .classify("payload", { requestId: "req-unset" });

    expect(calls[0]!.body).toEqual({
      text: "payload",
      mode: "block",
      metadata: { silmaril: silmarilMetadata("req-mode") },
    });
    expect(overridden.mode).toBe("block");
    expect(inherited.mode).toBe("shadow");
    expect(calls[2]!.body).not.toHaveProperty("mode");
    expect(unset).not.toHaveProperty("mode");
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
        { status: 200, body: decisions(allowed()) },
      ]);
      const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
      const promise = fw.classify("x");
      // Advance through the backoff waits: 2^0=1s, 2^1=2s.
      await vi.advanceTimersByTimeAsync(1_000);
      await vi.advanceTimersByTimeAsync(2_000);
      const result = await promise;
      expect(result.action).toBe("allow");
      expect(calls).toHaveLength(3);
      expect(new Set(calls.map((call) => call.url))).toEqual(new Set([VERSION_2_URL]));
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
        body: decisions(allowed(), blocked({ outcome: "secret_exposure" })),
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const results = await fw.classifyBatch(["a", "b"], { requestId: "batch-req" });
    expect(results).toEqual([
      { action: "allow" },
      { action: "block", source: "model", outcome: "secret_exposure" },
    ]);
    expect(calls[0]!.url).toBe(VERSION_2_URL);
    expect(calls[0]!.body).toEqual({
      texts: ["a", "b"],
      metadata: [
        { silmaril: silmarilMetadata("batch-req", 0) },
        { silmaril: silmarilMetadata("batch-req", 1) },
      ],
    });
  });

  it.each([
    { description: "zero", results: [] },
    { description: "one", results: [allowed()] },
  ])("rejects too few results ($description)", async ({ results }) => {
    const { calls } = mockFetch([{ status: 200, body: { results } }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    await expect(fw.classifyBatch(["a", "b"])).rejects.toThrow(
      new RegExp(
        `response results length ${results.length} does not match submitted texts length 2`,
      ),
    );
    expect(calls).toHaveLength(1);
  });

  it("rejects too many results", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: {
          results: [
            allowed(),
            blocked(),
            allowed(),
          ],
        },
      },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    await expect(fw.classifyBatch(["a", "b"])).rejects.toThrow(
      /response results length 3 does not match submitted texts length 2/,
    );
    expect(calls).toHaveLength(1);
  });

  it("validates response cardinality against the submitted snapshot", async () => {
    const { calls } = controlledFetch();
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const texts = ["a", "b"];

    const promise = fw.classifyBatch(texts, { requestId: "snapshot-req" });
    await flush();
    expect(calls[0]!.body.texts).toEqual(["a", "b"]);

    texts.pop();
    calls[0]!.settle(200, decisions(allowed(), blocked()));

    await expect(promise).resolves.toHaveLength(2);
  });

  it("sanitizes lone surrogates before sending batch payloads", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: {
          results: [
            allowed(),
            allowed(),
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

  it("serializes hooks and tool_names when provided", async () => {
    const { calls } = mockFetch([
      { status: 200, body: { results: [allowed()] } },
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
          results: [
            allowed({ governance: { action: "allow", policy_version: "v1" } }),
            blocked({ source: "governance", governance: { action: "block", policy_version: "v1" } }),
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
      resources: [{ kind: "tool", id: "shell" }, { kind: "mcp_server", id: "github" }],
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
    expect(results).toEqual([
      { action: "allow", governance: { action: "allow", policyVersion: "v1" } },
      { action: "block", source: "governance", governance: { action: "block", policyVersion: "v1" } },
    ]);
  });

  it("serializes metadata when provided", async () => {
    const { calls } = mockFetch([
      {
        status: 200,
        body: {
          results: [
            allowed(),
            allowed(),
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
        body: { results: [allowed(), allowed()] },
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
          results: Array.from({ length: 5 }, () => allowed()),
        },
      },
      {
        status: 200,
        body: {
          results: Array.from({ length: 10 }, () => allowed()),
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
    const { calls } = mockFetch([{ status: 200, body: decisions() }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(fw.classifyBatch([])).rejects.toThrow(/texts must not be empty/);
    expect(calls).toHaveLength(0);
  });

  it("rejects hooks length mismatches before sending", async () => {
    const { calls } = mockFetch([{ status: 200, body: decisions() }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(
      fw.classifyBatch(["a", "b"], { hooks: [HookLabel.USER_INPUT] }),
    ).rejects.toThrow(/hooks length 1 does not match texts length 2/);
    expect(calls).toHaveLength(0);
  });

  it("rejects metadata length mismatches before sending", async () => {
    const { calls } = mockFetch([{ status: 200, body: decisions() }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(fw.classifyBatch(["a", "b"], { metadata: [{ run_id: "run-a" }] })).rejects.toThrow(
      /metadata length 1 does not match texts length 2/,
    );
    expect(calls).toHaveLength(0);
  });

  it("rejects toolNames length mismatches before sending", async () => {
    const { calls } = mockFetch([{ status: 200, body: decisions() }]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    await expect(fw.classifyBatch(["a", "b"], { toolNames: ["read_file"] })).rejects.toThrow(
      /toolNames length 1 does not match texts length 2/,
    );
    expect(calls).toHaveLength(0);
  });

  it("rejects governance length mismatches before sending", async () => {
    const { calls } = mockFetch([{ status: 200, body: decisions() }]);
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
      { status: 200, body: decisions(allowed()) },
    ]);
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    const longText = "a".repeat(4001);
    const result = await fw.classify(longText, { requestId: "long-event" });

    expect(result).toEqual({ action: "allow" });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.body).toEqual({
      text: longText,
      metadata: { silmaril: silmarilMetadata("long-event") },
    });
  });

  it("preserves exact conversationId and emits no chunk metadata", async () => {
    const { calls } = mockFetch([
      { status: 200, body: decisions(allowed()) },
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

  it("propagates fetch redirect rejections unchanged", async () => {
    const redirectError = new TypeError("fetch failed");
    globalThis.fetch = (async () => {
      throw redirectError;
    }) as unknown as typeof fetch;
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    let caught: unknown;
    try {
      await fw.classify("x");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBe(redirectError);
    expect(caught).toBeInstanceOf(TypeError);
  });

  it("native fetch refuses redirects without forwarding credentials or payload", async () => {
    interface ReceivedRequest {
      apiKey: string | string[] | undefined;
      body: string;
    }

    const sourceRequests: ReceivedRequest[] = [];
    const targetRequests: ReceivedRequest[] = [];
    let targetUrl = "";
    const target = createServer((request, response) => {
      let body = "";
      request.setEncoding("utf8");
      request.on("data", (chunk: string) => {
        body += chunk;
      });
      request.on("end", () => {
        targetRequests.push({
          apiKey: request.headers["x-api-key"],
          body,
        });
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify(decisions(allowed())));
      });
    });
    const source = createServer((request, response) => {
      let body = "";
      request.setEncoding("utf8");
      request.on("data", (chunk: string) => {
        body += chunk;
      });
      request.on("end", () => {
        sourceRequests.push({
          apiKey: request.headers["x-api-key"],
          body,
        });
        response.writeHead(302, { location: `${targetUrl}/classify` });
        response.end("redirect");
      });
    });
    const sourceSockets = trackServerSockets(source);
    const targetSockets = trackServerSockets(target);

    try {
      targetUrl = await listenOnLoopback(target);
      const sourceUrl = await listenOnLoopback(source);
      globalThis.fetch = NATIVE_FETCH;
      const fw = new Firewall({
        apiKey: "sk-redirect-test-only",
        apiUrl: `${sourceUrl}/classify`,
      });

      await expect(
        fw.classify("redirect probe", { requestId: "req-redirect-loopback" }),
      ).rejects.toBeInstanceOf(TypeError);

      expect(sourceRequests).toHaveLength(1);
      expect(sourceRequests[0]!.apiKey).toBe("sk-redirect-test-only");
      expect(JSON.parse(sourceRequests[0]!.body)).toMatchObject({
        text: "redirect probe",
        metadata: {
          silmaril: {
            request_id: "req-redirect-loopback",
          },
        },
      });
      expect(targetRequests).toEqual([]);
    } finally {
      await Promise.all([
        closeLoopbackServer(source, sourceSockets),
        closeLoopbackServer(target, targetSockets),
      ]);
    }
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
          controlledResponse(status, body, () => {
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
    calls[2]!.settle(200, decisions(blocked({ outcome: "third-a" }), allowed({ outcome: "third-b" })));
    calls[1]!.settle(200, decisions(blocked({ outcome: "second" })));
    calls[0]!.settle(200, decisions(allowed({ outcome: "first" })));

    const [firstResult, secondResult, thirdResult] = await Promise.all([first, second, third]);

    expect(firstResult.outcome).toBe("first");
    expect(secondResult.outcome).toBe("second");
    expect(thirdResult.map((result) => result.outcome)).toEqual(["third-a", "third-b"]);
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

    calls[1]!.settle(200, decisions(blocked()));
    calls[0]!.settle(200, decisions(blocked()));
    calls[2]!.settle(200, decisions(allowed()));

    expect((await shadow).mode).toBe("shadow");
    expect((await warn).mode).toBe("warn");
    expect((await inherited).mode).toBe("block");

    // The client carries no per-request state, so it stays reusable.
    expect(fw.mode).toBe("block");
    expect(fw.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    const reused = fw.classify("after", { requestId: "req-after" });
    await flush();
    calls[3]!.settle(200, decisions(allowed({ outcome: "after" })));
    expect((await reused).outcome).toBe("after");
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

  it.each(["caller", "attempt"] as const)("releases stalled retry cleanup on %s cancellation", async (kind) => {
    vi.useFakeTimers();
    let finishCleanup!: () => void;
    const cleanup = new Promise<void>((resolve) => { finishCleanup = resolve; });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response("throttled", { status: 429 }))
      .mockResolvedValueOnce(new Response(new ReadableStream({ cancel: () => cleanup }), { status: 429 }));
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();
    const reason = new Error("caller deadline");
    const fw = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL, timeoutMs: 8000 });
    const pending = fw.classify("x", { signal: controller.signal });
    pending.catch(() => {});
    try {
      await vi.advanceTimersByTimeAsync(1000);
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(vi.getTimerCount()).toBe(1);
      if (kind === "caller") {
        controller.abort(reason);
        await expect(pending).rejects.toBe(reason);
      } else {
        await vi.advanceTimersByTimeAsync(8000);
        await expect(pending).rejects.toMatchObject({ name: "TimeoutError" });
        expect(controller.signal.aborted).toBe(false);
      }
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      finishCleanup();
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
      calls[1]!.settle(200, decisions(allowed()));

      await expect(promise).resolves.toEqual({ action: "allow" });
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
      calls[1]!.settle(200, decisions(allowed()));
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
    calls[1]!.settle(200, decisions(allowed()));
    calls[2]!.settle(200, decisions(blocked()));

    expect((await survivor).action).toBe("allow");
    expect((await unsignalled).action).toBe("block");
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
      calls[i]!.settle(200, decisions(allowed()));
      await promise;
    }

    expect(added.filter((type) => type === "abort")).toHaveLength(3);
    expect(removed.filter((type) => type === "abort")).toHaveLength(3);
  });
});
