// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  Firewall,
  FirewallBlockedException,
  ReviewCompatibilityError,
  SilmarilApiError,
  type BlockResult,
  type ClassifyOptions,
} from "../src/index.js";
import { createLangChainHandler } from "../src/adapters/langchain.js";
import { allowed, blocked, decisions } from "./wire.js";

const BASE_URL = "https://api.test.invalid";
const VERSION_1_URL = `${BASE_URL}/classify`;
const VERSION_2_URL = `${BASE_URL}/v2/classify`;
const VERSION_1_ALLOW = { prediction: "BENIGN", score: 0.1, threshold: 0.5, outcome_scores: {} };
const VERSION_1_BLOCK = {
  prediction: "MALICIOUS",
  score: 0.9,
  threshold: 0.5,
  primary_outcome: "secret_exposure",
  outcome_scores: { secret_exposure: 0.75 },
};
const ADAPTED_BLOCK = { action: "block", source: "model", outcome: "secret_exposure" };

interface RuntimeCall {
  readonly url: string;
  readonly body: string;
  readonly headers: unknown;
}

interface RuntimeReply {
  readonly status: number;
  readonly body: unknown;
}

function runtime(...replies: readonly RuntimeReply[]): RuntimeCall[] {
  const calls: RuntimeCall[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string | URL, init: RequestInit) => {
    const reply = replies[Math.min(calls.length, replies.length - 1)]!;
    calls.push({ url: String(url), body: init.body as string, headers: init.headers });
    return new Response(JSON.stringify(reply.body), { status: reply.status });
  }));
  return calls;
}

function firewall(apiUrl = VERSION_1_URL): Firewall {
  return new Firewall({ apiKey: "sk-test", apiUrl });
}

type SharedOptions = Pick<ClassifyOptions, "mode" | "review">;

const METHODS = [
  {
    method: "classify",
    classify: (fw: Firewall, options: SharedOptions = {}): Promise<BlockResult> =>
      fw.classify("event", options),
    version1: (prediction: unknown): unknown => prediction,
  },
  {
    method: "classifyBatch",
    classify: (fw: Firewall, options: SharedOptions = {}): Promise<BlockResult> =>
      fw.classifyBatch(["event"], options).then((results) => results[0]!),
    version1: (prediction: unknown): unknown => ({ predictions: [prediction] }),
  },
] as const;

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("classify endpoint derivation", () => {
  it.each([
    { apiUrl: BASE_URL, base: BASE_URL, query: "" },
    { apiUrl: `${BASE_URL}/`, base: BASE_URL, query: "" },
    { apiUrl: `${BASE_URL}/classify`, base: BASE_URL, query: "" },
    { apiUrl: `${BASE_URL}/classify/`, base: BASE_URL, query: "" },
    { apiUrl: `${BASE_URL}/v2/classify`, base: BASE_URL, query: "" },
    { apiUrl: `${BASE_URL}/v2/classify/`, base: BASE_URL, query: "" },
    { apiUrl: `${BASE_URL}/alpha`, base: `${BASE_URL}/alpha`, query: "" },
    { apiUrl: `${BASE_URL}/alpha/`, base: `${BASE_URL}/alpha`, query: "" },
    { apiUrl: `${BASE_URL}/alpha/classify`, base: `${BASE_URL}/alpha`, query: "" },
    { apiUrl: `${BASE_URL}/alpha/v2/classify`, base: `${BASE_URL}/alpha`, query: "" },
    { apiUrl: `${BASE_URL}/v2`, base: `${BASE_URL}/v2`, query: "" },
    { apiUrl: `${BASE_URL}/reclassify`, base: `${BASE_URL}/reclassify`, query: "" },
    { apiUrl: `${BASE_URL}?stage=canary`, base: BASE_URL, query: "?stage=canary" },
    { apiUrl: `${BASE_URL}/classify?stage=canary&trace=1`, base: BASE_URL, query: "?stage=canary&trace=1" },
    { apiUrl: `${BASE_URL}/alpha/v2/classify/?stage=canary`, base: `${BASE_URL}/alpha`, query: "?stage=canary" },
    { apiUrl: "http://127.0.0.1:8080/classify", base: "http://127.0.0.1:8080", query: "" },
  ])("derives both endpoints from $apiUrl", async ({ apiUrl, base, query }) => {
    const calls = runtime({ status: 404, body: {} }, { status: 200, body: VERSION_1_ALLOW });
    const fw = firewall(apiUrl);

    await fw.classify("event");

    expect(fw.apiUrl).toBe(apiUrl);
    expect(calls.map((call) => call.url)).toEqual([
      `${base}/v2/classify${query}`,
      `${base}/classify${query}`,
    ]);
  });
});

describe.each(METHODS)("version 1 fallback through $method", ({ classify, version1 }) => {
  it("uses only /v2/classify when it answers", async () => {
    const calls = runtime({ status: 200, body: decisions(blocked({ confidence: "high", severity: "critical" })) });
    const fw = firewall();

    await expect(classify(fw)).resolves.toEqual({
      action: "block",
      source: "model",
      confidence: "high",
      severity: "critical",
    });
    await classify(fw);
    expect(calls.map((call) => call.url)).toEqual([VERSION_2_URL, VERSION_2_URL]);
  });

  it.each([403, 404, 405])("falls back to /classify on %d and adapts its verdict", async (status) => {
    const calls = runtime(
      { status, body: { message: "Missing Authentication Token" } },
      { status: 200, body: version1(VERSION_1_BLOCK) },
    );

    await expect(classify(firewall())).resolves.toEqual(ADAPTED_BLOCK);
    expect(calls.map((call) => call.url)).toEqual([VERSION_2_URL, VERSION_1_URL]);
    expect(calls[1]!.body).toBe(calls[0]!.body);
    expect(calls[1]!.headers).toBe(calls[0]!.headers);
  });

  it.each([400, 401, 409, 422, 500, 502, 503])("does not fall back on %d", async (status) => {
    const calls = runtime({ status, body: { detail: "rejected" } });

    await expect(classify(firewall())).rejects.toMatchObject({ name: "SilmarilApiError", status });
    expect(calls.map((call) => call.url)).toEqual([VERSION_2_URL]);
  });

  it("does not fall back when /v2/classify stays rate limited", async () => {
    vi.useFakeTimers();
    const calls = runtime({ status: 429, body: "rate limited" });
    const pending = classify(firewall());
    pending.catch(() => undefined);

    await vi.advanceTimersByTimeAsync(100_000);

    await expect(pending).rejects.toMatchObject({ name: "SilmarilApiError", status: 429 });
    expect(new Set(calls.map((call) => call.url))).toEqual(new Set([VERSION_2_URL]));
  });

  it.each([
    { verdict: "block", prediction: { ...VERSION_1_BLOCK, model_id: "silmaril-cascade-1-6" } },
    { verdict: "allow", prediction: { ...VERSION_1_ALLOW, model_id: "silmaril-cascade-1-6" } },
    {
      verdict: "governance block",
      prediction: {
        ...VERSION_1_ALLOW,
        prediction: "MALICIOUS",
        model_prediction: "BENIGN",
        mode: "block",
        governance: { action: "block", rule_id: "block-shell", policy_version: "policy-9" },
      },
    },
    { verdict: "warn-mode block", prediction: { ...VERSION_1_BLOCK, mode: "warn" } },
  ])("adapts a version 1 $verdict answered by /v2/classify as it does through fallback", async ({ prediction }) => {
    const calls = runtime(
      { status: 200, body: version1(prediction) },
      { status: 404, body: {} },
      { status: 200, body: version1(prediction) },
      { status: 200, body: version1(prediction) },
    );
    const routed = firewall();

    const answered = await classify(routed);
    const fallenBack = await classify(firewall());
    await classify(routed);

    expect(answered).toStrictEqual(fallenBack);
    expect(calls.map((call) => call.url)).toEqual([
      VERSION_2_URL,
      VERSION_2_URL,
      VERSION_1_URL,
      VERSION_2_URL,
    ]);
  });

  it("enforces a version 1 block answered by /v2/classify", async () => {
    const calls = runtime({ status: 200, body: version1(VERSION_1_BLOCK) }, { status: 200, body: VERSION_1_BLOCK });
    const fw = firewall();
    const operation = vi.fn(async () => "answer");
    const handler = await createLangChainHandler(fw);

    await expect(classify(fw)).resolves.toEqual(ADAPTED_BLOCK);
    const blockedOperation = await fw.protect(operation, { text: "event" }).catch((caught: unknown) => caught);

    expect(blockedOperation).toBeInstanceOf(FirewallBlockedException);
    expect(blockedOperation).toMatchObject({ result: ADAPTED_BLOCK });
    await expect(handler.handleLLMStart?.({} as never, ["event"], "run-version-1")).rejects.toBeInstanceOf(
      FirewallBlockedException,
    );
    expect(new Set(calls.map((call) => call.url))).toEqual(new Set([VERSION_2_URL]));
  });

  it("rejects a body from /v2/classify that is neither version without falling back", async () => {
    const calls = runtime({ status: 200, body: { detail: "unavailable" } });

    await expect(classify(firewall())).rejects.toThrow("response prediction must be BENIGN or MALICIOUS");
    expect(calls.map((call) => call.url)).toEqual([VERSION_2_URL]);
  });

  it("remembers a successful fallback for later single and batch calls", async () => {
    const calls = runtime(
      { status: 404, body: {} },
      { status: 200, body: version1(VERSION_1_ALLOW) },
      { status: 200, body: VERSION_1_BLOCK },
      { status: 200, body: { predictions: [VERSION_1_ALLOW, VERSION_1_BLOCK] } },
    );
    const fw = firewall();

    await expect(classify(fw)).resolves.toEqual({ action: "allow" });
    await expect(fw.classify("later")).resolves.toEqual(ADAPTED_BLOCK);
    await expect(fw.classifyBatch(["later", "batch"])).resolves.toEqual([
      { action: "allow" },
      ADAPTED_BLOCK,
    ]);
    expect(calls.map((call) => call.url)).toEqual([
      VERSION_2_URL,
      VERSION_1_URL,
      VERSION_1_URL,
      VERSION_1_URL,
    ]);
  });

  it("keeps the remembered fallback on one client instance", async () => {
    const calls = runtime(
      { status: 404, body: {} },
      { status: 200, body: version1(VERSION_1_ALLOW) },
      { status: 200, body: decisions(allowed()) },
    );

    await classify(firewall());
    await classify(firewall());

    expect(calls.map((call) => call.url)).toEqual([VERSION_2_URL, VERSION_1_URL, VERSION_2_URL]);
  });

  it.each([403, 404, 500])("returns the /classify error %d and does not remember it", async (status) => {
    const calls = runtime(
      { status: 404, body: { detail: "version 2 absent" } },
      { status, body: { detail: "version 1 failure" } },
      { status: 200, body: decisions(allowed()) },
    );
    const fw = firewall();

    const error = await classify(fw).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(SilmarilApiError);
    expect(error).toMatchObject({ status, body: '{"detail":"version 1 failure"}' });
    await expect(classify(fw)).resolves.toEqual({ action: "allow" });
    expect(calls.map((call) => call.url)).toEqual([VERSION_2_URL, VERSION_1_URL, VERSION_2_URL]);
  });

  it.each([
    { reason: "a missing label", prediction: { score: 0.9, threshold: 0.5 } },
    { reason: "an unknown label", prediction: { prediction: "SUSPICIOUS" } },
    { reason: "only a model label", prediction: { model_prediction: "MALICIOUS" } },
  ])("rejects a version 1 verdict with $reason and does not remember it", async ({ prediction }) => {
    const calls = runtime(
      { status: 404, body: {} },
      { status: 200, body: version1(prediction) },
      { status: 200, body: decisions(allowed()) },
    );
    const fw = firewall();

    await expect(classify(fw)).rejects.toThrow("response prediction must be BENIGN or MALICIOUS");
    await expect(classify(fw)).resolves.toEqual({ action: "allow" });
    expect(calls.map((call) => call.url)).toEqual([VERSION_2_URL, VERSION_1_URL, VERSION_2_URL]);
  });

  it("retries a rate-limited /classify fallback without returning to /v2/classify", async () => {
    vi.useFakeTimers();
    const calls = runtime(
      { status: 405, body: {} },
      { status: 429, body: "rate limited" },
      { status: 200, body: version1(VERSION_1_ALLOW) },
    );
    const pending = classify(firewall());

    await vi.advanceTimersByTimeAsync(1_000);

    await expect(pending).resolves.toEqual({ action: "allow" });
    expect(calls.map((call) => call.url)).toEqual([VERSION_2_URL, VERSION_1_URL, VERSION_1_URL]);
  });

  it.each([
    { reason: "no governance decision", governance: undefined },
    { reason: "a null governance decision", governance: null },
    { reason: "a governance allow", governance: { action: "allow", policy_version: "policy-9" } },
  ])("blocks a MALICIOUS prediction over a BENIGN model label with $reason", async ({ governance }) => {
    runtime(
      { status: 404, body: {} },
      {
        status: 200,
        body: version1({
          ...VERSION_1_BLOCK,
          model_prediction: "BENIGN",
          ...(governance === undefined ? {} : { governance }),
        }),
      },
    );
    const fw = firewall();

    const result = await classify(fw);

    expect(result).toMatchObject({ action: "block", source: "governance" });
    expect(result).not.toHaveProperty("outcome");
    await expect(fw.protect(vi.fn(async () => "answer"), { text: "event" })).rejects.toBeInstanceOf(
      FirewallBlockedException,
    );
  });

  it.each([
    {
      reason: "blocks on an unfamiliar model label",
      prediction: { ...VERSION_1_BLOCK, model_prediction: "UNSURE" },
      result: { action: "block", source: "governance" },
    },
    {
      reason: "attributes a block to the model label when it is MALICIOUS",
      prediction: { ...VERSION_1_BLOCK, model_prediction: "MALICIOUS" },
      result: ADAPTED_BLOCK,
    },
    {
      reason: "allows a BENIGN prediction whatever the model label",
      prediction: { ...VERSION_1_BLOCK, prediction: "BENIGN", model_prediction: "MALICIOUS" },
      result: { action: "allow" },
    },
  ])("$reason", async ({ prediction, result }) => {
    runtime({ status: 404, body: {} }, { status: 200, body: version1(prediction) });

    await expect(classify(firewall())).resolves.toEqual(result);
  });

  it("carries the model identifier over from the version 1 verdict", async () => {
    runtime(
      { status: 404, body: {} },
      { status: 200, body: version1({ ...VERSION_1_BLOCK, model_id: "silmaril-cascade-1-6" }) },
      { status: 200, body: version1({ ...VERSION_1_ALLOW, model_id: "silmaril-cascade-1-6" }) },
      { status: 200, body: version1({ ...VERSION_1_ALLOW, model_id: null }) },
    );
    const fw = firewall();

    await expect(classify(fw)).resolves.toEqual({ ...ADAPTED_BLOCK, modelId: "silmaril-cascade-1-6" });
    await expect(classify(fw)).resolves.toEqual({ action: "allow", modelId: "silmaril-cascade-1-6" });
    await expect(classify(fw)).resolves.toEqual({ action: "allow" });
  });

  it("derives the governance source and keeps the governance decision", async () => {
    runtime(
      { status: 404, body: {} },
      {
        status: 200,
        body: version1({
          ...VERSION_1_ALLOW,
          prediction: "MALICIOUS",
          model_prediction: "BENIGN",
          governance: { action: "block", rule_id: "block-shell", policy_version: "policy-9" },
        }),
      },
    );

    await expect(classify(firewall())).resolves.toEqual({
      action: "block",
      source: "governance",
      governance: { action: "block", ruleId: "block-shell", policyVersion: "policy-9" },
    });
  });

  it("prefers the requested mode, then the version 1 response mode", async () => {
    runtime(
      { status: 404, body: {} },
      { status: 200, body: version1({ ...VERSION_1_BLOCK, mode: "warn" }) },
      { status: 200, body: version1({ ...VERSION_1_BLOCK, mode: "warn" }) },
      { status: 200, body: version1({ ...VERSION_1_BLOCK, mode: "block" }) },
      { status: 200, body: version1(VERSION_1_BLOCK) },
      { status: 200, body: version1(VERSION_1_BLOCK) },
    );
    const fw = firewall();

    await expect(classify(fw)).resolves.toEqual({ ...ADAPTED_BLOCK, mode: "warn" });
    await expect(classify(fw, { mode: "block" })).resolves.toEqual({ ...ADAPTED_BLOCK, mode: "block" });
    await expect(classify(fw, { mode: "shadow" })).resolves.toEqual({ ...ADAPTED_BLOCK, mode: "shadow" });
    await expect(classify(fw, { mode: "shadow" })).resolves.toEqual({ ...ADAPTED_BLOCK, mode: "shadow" });
    await expect(classify(fw)).resolves.toEqual(ADAPTED_BLOCK);
  });

  it("rejects an invalid version 1 response mode", async () => {
    runtime(
      { status: 404, body: {} },
      { status: 200, body: version1({ ...VERSION_1_ALLOW, mode: "enforce" }) },
    );

    await expect(classify(firewall())).rejects.toThrow(
      "response mode must be shadow, warn, or block",
    );
  });
});

describe("version 1 fallback envelope", () => {
  it("adapts a version 1 batch answered by /v2/classify with its review and modes", async () => {
    const body = {
      predictions: [VERSION_1_ALLOW, { ...VERSION_1_BLOCK, mode: "warn" }],
      review: "standard",
    };
    const calls = runtime(
      { status: 200, body },
      { status: 404, body: {} },
      { status: 200, body },
      { status: 200, body: { predictions: [VERSION_1_ALLOW] } },
    );
    const options = { review: "standard" } as const;

    const answered = await firewall().classifyBatch(["first", "second"], options);

    expect(answered).toEqual([
      { action: "allow", review: "standard" },
      { ...ADAPTED_BLOCK, review: "standard", mode: "warn" },
    ]);
    expect(answered).toStrictEqual(await firewall().classifyBatch(["first", "second"], options));
    await expect(firewall().classifyBatch(["first", "second"])).rejects.toThrow(
      "response results length 1 does not match submitted texts length 2",
    );
    expect(calls.map((call) => call.url)).toEqual([
      VERSION_2_URL,
      VERSION_2_URL,
      VERSION_1_URL,
      VERSION_2_URL,
    ]);
  });

  it("carries the review acknowledgement over and still requires it", async () => {
    runtime(
      { status: 404, body: {} },
      { status: 200, body: { ...VERSION_1_ALLOW, review: "deep" } },
      { status: 200, body: { predictions: [VERSION_1_ALLOW, VERSION_1_BLOCK], review: "standard" } },
      { status: 200, body: VERSION_1_ALLOW },
      { status: 200, body: { predictions: [{ ...VERSION_1_ALLOW, review: "deep" }] } },
    );
    const fw = firewall();

    await expect(fw.classify("event", { review: "deep" })).resolves.toEqual({
      action: "allow",
      review: "deep",
    });
    await expect(fw.classifyBatch(["first", "second"], { review: "standard" })).resolves.toEqual([
      { action: "allow", review: "standard" },
      { ...ADAPTED_BLOCK, review: "standard" },
    ]);
    await expect(fw.classify("event", { review: "deep" })).rejects.toBeInstanceOf(
      ReviewCompatibilityError,
    );
    await expect(fw.classifyBatch(["event"], { review: "deep" })).rejects.toBeInstanceOf(
      ReviewCompatibilityError,
    );
  });

  it.each([
    { reason: "too few", predictions: [VERSION_1_ALLOW], length: 1 },
    { reason: "too many", predictions: [VERSION_1_ALLOW, VERSION_1_ALLOW, VERSION_1_ALLOW], length: 3 },
  ])("rejects $reason version 1 predictions", async ({ predictions, length }) => {
    runtime({ status: 404, body: {} }, { status: 200, body: { predictions } });

    await expect(firewall().classifyBatch(["first", "second"])).rejects.toThrow(
      `response results length ${length} does not match submitted texts length 2`,
    );
  });

  it.each([
    { reason: "null", predictions: null, error: "response predictions must be an array" },
    { reason: "an object", predictions: { prediction: "BENIGN" }, error: "response predictions must be an array" },
    { reason: "a list of labels", predictions: ["BENIGN"], error: "response prediction must be an object" },
  ])("rejects version 1 predictions that are $reason", async ({ predictions, error }) => {
    runtime({ status: 404, body: {} }, { status: 200, body: { predictions } });

    await expect(firewall().classifyBatch(["event"])).rejects.toThrow(error);
  });

  it("enforces an adapted block and names a governance block", async () => {
    runtime(
      { status: 403, body: {} },
      { status: 200, body: VERSION_1_BLOCK },
      {
        status: 200,
        body: { ...VERSION_1_ALLOW, governance: { action: "block", policy_version: "policy-9" } },
      },
      { status: 200, body: { ...VERSION_1_BLOCK, mode: "warn" } },
    );
    const fw = firewall();
    const operation = vi.fn(async () => "answer");

    const modelBlock = await fw.protect(operation, { text: "event" }).catch((caught: unknown) => caught);
    const governanceBlock = await fw.protect(operation, { text: "event" }).catch((caught: unknown) => caught);

    expect(modelBlock).toBeInstanceOf(FirewallBlockedException);
    expect(modelBlock).toMatchObject({ result: ADAPTED_BLOCK });
    expect(governanceBlock).toMatchObject({
      message: "Request blocked by Silmaril Firewall governance policy: 'event'",
      result: { action: "block", source: "governance" },
    });
    await expect(fw.protect(operation, { text: "event" })).resolves.toBe("answer");
  });
});
