// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

import { HumanMessage, ToolMessage } from "@langchain/core/messages";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  Firewall,
  ReviewCompatibilityError,
  type ReviewLevel,
} from "../src/index.js";
import { createDeepAgentsMiddleware } from "../src/adapters/deepagents.js";
import { createLangChainHandler } from "../src/adapters/langchain.js";

const TEST_API_URL = "https://api.test.invalid/classify";
const ORIGINAL_FETCH = globalThis.fetch;

interface FetchCall {
  readonly body: Record<string, unknown>;
}

function response(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: `status-${status}`,
    json: async () => body,
    text: async () => typeof body === "string" ? body : JSON.stringify(body),
  } as unknown as Response;
}

function mockFetch(responses: ReadonlyArray<{ status: number; body: unknown }>): FetchCall[] {
  const calls: FetchCall[] = [];
  let index = 0;
  globalThis.fetch = vi.fn(async (_url: string | URL, init: RequestInit) => {
    calls.push({ body: JSON.parse(init.body as string) as Record<string, unknown> });
    const selected = responses[Math.min(index, responses.length - 1)]!;
    index += 1;
    return response(selected.status, selected.body);
  }) as unknown as typeof fetch;
  return calls;
}

function single(review?: ReviewLevel): Record<string, unknown> {
  return {
    prediction: "BENIGN",
    score: 0.1,
    threshold: 0.5,
    ...(review === undefined ? {} : { review }),
  };
}

afterEach(() => {
  globalThis.fetch = ORIGINAL_FETCH;
  vi.useRealTimers();
});

describe("review selection", () => {
  it("exports ReviewLevel and preserves the legacy omitted wire and result shape", async () => {
    const level: ReviewLevel = "standard";
    expect(level).toBe("standard");
    const calls = mockFetch([{ status: 200, body: single() }]);
    const firewall = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    const result = await firewall.classify("hello", { requestId: "review-omitted" });

    expect(calls[0]!.body).not.toHaveProperty("review");
    expect(result).not.toHaveProperty("review");
    expect(firewall.review).toBeUndefined();
  });

  it("serializes and returns a verified explicit single-call acknowledgement", async () => {
    const calls = mockFetch([{ status: 200, body: single("standard") }]);
    const firewall = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    const result = await firewall.classify("hello", {
      review: "standard",
      requestId: "review-standard",
    });

    expect(calls[0]!.body.review).toBe("standard");
    expect(result.review).toBe("standard");
  });

  it("matches the batch envelope acknowledgement rather than prediction fields", async () => {
    const calls = mockFetch([{
      status: 200,
      body: {
        review: "deep",
        predictions: [
          { ...single(), review: "standard" },
          single(),
        ],
      },
    }]);
    const firewall = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    const results = await firewall.classifyBatch(["a", "b"], {
      review: "deep",
      requestId: "review-batch",
    });

    expect(calls[0]!.body.review).toBe("deep");
    expect(results.map((result) => result.review)).toEqual(["deep", "deep"]);
  });

  it("uses per-call review over the explicit client default", async () => {
    const calls = mockFetch([
      { status: 200, body: single("standard") },
      { status: 200, body: single("deep") },
      { status: 200, body: { review: "standard", predictions: [single()] } },
    ]);
    const firewall = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      review: "standard",
    });

    await firewall.classify("inherited", { requestId: "review-client" });
    await firewall.classify("overridden", {
      review: "deep",
      requestId: "review-call",
    });
    await firewall.classifyBatch(["inherited batch"], { requestId: "review-client-batch" });

    expect(calls.map((call) => call.body.review)).toEqual(["standard", "deep", "standard"]);
    expect(firewall.review).toBe("standard");
  });

  it("rejects null and invalid runtime review values before sending", async () => {
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as typeof fetch;
    const invalid = [null, "Deep", " deep", "", 1, true, {}];

    for (const review of invalid) {
      expect(() => new Firewall({
        apiKey: "sk-test",
        apiUrl: TEST_API_URL,
        review,
      } as never)).toThrow(/review must be standard or deep/);
    }

    const firewall = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });
    for (const review of invalid) {
      await expect(firewall.classify("x", { review } as never))
        .rejects.toThrow(/review must be standard or deep/);
      await expect(firewall.classifyBatch(["x"], { review } as never))
        .rejects.toThrow(/review must be standard or deep/);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["missing", undefined],
    ["mismatched", "standard"],
    ["invalid", null],
  ])("rejects a %s single acknowledgement without retrying the successful response", async (
    _case,
    acknowledgement,
  ) => {
    const body = {
      ...single(),
      ...(acknowledgement === undefined ? {} : { review: acknowledgement }),
    };
    const calls = mockFetch([{ status: 200, body }]);
    const firewall = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    const error = await firewall.classify("x", { review: "deep" }).catch((caught) => caught);

    expect(error).toBeInstanceOf(ReviewCompatibilityError);
    expect(error).toMatchObject({
      requestedReview: "deep",
      acknowledgedReview: acknowledgement,
    });
    expect(calls).toHaveLength(1);
  });

  it.each([
    ["null", null],
    ["primitive", "deep"],
  ])("treats a successful %s single response as a missing acknowledgement", async (
    _case,
    body,
  ) => {
    const calls = mockFetch([{ status: 200, body }]);
    const firewall = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    const error = await firewall.classify("x", { review: "deep" }).catch((caught) => caught);

    expect(error).toBeInstanceOf(ReviewCompatibilityError);
    expect(error).toMatchObject({
      requestedReview: "deep",
      acknowledgedReview: undefined,
    });
    expect(calls).toHaveLength(1);
  });

  it("rejects a missing batch envelope acknowledgement without retrying", async () => {
    const calls = mockFetch([{
      status: 200,
      body: { predictions: [{ ...single(), review: "deep" }] },
    }]);
    const firewall = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    await expect(firewall.classifyBatch(["x"], { review: "deep" }))
      .rejects.toBeInstanceOf(ReviewCompatibilityError);
    expect(calls).toHaveLength(1);
  });

  it("treats a successful null batch response as a missing acknowledgement", async () => {
    const calls = mockFetch([{ status: 200, body: null }]);
    const firewall = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    await expect(firewall.classifyBatch(["x"], { review: "standard" }))
      .rejects.toMatchObject({
        name: "ReviewCompatibilityError",
        requestedReview: "standard",
        acknowledgedReview: undefined,
      });
    expect(calls).toHaveLength(1);
  });

  it("preserves the selected review across transport retries", async () => {
    vi.useFakeTimers();
    const calls = mockFetch([
      { status: 429, body: "rate limited" },
      { status: 200, body: single("deep") },
    ]);
    const firewall = new Firewall({ apiKey: "sk-test", apiUrl: TEST_API_URL });

    const pending = firewall.classify("x", { review: "deep" });
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(pending).resolves.toMatchObject({ review: "deep" });
    expect(calls.map((call) => call.body.review)).toEqual(["deep", "deep"]);
  });

  it("keeps concurrent per-call review selections independent", async () => {
    const pending: Array<{
      body: Record<string, unknown>;
      resolve: (value: Response) => void;
    }> = [];
    globalThis.fetch = vi.fn((_url: string | URL, init: RequestInit) =>
      new Promise<Response>((resolve) => {
        pending.push({
          body: JSON.parse(init.body as string) as Record<string, unknown>,
          resolve,
        });
      })
    ) as unknown as typeof fetch;
    const firewall = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      review: "standard",
    });

    const deep = firewall.classify("deep", { review: "deep" });
    const standard = firewall.classify("standard");
    await vi.waitFor(() => expect(pending).toHaveLength(2));
    expect(pending.map((call) => call.body.review)).toEqual(["deep", "standard"]);

    pending[1]!.resolve(response(200, single("standard")));
    pending[0]!.resolve(response(200, single("deep")));
    await expect(Promise.all([deep, standard])).resolves.toMatchObject([
      { review: "deep" },
      { review: "standard" },
    ]);
  });
});

describe("review selection in adapters", () => {
  it("inherits the client default without an adapter review option", async () => {
    const calls = mockFetch([{ status: 200, body: single("deep") }]);
    const firewall = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      review: "deep",
    });
    const middleware = firewall.asMiddleware();
    const generate = vi.fn(async () => ({ text: "safe response" }));

    await middleware.wrapGenerate({
      params: { prompt: [{ role: "user", content: "hello" }] },
      doGenerate: generate,
    });

    expect(calls[0]!.body.review).toBe("deep");
    expect(generate).toHaveBeenCalledOnce();
  });

  it("checks compatibility before Vercel callbacks or block handling", async () => {
    const calls = mockFetch([{ status: 200, body: null }]);
    const firewall = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      review: "deep",
    });
    const onClassify = vi.fn();
    const onBlocked = vi.fn();
    const generate = vi.fn(async () => ({ text: "unreachable" }));
    const middleware = firewall.asMiddleware({ onClassify, onBlocked });

    await expect(middleware.wrapGenerate({
      params: { prompt: [{ role: "user", content: "unsafe" }] },
      doGenerate: generate,
    })).rejects.toBeInstanceOf(ReviewCompatibilityError);
    expect(onClassify).not.toHaveBeenCalled();
    expect(onBlocked).not.toHaveBeenCalled();
    expect(generate).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
  });

  it("does not swallow compatibility errors in fail-open LangChain handling", async () => {
    mockFetch([{ status: 200, body: single() }]);
    const firewall = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      review: "standard",
    });
    const onClassify = vi.fn();
    const logger = vi.fn();
    const handler = await createLangChainHandler(firewall, { onClassify, logger });

    await expect(handler.handleLLMStart?.({} as never, ["hello"], "run-review"))
      .rejects.toBeInstanceOf(ReviewCompatibilityError);
    expect(onClassify).not.toHaveBeenCalled();
    expect(logger).not.toHaveBeenCalled();
  });

  it("does not swallow compatibility errors in fail-open Deep Agents handling", async () => {
    mockFetch([{ status: 200, body: single() }]);
    const firewall = new Firewall({
      apiKey: "sk-test",
      apiUrl: TEST_API_URL,
      review: "standard",
    });
    const onClassify = vi.fn();
    const middleware = createDeepAgentsMiddleware(firewall, { onClassify });
    const request = {
      messages: [new HumanMessage("hello")],
      state: { messages: [new HumanMessage("hello")] },
      runtime: {},
    };
    const handler = vi.fn(async () => new ToolMessage({
      content: "unreachable",
      tool_call_id: "review-call",
    }));

    await expect(middleware.wrapModelCall!(request as never, handler as never))
      .rejects.toBeInstanceOf(ReviewCompatibilityError);
    expect(onClassify).not.toHaveBeenCalled();
    expect(handler).not.toHaveBeenCalled();
  });
});
