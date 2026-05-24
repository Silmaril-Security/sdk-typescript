// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

// Compile-time contract tests. These assertions ensure the public SDK types
// stay structurally assignable to the consumer-facing types in the `ai` SDK.
// A regression here causes `tsc` to fail during
// `npm run typecheck`, catching breakage before release instead of when a
// customer pastes `firewall.asMiddleware()` into `wrapLanguageModel(...)`.

import { describe, it, expect } from "vitest";
import { wrapLanguageModel, type LanguageModelMiddleware } from "ai";
import type {
  LanguageModelV2Middleware,
  LanguageModelV3,
  LanguageModelV3Middleware,
} from "@ai-sdk/provider";
import { Firewall, type FirewallMiddleware } from "../src/index.js";

const firewall = new Firewall({
  apiKey: "sk-test",
  apiUrl: "https://api.test.invalid/classify",
});

// --- Assignability: FirewallMiddleware -> ai middleware contracts ---

// Runtime value so we exercise the type relationship (not just a type alias).
// Typecheck fails if `asMiddleware()` cannot satisfy the current AI SDK
// middleware contract.
const asAiMiddleware: LanguageModelV2Middleware = firewall.asMiddleware();
const asAiV3Middleware: LanguageModelV3Middleware = firewall.asMiddleware();
const asCurrentAiMiddleware: LanguageModelMiddleware = firewall.asMiddleware();

// Plain FirewallMiddleware value must also satisfy the ai contract.
const bareMiddleware: FirewallMiddleware = firewall.asMiddleware();
const bareAsAi: LanguageModelV2Middleware = bareMiddleware;
const bareAsAiV3: LanguageModelV3Middleware = bareMiddleware;
const wrappedModel = wrapLanguageModel({
  model: {} as LanguageModelV3,
  middleware: bareMiddleware,
});

describe("type contract", () => {
  it("FirewallMiddleware is structurally assignable to ai middleware", () => {
    // The assignments above are the real test. This runtime assertion
    // anchors the compile-time check in a Vitest suite so it shows up in
    // reports and keeps the imports live.
    expect(typeof asAiMiddleware.wrapGenerate).toBe("function");
    expect(typeof asAiV3Middleware.wrapGenerate).toBe("function");
    expect(typeof asCurrentAiMiddleware.wrapStream).toBe("function");
    expect(typeof asAiMiddleware.wrapStream).toBe("function");
    expect(typeof bareAsAi.wrapGenerate).toBe("function");
    expect(typeof bareAsAiV3.wrapStream).toBe("function");
    expect(wrappedModel.specificationVersion).toBe("v3");
  });
});
