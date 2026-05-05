// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

// Compile-time contract tests. These assertions ensure the public SDK types
// stay structurally assignable to the consumer-facing types in the `ai` SDK
// (Vercel AI v5). A regression here causes `tsc` to fail during
// `npm run typecheck`, catching breakage before release instead of when a
// customer pastes `firewall.asMiddleware()` into `wrapLanguageModel(...)`.

import { describe, it, expect } from "vitest";
import type { LanguageModelV2Middleware } from "@ai-sdk/provider";
import { Firewall, type FirewallMiddleware } from "../src/index.js";

const firewall = new Firewall({
  apiKey: "sk-test",
  apiUrl: "https://api.test.invalid/classify",
});

// --- Assignability: FirewallMiddleware → ai LanguageModelV2Middleware ---

// Runtime value so we exercise the type relationship (not just a type alias).
// Typecheck fails if `asMiddleware()` cannot satisfy LanguageModelV2Middleware.
const asAiMiddleware: LanguageModelV2Middleware = firewall.asMiddleware();

// Plain FirewallMiddleware value must also satisfy the ai contract.
const bareMiddleware: FirewallMiddleware = firewall.asMiddleware();
const bareAsAi: LanguageModelV2Middleware = bareMiddleware;

describe("type contract", () => {
  it("FirewallMiddleware is structurally assignable to ai LanguageModelV2Middleware", () => {
    // The assignments above are the real test. This runtime assertion
    // anchors the compile-time check in a Vitest suite so it shows up in
    // reports and keeps the imports live.
    expect(typeof asAiMiddleware.wrapGenerate).toBe("function");
    expect(typeof asAiMiddleware.wrapStream).toBe("function");
    expect(typeof bareAsAi.wrapGenerate).toBe("function");
  });
});
