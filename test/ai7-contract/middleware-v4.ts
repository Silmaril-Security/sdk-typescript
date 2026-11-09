import type { LanguageModelV4Middleware } from "@ai-sdk/provider";

import { Firewall } from "../../src/index.js";
import { createMiddlewareV4 } from "../../src/adapters/vercel-v4.js";

const firewall = new Firewall({
  apiKey: "contract-only",
  apiUrl: "https://example.invalid/classify",
});

// This assignment is the compatibility contract. Do not replace it with a
// type assertion: the isolated Node 22 lane installs the exact AI SDK 7 and
// provider versions and verifies structural assignability.
const middleware: LanguageModelV4Middleware = createMiddlewareV4(firewall, {
  scanOutput: true,
  scanToolCalls: true,
});

void middleware;
