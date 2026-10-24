import { afterEach, describe, expect, it, vi } from "vitest";
import { Firewall, type FirewallMode } from "../src/index.js";
import { createMiddleware } from "../src/adapters/vercel.js";
import { createLangChainHandler } from "../src/adapters/langchain.js";
import { createDeepAgentsMiddleware } from "../src/adapters/deepagents.js";

const credentials = { apiKey: "offline-test", apiUrl: "https://api.test.invalid/classify" };
// These values represent JavaScript callers and unvalidated configuration input.
const invalidModes = ["Block", "enforce", "", null, false, 1, {}];

afterEach(() => vi.unstubAllGlobals());

describe("runtime mode validation", () => {
  it.each(invalidModes)("rejects constructor mode %j before a request", (value) => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    expect(() => new Firewall({ ...credentials, mode: value as FirewallMode }))
      .toThrow("mode must be shadow, warn, or block");
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(invalidModes)("rejects single and batch overrides %j before a request", async (value) => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const firewall = new Firewall({ ...credentials, mode: "block" });
    const options = { mode: value as FirewallMode };
    await expect(firewall.classify("event", options)).rejects.toThrow("mode must be");
    await expect(firewall.classifyBatch(["event"], options)).rejects.toThrow("mode must be");
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(invalidModes)("rejects adapter override %j before fail-open handling", async (value) => {
    const firewall = new Firewall({ ...credentials, mode: "block" });
    const classify = vi.spyOn(firewall, "classify");
    const options = { mode: value as FirewallMode };
    expect(() => createMiddleware(firewall, options)).toThrow("mode must be");
    await expect(createLangChainHandler(firewall, { ...options, failOpen: true }))
      .rejects.toThrow("mode must be");
    expect(() => createDeepAgentsMiddleware(firewall, { ...options, failOpen: true }))
      .toThrow("mode must be");
    expect(classify).not.toHaveBeenCalled();
  });

  it.each(["malicious", "governance"] as const)("valid block prevents generation for a %s verdict", async (kind) => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      prediction: kind === "malicious" ? "MALICIOUS" : "BENIGN",
      score: 0.9, threshold: 0.5,
      ...(kind === "governance" ? { governance: { action: "block", policy_version: "fixture" } } : {}),
    }), { status: 200 })));
    const firewall = new Firewall({ ...credentials, mode: "block" });
    const generate = vi.fn(async () => ({ text: "unreachable" }));
    await expect(createMiddleware(firewall).wrapGenerate({
      params: { prompt: [{ role: "user", content: "synthetic event" }] },
      doGenerate: generate,
    })).rejects.toThrow();
    expect(generate).not.toHaveBeenCalled();
  });
});
