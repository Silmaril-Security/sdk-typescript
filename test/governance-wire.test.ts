import { afterEach, expect, it, vi } from "vitest";
import { Firewall } from "../src/firewall.js";
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });
it("sends the resource read by policy while leaving caller identity in metadata", async () => {
  const calls: Record<string, unknown>[] = [];
  globalThis.fetch = vi.fn(async (_url, init) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    calls.push(body);
    const denied = JSON.stringify(body.resource) === JSON.stringify({ kind: "plugin", id: "blocked-plugin" });
    return new Response(JSON.stringify({ prediction: "BENIGN", score: 0.1, threshold: 0.5, governance: { action: denied ? "block" : "allow", policy_version: "fixture" } }));
  });
  const fw = new Firewall({ apiKey: "sk-test", apiUrl: "https://example.com/classify" });
  const result = await fw.classify("synthetic", { governance: { agent: "attribution-only", resource: { kind: "plugin", id: "blocked-plugin" } } });
  expect(result.governance?.action).toBe("block");
  expect(calls[0]).not.toHaveProperty("agent");
  const spoofed = await fw.classify("synthetic", { metadata: { silmaril: { governance: { resource: { kind: "plugin", id: "blocked-plugin" } } } } });
  expect(spoofed.governance?.action).toBe("allow");
});
it("retains null positions in canonical batch resources", async () => {
  globalThis.fetch = vi.fn(async (_url, init) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    expect(body.resources).toEqual([null, { kind: "plugin", id: "blocked-plugin" }, null]);
    return new Response(JSON.stringify({ predictions: [0, 1, 2].map(() => ({ prediction: "BENIGN", score: 0.1, threshold: 0.5 })) }));
  });
  const fw = new Firewall({ apiKey: "sk-test", apiUrl: "https://example.com/classify" });
  await fw.classifyBatch(["a", "b", "c"], { governance: [undefined, { resource: { kind: "plugin", id: "blocked-plugin" } }, { agent: "attribution-only" }] });
});
it.each([
  { kind: "plugin" }, { kind: "plugin", id: " " },
  { kind: "mcp_tool", id: "tool" }, { kind: "tool", id: "tool", parentId: "server" },
  { kind: "unknown", id: "tool" },
])("rejects invalid canonical refs before transport: %j", async (resource) => {
  const fetch = vi.fn(); globalThis.fetch = fetch;
  const fw = new Firewall({ apiKey: "sk-test", apiUrl: "https://example.com/classify" });
  await expect(fw.classify("synthetic", { governance: { resource: resource as never } })).rejects.toThrow();
  expect(fetch).not.toHaveBeenCalled();
});
