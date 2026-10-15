import { afterEach, describe, expect, it, vi } from "vitest";
import { Firewall } from "../src/firewall.js";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("governance response evidence", () => {
  it("preserves full evidence for a benign governance block through classify", async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({
        prediction: "BENIGN",
        score: 0.1,
        threshold: 0.5,
        governance: {
          action: "block",
          rule_id: "block-unapproved-mcp",
          policy_version: "policy-v6",
          resource: {
            kind: "mcp_tool",
            id: "create_issue",
            parent_id: "github",
          },
          identity_revision: "identity-revision-42",
          reason: "identity_unresolved",
        },
      })),
    );
    const fw = new Firewall({
      apiKey: "sk-test",
      apiUrl: "https://example.com/classify",
    });

    const result = await fw.classify("synthetic");

    expect(result.prediction).toBe("BENIGN");
    expect(result.governance).toEqual({
      action: "block",
      ruleId: "block-unapproved-mcp",
      policyVersion: "policy-v6",
      resource: {
        kind: "mcp_tool",
        id: "create_issue",
        parentId: "github",
      },
      identityRevision: "identity-revision-42",
      reason: "identity_unresolved",
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.governance)).toBe(true);
    expect(Object.isFrozen(result.governance?.resource)).toBe(true);
  });

  it("preserves unknown reasons and nullable optional evidence through classifyBatch", async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({
        predictions: [
          {
            prediction: "BENIGN",
            score: 0.1,
            threshold: 0.5,
            governance: {
              action: "block",
              rule_id: "future-rule",
              policy_version: "policy-v6",
              resource: {
                kind: "plugin",
                id: "future-plugin",
                parent_id: null,
              },
              identity_revision: "identity-revision-43",
              reason: "future_runtime_reason",
            },
          },
          { prediction: "BENIGN", score: 0, threshold: 0.5 },
          { prediction: "BENIGN", score: 0, threshold: 0.5, governance: null },
          {
            prediction: "BENIGN",
            score: 0,
            threshold: 0.5,
            governance: {
              action: "allow",
              rule_id: null,
              policy_version: "legacy-compatible",
              resource: null,
              identity_revision: null,
              reason: null,
            },
          },
        ],
      })),
    );
    const fw = new Firewall({
      apiKey: "sk-test",
      apiUrl: "https://example.com/classify",
    });

    const results = await fw.classifyBatch(["a", "b", "c", "d"]);

    expect(results[0]?.governance).toEqual({
      action: "block",
      ruleId: "future-rule",
      policyVersion: "policy-v6",
      resource: { kind: "plugin", id: "future-plugin" },
      identityRevision: "identity-revision-43",
      reason: "future_runtime_reason",
    });
    expect(results[1]).not.toHaveProperty("governance");
    expect(results[2]).not.toHaveProperty("governance");
    expect(results[3]?.governance).toEqual({
      action: "allow",
      policyVersion: "legacy-compatible",
    });
    for (const result of results) {
      expect(Object.isFrozen(result)).toBe(true);
      if (result.governance !== undefined) {
        expect(Object.isFrozen(result.governance)).toBe(true);
      }
      if (result.governance?.resource !== undefined) {
        expect(Object.isFrozen(result.governance.resource)).toBe(true);
      }
    }
  });

  describe.each(["classify", "classifyBatch"] as const)(
    "malformed evidence through %s",
    (method) => {
      it.each([
        {
          name: "an unknown resource kind",
          evidence: { resource: { kind: "future_kind", id: "resource-1" } },
          error: /resource has an invalid kind/,
        },
        {
          name: "an MCP tool without a parent",
          evidence: { resource: { kind: "mcp_tool", id: "tool-1" } },
          error: /mcp_tool resource requires a non-empty parent_id/,
        },
        {
          name: "a resource without an id",
          evidence: { resource: { kind: "plugin" } },
          error: /resource id must be a non-empty string/,
        },
        {
          name: "a resource with a blank id",
          evidence: { resource: { kind: "plugin", id: " " } },
          error: /resource id must be a non-empty string/,
        },
        {
          name: "a non-string identity revision",
          evidence: { identity_revision: 42 },
          error: /identity_revision must be a string when provided/,
        },
        {
          name: "a non-string reason",
          evidence: { reason: ["identity_unresolved"] },
          error: /reason must be a string when provided/,
        },
      ])("rejects $name", async ({ evidence, error }) => {
        const prediction = {
          prediction: "BENIGN",
          score: 0.1,
          threshold: 0.5,
          governance: {
            action: "block",
            policy_version: "policy-v6",
            ...evidence,
          },
        };
        const fetch = vi.fn(async () =>
          new Response(JSON.stringify(
            method === "classify" ? prediction : { predictions: [prediction] },
          )),
        );
        globalThis.fetch = fetch;
        const fw = new Firewall({
          apiKey: "sk-test",
          apiUrl: "https://example.com/classify",
        });

        const classification = method === "classify"
          ? fw.classify("synthetic")
          : fw.classifyBatch(["synthetic"]);

        await expect(classification).rejects.toThrow(error);
        expect(fetch).toHaveBeenCalledOnce();
      });
    },
  );
});

it("sends the resource read by policy while leaving caller identity in metadata", async () => {
  const calls: Record<string, unknown>[] = [];
  globalThis.fetch = vi.fn(async (_url, init) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    calls.push(body);
    const denied = JSON.stringify(body.resource)
      === JSON.stringify({ kind: "plugin", id: "blocked-plugin" });
    return new Response(JSON.stringify({
      prediction: "BENIGN",
      score: 0.1,
      threshold: 0.5,
      governance: {
        action: denied ? "block" : "allow",
        policy_version: "fixture",
      },
    }));
  });
  const fw = new Firewall({
    apiKey: "sk-test",
    apiUrl: "https://example.com/classify",
  });
  const result = await fw.classify("synthetic", {
    governance: {
      agent: "attribution-only",
      resource: { kind: "plugin", id: "blocked-plugin" },
    },
  });
  expect(result.governance?.action).toBe("block");
  expect(calls[0]).not.toHaveProperty("agent");
  const spoofed = await fw.classify("synthetic", {
    metadata: {
      silmaril: {
        governance: {
          resource: { kind: "plugin", id: "blocked-plugin" },
        },
      },
    },
  });
  expect(spoofed.governance?.action).toBe("allow");
});

it("retains null positions in canonical batch resources", async () => {
  globalThis.fetch = vi.fn(async (_url, init) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    expect(body.resources).toEqual([null, { kind: "plugin", id: "blocked-plugin" }, null]);
    return new Response(JSON.stringify({
      predictions: [0, 1, 2].map(() => ({
        prediction: "BENIGN",
        score: 0.1,
        threshold: 0.5,
      })),
    }));
  });
  const fw = new Firewall({
    apiKey: "sk-test",
    apiUrl: "https://example.com/classify",
  });
  await fw.classifyBatch(["a", "b", "c"], {
    governance: [
      undefined,
      { resource: { kind: "plugin", id: "blocked-plugin" } },
      { agent: "attribution-only" },
    ],
  });
});

it.each([
  { kind: "plugin" },
  { kind: "plugin", id: " " },
  { kind: "mcp_tool", id: "tool" },
  { kind: "tool", id: "tool", parentId: "server" },
  { kind: "unknown", id: "tool" },
])("rejects invalid canonical refs before transport: %j", async (resource) => {
  const fetch = vi.fn();
  globalThis.fetch = fetch;
  const fw = new Firewall({
    apiKey: "sk-test",
    apiUrl: "https://example.com/classify",
  });
  await expect(
    fw.classify("synthetic", { governance: { resource: resource as never } }),
  ).rejects.toThrow();
  expect(fetch).not.toHaveBeenCalled();
});
