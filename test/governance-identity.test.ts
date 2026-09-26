// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import {
  Firewall,
  resolveMcpToolResource,
  type ConcreteGovernanceResource,
} from "../src/index.js";

const API_URL = "https://api.test.invalid/classify";

function response(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    json: async () => body,
  } as Response;
}

describe("governance identity contract", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("pins the exact vendored contract bytes", () => {
    const contractDir = resolve(process.cwd(), "contracts/governance/v1");
    const sums = readFileSync(resolve(contractDir, "SHA256SUMS"), "utf8").trim().split("\n");
    for (const line of sums) {
      const [expected, file] = line.split(/\s+/u);
      const actual = createHash("sha256")
        .update(readFileSync(resolve(contractDir, file!)))
        .digest("hex");
      expect(actual, file).toBe(expected);
    }
  });

  it("serializes all seven concrete resource kinds without changing raw tool_name", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    globalThis.fetch = (async (_url, init) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return response({ prediction: "BENIGN", score: 0, threshold: 0.5 });
    }) as typeof fetch;
    const firewall = new Firewall({ apiKey: "test", apiUrl: API_URL });
    const resources: ConcreteGovernanceResource[] = [
      { kind: "agent", id: "cursor" },
      { kind: "tool", id: "read_file" },
      { kind: "mcp_server", id: "github" },
      { kind: "mcp_tool", id: "create_issue", parentId: "github" },
      { kind: "plugin", id: "firewall" },
      { kind: "skill", id: "review" },
      { kind: "extension", id: "publisher.extension" },
    ];

    for (const resource of resources) {
      await firewall.classify("input", {
        toolName: "MCP:github:create_issue",
        resource,
        identityRevision: "snapshot-7",
      });
    }

    expect(bodies.map((body) => body.resource)).toEqual([
      { kind: "agent", id: "cursor" },
      { kind: "tool", id: "read_file" },
      { kind: "mcp_server", id: "github" },
      { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
      { kind: "plugin", id: "firewall" },
      { kind: "skill", id: "review" },
      { kind: "extension", id: "publisher.extension" },
    ]);
    expect(bodies.every((body) => body.tool_name === "MCP:github:create_issue")).toBe(true);
    expect(bodies.every((body) => body.identity_revision === "snapshot-7")).toBe(true);
  });

  it("serializes aligned nullable batch resources and one identity revision", async () => {
    let body: Record<string, unknown> | undefined;
    globalThis.fetch = (async (_url, init) => {
      body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return response({
        predictions: [
          { prediction: "BENIGN", score: 0, threshold: 0.5 },
          { prediction: "BENIGN", score: 0, threshold: 0.5 },
        ],
      });
    }) as typeof fetch;
    const firewall = new Firewall({ apiKey: "test", apiUrl: API_URL });

    await firewall.classifyBatch(["a", "b"], {
      toolNames: ["raw_a", "raw_b"],
      resources: [{ kind: "mcp_tool", id: "search", parentId: "docs" }, null],
      identityRevision: "snapshot-batch",
    });

    expect(body).toMatchObject({
      tool_names: ["raw_a", "raw_b"],
      resources: [{ kind: "mcp_tool", id: "search", parent_id: "docs" }, null],
      identity_revision: "snapshot-batch",
    });
  });

  it("preserves legacy wildcard GovernanceContext serialization", async () => {
    let body: Record<string, unknown> | undefined;
    globalThis.fetch = (async (_url, init) => {
      body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return response({ prediction: "BENIGN", score: 0, threshold: 0.5 });
    }) as typeof fetch;
    const firewall = new Firewall({ apiKey: "test", apiUrl: API_URL });

    await firewall.classify("input", {
      governance: { resource: { kind: "mcp_server" } },
    });

    expect(body).toMatchObject({
      metadata: {
        silmaril: {
          governance: { resource: { kind: "mcp_server" } },
        },
      },
    });
  });

  it("rejects malformed resources and alignment before network", async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      return response({});
    }) as typeof fetch;
    const firewall = new Firewall({ apiKey: "test", apiUrl: API_URL });

    await expect(
      firewall.classify("x", {
        resource: { kind: "mcp_tool", id: "search" } as ConcreteGovernanceResource,
      }),
    ).rejects.toThrow(/parentId is required/);
    await expect(
      firewall.classify("x", {
        resource: {
          kind: "tool",
          id: "x",
          parentId: "server",
        } as unknown as ConcreteGovernanceResource,
      }),
    ).rejects.toThrow(/parentId is only valid/);
    await expect(
      firewall.classify("x", { resource: { kind: "tool", id: "   " } }),
    ).rejects.toThrow(/id must be a non-empty string/);
    await expect(
      firewall.classifyBatch(["a", "b"], { resources: [{ kind: "tool", id: "x" }] }),
    ).rejects.toThrow(/resources length 1 does not match texts length 2/);
    await expect(
      firewall.classify("x", { identityRevision: "" }),
    ).rejects.toThrow(/identityRevision must be a non-empty string/);
    expect(calls).toBe(0);
  });

  it("parses governance identity response fields", async () => {
    globalThis.fetch = (async () => response({
      prediction: "BENIGN",
      score: 0,
      threshold: 0.5,
      governance: {
        action: "block",
        rule_id: "deny-search",
        policy_version: "policy-4",
        resource: { kind: "mcp_tool", id: "search", parent_id: "docs" },
        identity_revision: "snapshot-4",
        reason: "identity_unresolved",
      },
    })) as typeof fetch;
    const firewall = new Firewall({ apiKey: "test", apiUrl: API_URL });

    await expect(firewall.classify("x")).resolves.toMatchObject({
      prediction: "BENIGN",
      governance: {
        action: "block",
        ruleId: "deny-search",
        policyVersion: "policy-4",
        resource: { kind: "mcp_tool", id: "search", parentId: "docs" },
        identityRevision: "snapshot-4",
        reason: "identity_unresolved",
      },
    });
  });
});

describe("resolveMcpToolResource", () => {
  it("supports mcp__ and MCP: spellings with exact configured identity precedence", () => {
    expect(resolveMcpToolResource(["git-hub", "git_hub"], "mcp__git_hub__search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search", parentId: "git_hub" },
    });
    expect(resolveMcpToolResource(["github"], "MCP:github:create_issue")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "create_issue", parentId: "github" },
    });
  });

  it("uses only a unique configured host alias and reports collisions explicitly", () => {
    expect(resolveMcpToolResource(["git-hub"], "mcp__git_hub__search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search", parentId: "git-hub" },
    });
    expect(resolveMcpToolResource(["git-hub", "git.hub"], "mcp__git_hub__search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search", parentId: "git-hub" },
    });
    expect(
      resolveMcpToolResource(["git-hub-id", "git-hub_id"], "mcp__git_hub_id__search"),
    ).toEqual({
      status: "ambiguous",
      serverIds: ["git-hub-id", "git-hub_id"],
    });
    expect(resolveMcpToolResource(["git.hub"], "mcp__git_hub__search")).toEqual({
      status: "unresolved",
      reason: "unknown_server",
    });
    expect(resolveMcpToolResource(["git.hub"], "MCP:git.hub:search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search", parentId: "git.hub" },
    });
    expect(resolveMcpToolResource(["git-hub"], "mcp__other_server__search")).toEqual({
      status: "unresolved",
      reason: "unknown_server",
    });
    expect(resolveMcpToolResource(["git-hub"], "read_file")).toEqual({
      status: "unresolved",
      reason: "unrecognized_tool_name",
    });
  });
});
