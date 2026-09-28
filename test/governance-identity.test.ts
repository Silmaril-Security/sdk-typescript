// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import {
  Firewall,
  resolveMcpToolResource,
  type ConcreteGovernanceResource,
  type McpDispatchCatalog,
} from "../src/index.js";

const API_URL = "https://api.test.invalid/classify";
const CONTRACT_DIR = resolve(process.cwd(), "contracts/governance/v1");

interface ContractServer {
  readonly id: string;
  readonly aliases?: readonly string[];
}

interface ContractTool {
  readonly id: string;
  readonly parent_id: string;
}

interface ContractResource {
  readonly kind: "mcp_tool";
  readonly id: string;
  readonly parent_id: string;
}

interface DispatchCase {
  readonly name: string;
  readonly raw_name: string;
  readonly authoritative_resource?: ContractResource;
  readonly catalog: {
    readonly servers: readonly ContractServer[];
    readonly tools?: readonly ContractTool[];
  };
  readonly result: ContractResource | null;
  readonly failure: "ambiguous" | "unresolved" | null;
}

interface PolicyCase {
  readonly name: string;
  readonly selector: { readonly kind?: string } | null;
  readonly actual: { readonly kind?: string } | null;
  readonly matches: boolean;
}

function contractJson<T>(fileName: string): T {
  return JSON.parse(readFileSync(resolve(CONTRACT_DIR, fileName), "utf8")) as T;
}

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
    const sums = readFileSync(resolve(CONTRACT_DIR, "SHA256SUMS"), "utf8").trim().split("\n");
    for (const line of sums) {
      const [expected, file] = line.split(/\s+/u);
      const actual = createHash("sha256")
        .update(readFileSync(resolve(CONTRACT_DIR, file!)))
        .digest("hex");
      expect(actual, file).toBe(expected);
    }
  });

  it("reads seven-kind policy vectors without evaluating Firewall matching", () => {
    const schema = contractJson<{
      properties: { kind: { enum: readonly string[] } };
    }>("resource.schema.json");
    const matching = contractJson<{ cases: readonly PolicyCase[] }>("matching.json");
    const seen = new Set<string>();
    for (const policyCase of matching.cases) {
      if (policyCase.selector?.kind !== undefined) {
        seen.add(policyCase.selector.kind);
      }
      if (policyCase.actual?.kind !== undefined) {
        seen.add(policyCase.actual.kind);
      }
      expect(typeof policyCase.matches).toBe("boolean");
    }
    expect([...seen].sort()).toEqual([...schema.properties.kind.enum].sort());
    // Selector wildcards, mcp_server inheritance, and specificity stay in
    // Firewall. This client validates concrete refs and resolves dispatch names.
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

  it("sends an explicit canonical resource unchanged when the raw name is ambiguous", async () => {
    let body: Record<string, unknown> | undefined;
    globalThis.fetch = (async (_url, init) => {
      body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return response({ prediction: "BENIGN", score: 0, threshold: 0.5 });
    }) as typeof fetch;
    const firewall = new Firewall({ apiKey: "test", apiUrl: API_URL });

    await firewall.classify("search papers", {
      toolName: "mcp__git_hub__search",
      resource: { kind: "mcp_tool", id: "search", parentId: "git-hub" },
    });

    expect(body).toMatchObject({
      tool_name: "mcp__git_hub__search",
      resource: { kind: "mcp_tool", id: "search", parent_id: "git-hub" },
    });
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
  it("supports mcp__ and MCP: spellings when one canonical parent matches", () => {
    expect(resolveMcpToolResource(["git_hub", "git_hub"], "mcp__git_hub__search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search", parentId: "git_hub" },
    });
    expect(resolveMcpToolResource(["github"], "MCP:github:create_issue")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "create_issue", parentId: "github" },
    });
  });

  it("treats an exact spelling and a distinct host alias as ambiguous", () => {
    expect(resolveMcpToolResource(["git-hub", "git_hub"], "mcp__git_hub__search")).toEqual({
      status: "ambiguous",
      serverIds: ["git-hub", "git_hub"],
    });
    expect(resolveMcpToolResource(["git-hub", "git_hub"], "MCP:git_hub:search")).toEqual({
      status: "ambiguous",
      serverIds: ["git-hub", "git_hub"],
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

  it("splits on the first delimiter and keeps later delimiter characters in the tool id", () => {
    expect(resolveMcpToolResource(["github"], "mcp__github__search__more")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search__more", parentId: "github" },
    });
    expect(resolveMcpToolResource(["github"], "MCP:github:search:more")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search:more", parentId: "github" },
    });
  });

  it("leaves long delimiter runs and incomplete dispatch names unresolved", () => {
    const configured = ["github", "git-hub"];
    const unrecognized = { status: "unresolved", reason: "unrecognized_tool_name" } as const;
    const repeatedDelimiters = "__".repeat(20_000);

    expect(resolveMcpToolResource(configured, `mcp__${"a_".repeat(20_000)}search`)).toEqual(
      unrecognized,
    );
    expect(resolveMcpToolResource(configured, `MCP:${":".repeat(20_000)}search`)).toEqual(
      unrecognized,
    );
    expect(resolveMcpToolResource(configured, `mcp__${"_".repeat(20_000)}search`)).toEqual({
      status: "unresolved",
      reason: "unknown_server",
    });
    expect(resolveMcpToolResource(configured, `mcp__github__search${repeatedDelimiters}`)).toEqual({
      status: "resolved",
      resource: {
        kind: "mcp_tool",
        id: `search${repeatedDelimiters}`,
        parentId: "github",
      },
    });

    for (const toolName of [
      "mcp____search",
      "mcp__github__",
      "MCP::search",
      "MCP:github:",
      "mcp__git\nhub__search",
      "mcp__github__search\n",
      "mcp__github__search\r",
      "MCP:github:sea\nrch",
      "MCP:github:search\n",
    ]) {
      expect(resolveMcpToolResource(configured, toolName)).toEqual(unrecognized);
    }

    expect(resolveMcpToolResource(["git\nhub"], "MCP:git\nhub:search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search", parentId: "git\nhub" },
    });
  });

  it("merges aliases repeated for one server and still collides across servers", () => {
    expect(resolveMcpToolResource({
      servers: [
        { id: "git", aliases: ["origin"] },
        { id: "git", aliases: ["docs"] },
      ],
      tools: [{ id: "search", parentId: "git" }],
    }, "mcp__docs__search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search", parentId: "git" },
    });
    expect(resolveMcpToolResource({
      servers: [
        { id: "git", aliases: ["shared"] },
        { id: "hub", aliases: ["shared"] },
      ],
      tools: [
        { id: "search", parentId: "git" },
        { id: "search", parentId: "hub" },
      ],
    }, "mcp__shared__search")).toEqual({
      status: "ambiguous",
      serverIds: ["git", "hub"],
    });
    expect(resolveMcpToolResource({
      servers: [{ id: "git" }],
    }, "mcp__git__hub__search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "hub__search", parentId: "git" },
    });
  });

  it("uses a configured server id that itself contains the dispatch separator", () => {
    expect(resolveMcpToolResource(["prod__west"], "mcp__prod__west__search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search", parentId: "prod__west" },
    });
    expect(resolveMcpToolResource(["prod:west"], "MCP:prod:west:search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "search", parentId: "prod:west" },
    });
    expect(resolveMcpToolResource(["prod"], "mcp__prod__west__search")).toEqual({
      status: "resolved",
      resource: { kind: "mcp_tool", id: "west__search", parentId: "prod" },
    });
  });

  it("reports overlapping exact and alias prefixes as ambiguous", () => {
    expect(
      resolveMcpToolResource(["prod", "prod__west", "prod_west"], "mcp__prod__west__search"),
    ).toEqual({
      status: "ambiguous",
      serverIds: ["prod", "prod__west"],
    });
    expect(
      resolveMcpToolResource(["prod", "prod:west", "prod-west"], "MCP:prod:west:search"),
    ).toEqual({
      status: "ambiguous",
      serverIds: ["prod", "prod:west"],
    });
    expect(resolveMcpToolResource(["prod_west", "prod-west"], "mcp__prod_west__search")).toEqual({
      status: "ambiguous",
      serverIds: ["prod-west", "prod_west"],
    });
    expect(
      resolveMcpToolResource(["foo-bar__baz", "foo_bar-_baz"], "mcp__foo_bar__baz__tool"),
    ).toEqual({
      status: "ambiguous",
      serverIds: ["foo-bar__baz", "foo_bar-_baz"],
    });
  });

  it("keeps long separator-bearing names unresolved when no configured prefix fits", () => {
    const repeated = "prod__west__".repeat(5_000);
    expect(resolveMcpToolResource(["github"], `mcp__${repeated}search`)).toEqual({
      status: "unresolved",
      reason: "unknown_server",
    });
    expect(resolveMcpToolResource(["prod__west"], `mcp__prod__west__search${repeated}`)).toEqual({
      status: "resolved",
      resource: {
        kind: "mcp_tool",
        id: `search${repeated}`,
        parentId: "prod__west",
      },
    });
    expect(resolveMcpToolResource(["prod__west"], "mcp__prod__west__")).toEqual({
      status: "unresolved",
      reason: "unknown_server",
    });
    expect(resolveMcpToolResource(["prod:west"], "MCP:prod:west:")).toEqual({
      status: "unresolved",
      reason: "unknown_server",
    });
    expect(resolveMcpToolResource(["prod__west"], "mcp__\nprod__west__search")).toEqual({
      status: "unresolved",
      reason: "unrecognized_tool_name",
    });
  });

  const dispatchCases = contractJson<{
    mcp_dispatch_cases: readonly DispatchCase[];
  }>("matching.json").mcp_dispatch_cases;

  it("covers every final dispatch vector", () => {
    expect(dispatchCases).toHaveLength(19);
  });

  it.each(dispatchCases.map((dispatchCase) => [dispatchCase.name, dispatchCase] as const))(
    "dispatch vector: %s",
    async (_name, dispatchCase) => {
      const catalog = toDispatchCatalog(dispatchCase);
      const resolution = resolveMcpToolResource(catalog, dispatchCase.raw_name);

      if (dispatchCase.authoritative_resource !== undefined) {
        expect(resolution.status).toBe("ambiguous");
        expect(dispatchCase.result).toEqual(dispatchCase.authoritative_resource);
        const originalFetch = globalThis.fetch;
        let body: Record<string, unknown> | undefined;
        globalThis.fetch = (async (_url, init) => {
          body = JSON.parse(String(init?.body)) as Record<string, unknown>;
          return response({ prediction: "BENIGN", score: 0, threshold: 0.5 });
        }) as typeof fetch;
        try {
          const firewall = new Firewall({ apiKey: "test", apiUrl: API_URL });
          const authoritative = dispatchCase.authoritative_resource;
          await firewall.classify("search papers", {
            toolName: dispatchCase.raw_name,
            resource: {
              kind: authoritative.kind,
              id: authoritative.id,
              parentId: authoritative.parent_id,
            },
          });
          expect(body).toMatchObject({
            tool_name: dispatchCase.raw_name,
            resource: {
              kind: authoritative.kind,
              id: authoritative.id,
              parent_id: authoritative.parent_id,
            },
          });
        } finally {
          globalThis.fetch = originalFetch;
        }
        return;
      }

      if (dispatchCase.result !== null) {
        expect(resolution).toEqual({
          status: "resolved",
          resource: {
            kind: dispatchCase.result.kind,
            id: dispatchCase.result.id,
            parentId: dispatchCase.result.parent_id,
          },
        });
        return;
      }
      if (dispatchCase.failure === "ambiguous") {
        expect(resolution.status).toBe("ambiguous");
        return;
      }
      expect(resolution.status).toBe("unresolved");
      expect(dispatchCase.failure).toBe("unresolved");
    },
  );
});

function toDispatchCatalog(dispatchCase: DispatchCase): McpDispatchCatalog {
  const servers = dispatchCase.catalog.servers.map((server) =>
    server.aliases === undefined
      ? { id: server.id }
      : { id: server.id, aliases: server.aliases },
  );
  if (dispatchCase.catalog.tools === undefined) {
    return { servers };
  }
  return {
    servers,
    tools: dispatchCase.catalog.tools.map((tool) => ({
      id: tool.id,
      parentId: tool.parent_id,
    })),
  };
}
