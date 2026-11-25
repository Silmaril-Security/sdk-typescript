// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { adaptVersion1Response, blockResultsFromResponse } from "../src/firewall.js";
import type { BlockResult, GovernanceDecision, ReviewLevel } from "../src/index.js";

interface WireGovernance {
  readonly action: "allow" | "block";
  readonly rule_id: string;
  readonly policy_version: string;
  readonly identity_revision: string;
  readonly resource: {
    readonly kind: "mcp_tool";
    readonly id: string;
    readonly parent_id: string;
  };
}

interface WireDecision {
  readonly action: "allow" | "block";
  readonly source: string | null;
  readonly confidence: string | null;
  readonly severity: string | null;
  readonly outcome: string | null;
  readonly governance: WireGovernance | null;
  readonly model_id: string | null;
}

interface WireResponse {
  readonly results: readonly WireDecision[];
  readonly review?: ReviewLevel;
}

interface ContractCase {
  readonly name: string;
  readonly v1: unknown;
  readonly v2: WireResponse;
  readonly adapted: WireResponse;
}

const CONTRACT = new URL("./contracts/classify/v2/", import.meta.url);
const CASES_BYTES = readFileSync(new URL("cases.json", CONTRACT));
const CASES = JSON.parse(CASES_BYTES.toString("utf8")) as readonly ContractCase[];

function expectedGovernance(governance: WireGovernance): GovernanceDecision {
  return {
    action: governance.action,
    ruleId: governance.rule_id,
    policyVersion: governance.policy_version,
    identityRevision: governance.identity_revision,
    resource: {
      kind: governance.resource.kind,
      id: governance.resource.id,
      parentId: governance.resource.parent_id,
    },
  };
}

function expectedResults(response: WireResponse): BlockResult[] {
  return response.results.map(({ action, governance, model_id: modelId, ...evidence }) => ({
    action,
    ...Object.fromEntries(Object.entries(evidence).filter(([, value]) => value !== null)),
    ...(governance === null ? {} : { governance: expectedGovernance(governance) }),
    ...(modelId === null ? {} : { modelId }),
    ...(response.review === undefined ? {} : { review: response.review }),
  }));
}

function parse(response: WireResponse): BlockResult[] {
  return blockResultsFromResponse(response, response.results.length, undefined, response.review);
}

describe("classify contract 2.0.0", () => {
  it("vendors cases.json with the digest pinned by SHA256SUMS", () => {
    const pinned = new Map(
      readFileSync(new URL("SHA256SUMS", CONTRACT), "utf8")
        .trim()
        .split("\n")
        .map((line) => line.split(/\s+/).reverse() as [string, string]),
    );

    expect(createHash("sha256").update(CASES_BYTES).digest("hex")).toBe(pinned.get("cases.json"));
  });

  it("covers uniquely named cases", () => {
    expect(CASES.length).toBeGreaterThan(0);
    expect(new Set(CASES.map((entry) => entry.name)).size).toBe(CASES.length);
  });

  it("adapts a MALICIOUS prediction over a BENIGN model label to a governance block", () => {
    expect(adaptVersion1Response({
      prediction: "MALICIOUS",
      model_prediction: "BENIGN",
      primary_outcome: "benign",
      outcome_scores: {},
      score: 0,
      threshold: 0.5,
    })).toStrictEqual({
      results: [{
        action: "block",
        source: "governance",
        confidence: null,
        severity: null,
        outcome: null,
        governance: null,
        model_id: null,
      }],
    });
  });

  it("pins a model identifier on every vendored result", () => {
    const results = CASES.flatMap(({ v2, adapted }) => [...v2.results, ...adapted.results]);

    expect(results.length).toBeGreaterThan(0);
    expect(results.every((result) => typeof result.model_id === "string")).toBe(true);
  });

  describe.each(CASES)("$name", ({ v1, v2, adapted }) => {
    it("parses the version 2 body into its decisions", () => {
      const results = parse(v2);

      expect(results).toStrictEqual(expectedResults(v2));
      expect(results.map((result) => result.action !== "allow")).toEqual(
        v2.results.map((decision) => decision.action === "block"),
      );
    });

    it("adapts the version 1 body to the adapted body", () => {
      expect(adaptVersion1Response(v1)).toStrictEqual(adapted);
    });

    it("parses the adapted body into the version 2 decisions without judge evidence", () => {
      const results = parse(adapted);

      expect(results).toStrictEqual(expectedResults(adapted));
      expect(results).toStrictEqual(
        parse(v2).map(({ confidence: _confidence, severity: _severity, ...decision }) => decision),
      );
    });
  });
});
