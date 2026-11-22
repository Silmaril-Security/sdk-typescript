// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

export type WireDecision = Readonly<Record<string, unknown>>;

const EMPTY_DECISION = {
  source: null,
  confidence: null,
  severity: null,
  outcome: null,
  governance: null,
  model_id: null,
};

export function allowed(fields: WireDecision = {}): WireDecision {
  return { action: "allow", ...EMPTY_DECISION, ...fields };
}

export function blocked(fields: WireDecision = {}): WireDecision {
  return { action: "block", ...EMPTY_DECISION, source: "model", ...fields };
}

export function decisions(...results: readonly WireDecision[]): { results: readonly WireDecision[] } {
  return { results };
}
