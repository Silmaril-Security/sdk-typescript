// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { describe, expect, it } from "vitest";
import {
  HARMFUL_OUTCOMES,
  isHarmfulOutcome,
  Outcome,
  OUTCOME_DESCRIPTIONS,
} from "../src/index.js";

describe("outcomes", () => {
  it("exports the ordered harmful outcome taxonomy", () => {
    expect(HARMFUL_OUTCOMES).toEqual([
      Outcome.InformationDisclosure,
      Outcome.SecretExposure,
      Outcome.ControlAbuse,
      Outcome.SystemCompromise,
      Outcome.ServiceDisruption,
      Outcome.CodeGeneration,
      Outcome.StoryScriptGeneration,
      Outcome.GameGeneration,
      Outcome.WebsiteGeneration,
      Outcome.ClickUpTermsViolation,
      Outcome.TraditionalAiAbuse,
    ]);
    expect(HARMFUL_OUTCOMES).toEqual(Object.values(Outcome));
    expect(Object.keys(OUTCOME_DESCRIPTIONS)).toEqual(HARMFUL_OUTCOMES);
    for (const outcome of HARMFUL_OUTCOMES) {
      expect(OUTCOME_DESCRIPTIONS[outcome]).toBeTruthy();
      expect(isHarmfulOutcome(outcome)).toBe(true);
    }
  });

  it("has no benign outcome", () => {
    expect(Outcome).not.toHaveProperty("Benign");
    expect(isHarmfulOutcome("benign")).toBe(false);
    expect(OUTCOME_DESCRIPTIONS).not.toHaveProperty("benign");
  });

  it("recognizes only known harmful outcomes", () => {
    expect(isHarmfulOutcome(Outcome.SecretExposure)).toBe(true);
    expect(isHarmfulOutcome("data_exfiltration")).toBe(false);
    expect(isHarmfulOutcome(42)).toBe(false);
    expect(isHarmfulOutcome(undefined)).toBe(false);
  });
});
