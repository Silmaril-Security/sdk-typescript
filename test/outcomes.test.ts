// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.

import { describe, expect, it } from "vitest";
import {
  HARMFUL_OUTCOMES,
  isHarmfulOutcome,
  isPrimaryOutcome,
  normalizeHarmfulOutcomeMap,
  normalizePrimaryOutcome,
  Outcome,
  OUTCOME_DESCRIPTIONS,
  PRIMARY_OUTCOMES,
} from "../src/index.js";

describe("outcomes", () => {
  it("exports ordered primary and harmful outcome taxonomy", () => {
    expect(PRIMARY_OUTCOMES).toEqual([
      Outcome.Benign,
      Outcome.InformationDisclosure,
      Outcome.SecretExposure,
      Outcome.ControlAbuse,
      Outcome.SystemCompromise,
      Outcome.ServiceDisruption,
    ]);
    expect(HARMFUL_OUTCOMES).toEqual(PRIMARY_OUTCOMES.slice(1));
    for (const outcome of PRIMARY_OUTCOMES) {
      expect(OUTCOME_DESCRIPTIONS[outcome]).toBeTruthy();
      expect(isPrimaryOutcome(outcome)).toBe(true);
    }
  });

  it("validates primary and harmful outcomes", () => {
    expect(normalizePrimaryOutcome(Outcome.Benign)).toBe(Outcome.Benign);
    expect(normalizePrimaryOutcome("data_exfiltration")).toBe("data_exfiltration");
    expect(isHarmfulOutcome(Outcome.SecretExposure)).toBe(true);
    expect(isHarmfulOutcome(Outcome.Benign)).toBe(false);
    expect(isPrimaryOutcome(42)).toBe(false);
    expect(isHarmfulOutcome("data_exfiltration")).toBe(false);
    expect(() => normalizePrimaryOutcome(42)).toThrow(/invalid primary_outcome/);
  });

  it("normalizes harmful outcome maps", () => {
    expect(
      normalizeHarmfulOutcomeMap(
        {
          [Outcome.SecretExposure]: 0.9,
          [Outcome.SystemCompromise]: 0.7,
        },
        "outcome_scores",
      ),
    ).toEqual({
      [Outcome.SecretExposure]: 0.9,
      [Outcome.SystemCompromise]: 0.7,
    });
    expect(normalizeHarmfulOutcomeMap({ data_exfiltration: 1 }, "outcome_scores")).toEqual({
      data_exfiltration: 1,
    });
    expect(() =>
      normalizeHarmfulOutcomeMap({ [Outcome.Benign]: 1 }, "outcome_scores"),
    ).toThrow(/invalid outcome_scores key/);
    expect(() =>
      normalizeHarmfulOutcomeMap({ [Outcome.Benign]: "high" }, "outcome_scores"),
    ).toThrow(/invalid outcome_scores key/);
    expect(() =>
      normalizeHarmfulOutcomeMap({ [Outcome.SecretExposure]: "high" }, "outcome_scores"),
    ).toThrow(/invalid outcome_scores value/);
  });
});
