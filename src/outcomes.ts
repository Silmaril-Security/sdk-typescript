// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

export const Outcome = {
  Benign: "benign",
  InformationDisclosure: "information_disclosure",
  SecretExposure: "secret_exposure",
  ControlAbuse: "control_abuse",
  SystemCompromise: "system_compromise",
  ServiceDisruption: "service_disruption",
} as const;

export type PrimaryOutcome = (typeof Outcome)[keyof typeof Outcome];
export type HarmfulOutcome = Exclude<PrimaryOutcome, typeof Outcome.Benign>;

export const PRIMARY_OUTCOMES = [
  Outcome.Benign,
  Outcome.InformationDisclosure,
  Outcome.SecretExposure,
  Outcome.ControlAbuse,
  Outcome.SystemCompromise,
  Outcome.ServiceDisruption,
] as const satisfies readonly PrimaryOutcome[];

export const HARMFUL_OUTCOMES = [
  Outcome.InformationDisclosure,
  Outcome.SecretExposure,
  Outcome.ControlAbuse,
  Outcome.SystemCompromise,
  Outcome.ServiceDisruption,
] as const satisfies readonly HarmfulOutcome[];

export const OUTCOME_DESCRIPTIONS = {
  [Outcome.Benign]: "No harmful firewall outcome detected.",
  [Outcome.InformationDisclosure]:
    "Exposes private data, documents, internal context, logs, traces, customer data, SQL rows, topology, or similar non-secret sensitive information.",
  [Outcome.SecretExposure]:
    "Exposes credentials, tokens, API keys, cookies, passwords, signing keys, OAuth secrets, session material, or webhook secrets.",
  [Outcome.ControlAbuse]:
    "Misuses authorized tools or user privileges to send, change, approve, delete, operate, or bypass policy/RBAC without a stronger outcome.",
  [Outcome.SystemCompromise]:
    "Enables privilege escalation, account takeover, hostile integration or plugin takeover, persistence, lateral movement, attacker webhook registration, or code/plugin execution.",
  [Outcome.ServiceDisruption]:
    "Causes downtime, lockout, degradation, alert suppression, destructive loops, resource exhaustion, cost spikes, or hidden outage evidence.",
} as const satisfies Readonly<Record<PrimaryOutcome, string>>;

const PRIMARY_OUTCOME_SET = new Set<string>(PRIMARY_OUTCOMES);
const HARMFUL_OUTCOME_SET = new Set<string>(HARMFUL_OUTCOMES);

export function isPrimaryOutcome(value: string): value is PrimaryOutcome {
  return PRIMARY_OUTCOME_SET.has(value);
}

export function isHarmfulOutcome(value: string): value is HarmfulOutcome {
  return HARMFUL_OUTCOME_SET.has(value);
}

export function normalizePrimaryOutcome(
  value: unknown,
  fieldName = "primary_outcome",
): PrimaryOutcome {
  if (typeof value !== "string" || !isPrimaryOutcome(value)) {
    throw new Error(`Firewall: invalid ${fieldName} ${JSON.stringify(value)}`);
  }
  return value;
}

export function normalizeHarmfulOutcome(
  value: unknown,
  fieldName = "outcome",
): HarmfulOutcome {
  if (typeof value !== "string" || !isHarmfulOutcome(value)) {
    throw new Error(`Firewall: invalid ${fieldName} ${JSON.stringify(value)}`);
  }
  return value;
}

export function normalizeHarmfulOutcomeMap(
  values: unknown,
  fieldName: string,
): Readonly<Partial<Record<HarmfulOutcome, number>>> | undefined {
  if (values === undefined || values === null) {
    return undefined;
  }
  if (typeof values !== "object" || Array.isArray(values)) {
    throw new Error(`Firewall: invalid ${fieldName} ${JSON.stringify(values)}`);
  }
  const out: Partial<Record<HarmfulOutcome, number>> = {};
  for (const [key, value] of Object.entries(values)) {
    if (typeof value !== "number") {
      throw new Error(`Firewall: invalid ${fieldName} value for ${JSON.stringify(key)}`);
    }
    out[normalizeHarmfulOutcome(key, `${fieldName} key`)] = value;
  }
  return Object.freeze(out);
}
