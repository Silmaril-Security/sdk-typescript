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

declare const unknownOutcomeBrand: unique symbol;

export type KnownPrimaryOutcome = (typeof Outcome)[keyof typeof Outcome];
export type KnownHarmfulOutcome = Exclude<KnownPrimaryOutcome, typeof Outcome.Benign>;
export type UnknownOutcome = string & { readonly [unknownOutcomeBrand]: "UnknownOutcome" };
export type PrimaryOutcome = KnownPrimaryOutcome | UnknownOutcome;
export type HarmfulOutcome = KnownHarmfulOutcome | UnknownOutcome;

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
] as const satisfies readonly KnownHarmfulOutcome[];

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
} as const satisfies Readonly<Record<KnownPrimaryOutcome, string>>;

const PRIMARY_OUTCOME_SET = new Set<string>(PRIMARY_OUTCOMES);
const HARMFUL_OUTCOME_SET = new Set<string>(HARMFUL_OUTCOMES);

export function isPrimaryOutcome(value: unknown): value is KnownPrimaryOutcome {
  return typeof value === "string" && PRIMARY_OUTCOME_SET.has(value);
}

export function isHarmfulOutcome(value: unknown): value is KnownHarmfulOutcome {
  return typeof value === "string" && HARMFUL_OUTCOME_SET.has(value);
}

export function normalizePrimaryOutcome(
  value: unknown,
  fieldName = "primary_outcome",
): PrimaryOutcome {
  if (typeof value !== "string") {
    throw new Error(`Firewall: invalid ${fieldName} ${JSON.stringify(value)}`);
  }
  return isPrimaryOutcome(value) ? value : (value as UnknownOutcome);
}

export function normalizeHarmfulOutcome(
  value: unknown,
  fieldName = "outcome",
): HarmfulOutcome {
  if (typeof value !== "string" || value === Outcome.Benign) {
    throw new Error(`Firewall: invalid ${fieldName} ${JSON.stringify(value)}`);
  }
  return isHarmfulOutcome(value) ? value : (value as UnknownOutcome);
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
    const normalizedKey = normalizeHarmfulOutcome(key, `${fieldName} key`);
    if (typeof value !== "number") {
      throw new Error(`Firewall: invalid ${fieldName} value for ${JSON.stringify(key)}`);
    }
    out[normalizedKey] = value;
  }
  return Object.freeze(out);
}
