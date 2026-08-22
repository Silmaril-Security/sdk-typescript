// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

export {
  Firewall,
  DEFAULT_TIMEOUT_MS,
} from "./firewall.js";

export { FirewallBlockedException, PromptBlockedException, SilmarilApiError } from "./exceptions.js";
export type { MalformedInputDetails } from "./exceptions.js";

export type { FirewallMiddleware } from "./adapters/vercel.js";

export {
  HookLabel,
  FirewallHook,
  DEFAULT_HOOKS,
  INPUT_HOOKS,
  OUTPUT_HOOKS,
  ALL_HOOKS,
  FIREWALL_HOOK_TO_LABEL,
  resolveHooks,
  prependHook,
  prependToolName,
} from "./hooks.js";

export {
  Outcome,
  PRIMARY_OUTCOMES,
  HARMFUL_OUTCOMES,
  OUTCOME_DESCRIPTIONS,
  isPrimaryOutcome,
  isHarmfulOutcome,
  normalizePrimaryOutcome,
  normalizeHarmfulOutcome,
  normalizeHarmfulOutcomeMap,
} from "./outcomes.js";

export type {
  KnownPrimaryOutcome,
  KnownHarmfulOutcome,
  PrimaryOutcome,
  HarmfulOutcome,
  UnknownOutcome,
} from "./outcomes.js";

export type {
  BlockResult,
  ClassifyEvent,
  Prediction,
  FirewallMode,
  ClassificationMetadata,
  FirewallOptions,
  ClassifyOptions,
  ClassifyBatchOptions,
  LangChainAdapterOptions,
  LangChainFirewallHandler,
  MiddlewareOptions,
} from "./types.js";
