// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

export {
  Firewall,
  DEFAULT_TIMEOUT_MS,
} from "./firewall.js";

export {
  FirewallBlockedException,
  PromptBlockedException,
  ReviewCompatibilityError,
  SilmarilApiError,
} from "./exceptions.js";
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
  HARMFUL_OUTCOMES,
  OUTCOME_DESCRIPTIONS,
  isHarmfulOutcome,
} from "./outcomes.js";

export type {
  KnownHarmfulOutcome,
} from "./outcomes.js";

export type {
  BlockResult,
  ClassifyEvent,
  FirewallAction,
  Confidence,
  Severity,
  FirewallMode,
  ReviewLevel,
  GovernanceAction,
  GovernanceResourceKind,
  GovernanceResource,
  GovernanceContext,
  GovernanceDecision,
  ClassificationMetadata,
  FirewallOptions,
  ClassifyOptions,
  ClassifyBatchOptions,
  ProtectOptions,
  LangChainAdapterOptions,
  LangChainFirewallHandler,
  MiddlewareOptions,
} from "./types.js";
