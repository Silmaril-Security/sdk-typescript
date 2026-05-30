// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

export {
  Firewall,
  DEFAULT_CHUNK_CONCURRENCY,
  DEFAULT_TIMEOUT_MS,
} from "./firewall.js";

export { FirewallBlockedException, PromptBlockedException, SilmarilApiError } from "./exceptions.js";
export type { MalformedInputDetails } from "./exceptions.js";

export type { FirewallMiddleware } from "./adapters/vercel.js";

export {
  chunkText,
  sanitizeText,
  MAX_INPUT_TOKENS,
  CHUNK_WINDOW,
  CHUNK_OVERLAP,
  MAX_INPUT_CHARS,
  SERVER_SINGLE_TEXT_MAX_CHARS,
  CHUNK_WINDOW_CHARS,
  CHUNK_OVERLAP_CHARS,
} from "./chunking.js";

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

export type {
  BlockResult,
  ClassifyEvent,
  Prediction,
  ClassificationMetadata,
  FirewallOptions,
  ClassifyOptions,
  ClassifyBatchOptions,
  LangChainAdapterOptions,
  LangChainFirewallHandler,
  MiddlewareOptions,
} from "./types.js";
