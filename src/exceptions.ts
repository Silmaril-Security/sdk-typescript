// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type { HookLabel } from "./hooks.js";
import type { BlockResult, ReviewLevel } from "./types.js";

const MAX_PROMPT_DISPLAY_LEN = 100;

export interface MalformedInputDetails {
  field?: string;
  inputIndex?: number;
  charOffset?: number;
  malformedToken?: string;
  codePoint?: string;
  reason?: string;
}

export class FirewallBlockedException extends Error {
  readonly score: number;
  readonly threshold: number;
  readonly promptText: string;
  readonly runId: string | undefined;
  readonly hook: HookLabel | undefined;
  readonly toolName: string | undefined;
  readonly toolCallId: string | undefined;
  readonly result: BlockResult | undefined;

  constructor(params: {
    score: number;
    threshold: number;
    promptText: string;
    runId?: string;
    hook?: HookLabel;
    toolName?: string;
    toolCallId?: string;
    result?: BlockResult;
  }) {
    super(FirewallBlockedException.formatMessage(params));
    this.name = "FirewallBlockedException";
    this.score = params.score;
    this.threshold = params.threshold;
    this.promptText = params.promptText;
    this.runId = params.runId;
    this.hook = params.hook;
    this.toolName = params.toolName;
    this.toolCallId = params.toolCallId;
    this.result = params.result;
    Object.setPrototypeOf(this, FirewallBlockedException.prototype);
  }

  private static formatMessage(params: {
    score: number;
    threshold: number;
    promptText: string;
    result?: BlockResult;
  }): string {
    const truncated =
      params.promptText.length > MAX_PROMPT_DISPLAY_LEN
        ? `${params.promptText.slice(0, MAX_PROMPT_DISPLAY_LEN)}...`
        : params.promptText;
    if (
      params.result?.prediction !== "MALICIOUS" &&
      params.result?.governance?.action === "block"
    ) {
      return `Request blocked by Silmaril Firewall governance policy: '${truncated}'`;
    }
    return (
      `Request blocked by Silmaril Firewall ` +
      `(score=${params.score.toFixed(4)}, threshold=${params.threshold.toFixed(4)}): ` +
      `'${truncated}'`
    );
  }
}

/** @deprecated Use FirewallBlockedException instead. */
export const PromptBlockedException = FirewallBlockedException;
/** @deprecated Use FirewallBlockedException instead. */
export type PromptBlockedException = FirewallBlockedException;

const REVIEW_COMPATIBILITY_ERROR_BRAND = Symbol.for(
  "@silmaril-security/sdk/ReviewCompatibilityError",
);

export class ReviewCompatibilityError extends Error {
  readonly requestedReview: ReviewLevel;
  readonly acknowledgedReview: unknown;

  constructor(requestedReview: ReviewLevel, acknowledgedReview: unknown) {
    const detail = acknowledgedReview === undefined
      ? "the response omitted its acknowledgement"
      : "the response acknowledgement did not match";
    super(`Silmaril review compatibility error: ${detail} for requested ${requestedReview} review`);
    this.name = "ReviewCompatibilityError";
    this.requestedReview = requestedReview;
    this.acknowledgedReview = acknowledgedReview;
    Object.defineProperty(this, REVIEW_COMPATIBILITY_ERROR_BRAND, {
      value: true,
      enumerable: false,
      configurable: false,
      writable: false,
    });
    Object.setPrototypeOf(this, ReviewCompatibilityError.prototype);
  }
}

export function isReviewCompatibilityError(error: unknown): error is ReviewCompatibilityError {
  if ((typeof error !== "object" && typeof error !== "function") || error === null) {
    return false;
  }
  try {
    return Object.getOwnPropertyDescriptor(
      error,
      REVIEW_COMPATIBILITY_ERROR_BRAND,
    )?.value === true;
  } catch {
    return false;
  }
}

export class SilmarilApiError extends Error {
  readonly status: number;
  readonly statusText: string;
  readonly body: string;
  readonly details: MalformedInputDetails | undefined;
  readonly error: string | undefined;
  readonly apiMessage: string | undefined;

  constructor(params: {
    status: number;
    statusText: string;
    body: string;
    details?: MalformedInputDetails;
    error?: string;
    apiMessage?: string;
  }) {
    const statusText = params.statusText ? ` ${params.statusText}` : "";
    super(`Silmaril API error ${params.status}${statusText}`);
    this.name = "SilmarilApiError";
    this.status = params.status;
    this.statusText = params.statusText;
    this.body = params.body;
    const parsed = parseErrorBody(params.body);
    this.details = params.details ?? parsed.details;
    this.error = params.error ?? parsed.error;
    this.apiMessage = params.apiMessage ?? parsed.apiMessage;
    Object.setPrototypeOf(this, SilmarilApiError.prototype);
  }
}

function parseErrorBody(body: string): {
  details: MalformedInputDetails | undefined;
  error: string | undefined;
  apiMessage: string | undefined;
} {
  try {
    const parsed = JSON.parse(body) as unknown;
    if (!parsed || typeof parsed !== "object") {
      return { details: undefined, error: undefined, apiMessage: undefined };
    }
    const data = parsed as Record<string, unknown>;
    return {
      details:
        data.details && typeof data.details === "object"
          ? (data.details as MalformedInputDetails)
          : undefined,
      error: typeof data.error === "string" ? data.error : undefined,
      apiMessage: typeof data.message === "string" ? data.message : undefined,
    };
  } catch {
    return { details: undefined, error: undefined, apiMessage: undefined };
  }
}
