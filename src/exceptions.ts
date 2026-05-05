// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

const MAX_PROMPT_DISPLAY_LEN = 100;

export interface MalformedInputDetails {
  field?: string;
  inputIndex?: number;
  charOffset?: number;
  malformedToken?: string;
  codePoint?: string;
  reason?: string;
}

export class PromptBlockedException extends Error {
  readonly score: number;
  readonly threshold: number;
  readonly promptText: string;
  readonly runId: string | undefined;

  constructor(params: {
    score: number;
    threshold: number;
    promptText: string;
    runId?: string;
  }) {
    super(PromptBlockedException.formatMessage(params));
    this.name = "PromptBlockedException";
    this.score = params.score;
    this.threshold = params.threshold;
    this.promptText = params.promptText;
    this.runId = params.runId;
    Object.setPrototypeOf(this, PromptBlockedException.prototype);
  }

  private static formatMessage(params: {
    score: number;
    threshold: number;
    promptText: string;
  }): string {
    const truncated =
      params.promptText.length > MAX_PROMPT_DISPLAY_LEN
        ? `${params.promptText.slice(0, MAX_PROMPT_DISPLAY_LEN)}...`
        : params.promptText;
    return (
      `Prompt blocked by Silmaril Firewall ` +
      `(score=${params.score.toFixed(4)}, threshold=${params.threshold.toFixed(4)}): ` +
      `'${truncated}'`
    );
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
    super(`Silmaril API error ${params.status} ${params.statusText}: ${params.body}`);
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
