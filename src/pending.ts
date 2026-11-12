// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

/** Classifications that run beside the host flow and are joined at a later boundary. */

import { AsyncLocalStorage } from "node:async_hooks";

export const DEFAULT_MAX_CONCURRENT = 32;
export const DEFAULT_MAX_QUEUED = 64;
const BACKGROUND_RETRIES = 1;
const retryLimit = new AsyncLocalStorage<number>();

/** Retries allowed for the current request; background classifications retry once. */
export function retryBudget(maxRetries: number): number {
  return Math.min(maxRetries, retryLimit.getStore() ?? maxRetries);
}

export function conversationId(metadata: Readonly<Record<string, unknown>> | undefined): string | undefined {
  const value = metadata?.conversationId;
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function validateLimit(name: string, value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`Firewall: ${name} must be a positive integer, got ${value}`);
  }
  return value;
}

/** Sends classifications for one conversation in the order they were started. */
export class PendingVerdicts {
  private readonly tails = new Map<string, Promise<unknown>>();
  private readonly depths = new Map<string, number>();
  private readonly outstanding = new Set<Promise<unknown>>();
  private readonly waiting: Array<() => void> = [];
  private running = 0;

  constructor(
    private readonly maxConcurrent: number,
    private readonly maxQueued: number,
  ) {}

  /** Start a classification the caller joins by awaiting the returned promise. */
  submit<T>(call: () => Promise<T>, conversation?: string): Promise<T> {
    const pending = this.start(call, conversation);
    pending.catch(() => undefined);
    return pending;
  }

  /** Start a classification nobody joins; failures are reported, never thrown. */
  observe<T>(call: () => Promise<T>, conversation?: string): Promise<T | undefined> {
    if (conversation !== undefined && (this.depths.get(conversation) ?? 0) >= this.maxQueued) {
      // eslint-disable-next-line no-console
      console.warn("silmaril.firewall: dropped background classification: conversation queue is full");
      return Promise.resolve(undefined);
    }
    return this.start(() => retryLimit.run(BACKGROUND_RETRIES, call), conversation).catch((error: unknown) => {
      // eslint-disable-next-line no-console
      console.warn("silmaril.firewall: background classification failed", error);
      return undefined;
    });
  }

  /** Wait until every classification started so far has finished. */
  async drain(): Promise<void> {
    while (this.outstanding.size > 0) {
      await Promise.allSettled([...this.outstanding]);
    }
  }

  private start<T>(call: () => Promise<T>, conversation: string | undefined): Promise<T> {
    const previous = conversation === undefined ? undefined : this.tails.get(conversation);
    const pending = this.run(call, previous);
    this.outstanding.add(pending);
    if (conversation !== undefined) {
      this.tails.set(conversation, pending);
      this.depths.set(conversation, (this.depths.get(conversation) ?? 0) + 1);
    }
    const finish = (): void => {
      this.outstanding.delete(pending);
      if (conversation === undefined) {
        return;
      }
      const depth = (this.depths.get(conversation) ?? 1) - 1;
      if (depth > 0) {
        this.depths.set(conversation, depth);
      } else {
        this.depths.delete(conversation);
      }
      if (this.tails.get(conversation) === pending) {
        this.tails.delete(conversation);
      }
    };
    pending.then(finish, finish);
    return pending;
  }

  private async run<T>(call: () => Promise<T>, previous: Promise<unknown> | undefined): Promise<T> {
    if (previous !== undefined) {
      await previous.catch(() => undefined);
    }
    if (this.running >= this.maxConcurrent) {
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    } else {
      this.running++;
    }
    try {
      return await call();
    } finally {
      const next = this.waiting.shift();
      if (next) {
        next();
      } else {
        this.running--;
      }
    }
  }
}

/** Run an operation beside its check and discard the result when the check fails. */
export async function alongside<T>(
  check: Promise<unknown>,
  run: () => PromiseLike<T>,
  discard: (result: T) => void = () => undefined,
): Promise<T> {
  const running = Promise.resolve().then(run);
  try {
    const [result] = await Promise.all([running, check]);
    return result;
  } catch (error) {
    running.then(discard, () => undefined);
    throw error;
  }
}

interface DeferredVerdict {
  readonly promise: Promise<unknown>;
  failed: boolean;
  failure: unknown;
}

/** Pending verdicts grouped by the execution that must join them. */
export class Deferred {
  private readonly scopes = new Map<string, DeferredVerdict[]>();

  add(scope: string, promise: Promise<unknown>): void {
    const verdict: DeferredVerdict = { promise, failed: false, failure: undefined };
    promise.catch((error: unknown) => {
      verdict.failed = true;
      verdict.failure = error;
    });
    const verdicts = this.scopes.get(scope) ?? [];
    verdicts.push(verdict);
    this.scopes.set(scope, verdicts);
  }

  /** Remove and return every verdict the scope still has to join. */
  take(scope: string): Promise<unknown>[] {
    const verdicts = this.scopes.get(scope) ?? [];
    this.scopes.delete(scope);
    return verdicts.map((verdict) => verdict.promise);
  }

  /** Throw the failure of a verdict that has already landed, without waiting for the rest. */
  check(scope: string): void {
    const landed = this.scopes.get(scope)?.find((verdict) => verdict.failed);
    if (landed !== undefined) {
      this.scopes.delete(scope);
      throw landed.failure;
    }
  }
}
