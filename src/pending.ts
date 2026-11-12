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

/** Report a background classification that failed or was not started. */
export function reportBackground(message: string, error?: unknown): void {
  // eslint-disable-next-line no-console
  console.warn(`silmaril.firewall: ${message}`, ...(error === undefined ? [] : [error]));
}

/** Wait for a conversation's earlier classifications, or until the caller aborts. */
function settled(gate: Promise<unknown>, signal: AbortSignal | undefined): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const onAbort = (): void => reject(signal?.reason);
    signal?.addEventListener("abort", onAbort, { once: true });
    void gate.then(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    });
  });
}

/** Sends classifications for one conversation in the order they were started. */
export class PendingVerdicts {
  private readonly gates = new Map<string, Promise<unknown>>();
  private readonly depths = new Map<string, number>();
  private readonly outstanding = new Set<Promise<unknown>>();
  private readonly waiting: Array<() => void> = [];
  private running = 0;
  private background = 0;

  constructor(
    private readonly maxConcurrent: number,
    private readonly maxQueued: number,
  ) {}

  /**
   * Start a classification the caller joins by awaiting the returned promise.
   * An aborted signal stops it waiting for its turn; later classifications keep their order.
   */
  submit<T>(call: () => Promise<T>, conversation?: string, signal?: AbortSignal): Promise<T> {
    const pending = this.start(call, conversation, signal);
    pending.catch(() => undefined);
    return pending;
  }

  /** Start a classification nobody joins; failures are reported, never thrown. */
  observe<T>(call: () => Promise<T>, conversation?: string): Promise<T | undefined> {
    const conversationFull = conversation !== undefined
      && (this.depths.get(conversation) ?? 0) >= this.maxQueued;
    if (conversationFull || this.background >= this.maxConcurrent * this.maxQueued) {
      reportBackground("dropped background classification: queue is full");
      return Promise.resolve(undefined);
    }
    this.background++;
    const pending = this.start(() => retryLimit.run(BACKGROUND_RETRIES, call), conversation, undefined);
    const release = (): void => { this.background--; };
    pending.then(release, release);
    return pending.catch((error: unknown) => {
      reportBackground("background classification failed", error);
      return undefined;
    });
  }

  /** Wait until every classification started so far has finished. */
  async drain(): Promise<void> {
    while (this.outstanding.size > 0) {
      await Promise.allSettled([...this.outstanding]);
    }
  }

  private start<T>(
    call: () => Promise<T>,
    conversation: string | undefined,
    signal: AbortSignal | undefined,
  ): Promise<T> {
    const previous = conversation === undefined ? undefined : this.gates.get(conversation);
    const pending = this.run(call, previous, signal);
    this.outstanding.add(pending);
    if (conversation !== undefined) {
      // A cancelled classification settles early, so its successors wait for its predecessor too.
      const gate = Promise.allSettled([previous, pending]).then(() => undefined);
      this.gates.set(conversation, gate);
      this.depths.set(conversation, (this.depths.get(conversation) ?? 0) + 1);
      void gate.then(() => {
        if (this.gates.get(conversation) === gate) {
          this.gates.delete(conversation);
        }
      });
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
    };
    pending.then(finish, finish);
    return pending;
  }

  private async run<T>(
    call: () => Promise<T>,
    previous: Promise<unknown> | undefined,
    signal: AbortSignal | undefined,
  ): Promise<T> {
    signal?.throwIfAborted();
    if (previous !== undefined) {
      await settled(previous, signal);
    }
    await this.acquire(signal);
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

  private acquire(signal: AbortSignal | undefined): Promise<void> {
    if (this.running < this.maxConcurrent) {
      this.running++;
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const onAbort = (): void => {
        const position = this.waiting.indexOf(grant);
        if (position >= 0) {
          this.waiting.splice(position, 1);
          reject(signal?.reason);
        }
      };
      const grant = (): void => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      };
      this.waiting.push(grant);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
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
  passed: boolean;
  failed: boolean;
  failure: unknown;
}

/**
 * Pending verdicts grouped by the execution that must join them. A scope keeps
 * its verdicts until it is dropped, so concurrent joiners wait for the same
 * checks and a failure reaches every later boundary of that execution.
 */
export class Deferred {
  private readonly scopes = new Map<string, DeferredVerdict[]>();

  add(scope: string, promise: Promise<unknown>): void {
    const verdict: DeferredVerdict = { promise, passed: false, failed: false, failure: undefined };
    promise.then(
      () => { verdict.passed = true; },
      (error: unknown) => {
        verdict.failed = true;
        verdict.failure = error;
      },
    );
    const verdicts = this.scopes.get(scope) ?? [];
    verdicts.push(verdict);
    this.scopes.set(scope, verdicts);
  }

  /** Wait for every verdict in the scope and throw the first failure. */
  async join(scope: string): Promise<void> {
    for (const verdict of [...this.scopes.get(scope) ?? []]) {
      await verdict.promise.catch(() => undefined);
      if (verdict.failed) {
        throw verdict.failure;
      }
    }
    const unfinished = (this.scopes.get(scope) ?? []).filter((verdict) => !verdict.passed);
    if (unfinished.length > 0) {
      this.scopes.set(scope, unfinished);
    } else {
      this.scopes.delete(scope);
    }
  }

  /** Throw the failure of a verdict that has already landed, without waiting for the rest. */
  check(scope: string): void {
    const landed = this.scopes.get(scope)?.find((verdict) => verdict.failed);
    if (landed !== undefined) {
      throw landed.failure;
    }
  }

  /** Forget a scope once its execution has ended. */
  drop(scope: string): void {
    this.scopes.delete(scope);
  }

  clear(): void {
    this.scopes.clear();
  }
}
