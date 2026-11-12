// Copyright (c) 2026 Silmaril Security Inc. All rights reserved.

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

export function validThreadId(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

const NO_THREAD_IDS: readonly string[] = Object.freeze([]);

function threadIds(first?: string, second?: string): readonly string[] {
  if (first === undefined) return second === undefined ? NO_THREAD_IDS : Object.freeze([second]);
  return Object.freeze(second === undefined || second === first ? [first] : [first, second]);
}

/** Native config is authoritative, including an explicitly invalid/empty ID. */
export function nativeThreadId(runtime?: unknown, metadata?: unknown, inherited?: string, currentConfig?: unknown): string | undefined {
  const explicit = record(record(runtime)?.configurable);
  const current = record(record(currentConfig)?.configurable);
  for (const candidate of [explicit, current, record(metadata)]) {
    if (candidate && Object.prototype.hasOwnProperty.call(candidate, "thread_id")) {
      return validThreadId(candidate.thread_id);
    }
  }
  return inherited;
}

export function rejectConversationOptions(options: object): void {
  if ("conversationId" in options || "conversation_id" in options) {
    throw new TypeError("conversationId/conversation_id was removed. Pass the native configurable.thread_id when invoking the agent or runnable instead.");
  }
}

interface RunIdentity {
  threadId: string | undefined;
  /** At most two ordinary candidates deeper children must not re-accept. */
  untrustedThreadIds: readonly string[];
  parentRunId: string | undefined;
  graphProven: boolean;
}

/** State belongs to callback runs, never to a reusable agent or current user. */
export class RunThreadIdentity {
  private readonly runs = new Map<string, RunIdentity>();
  private readonly children = new Map<string, Set<string>>();

  constructor(
    private readonly boundIdentity?: { threadId: string | undefined },
    private readonly currentConfig: () => unknown = () => undefined,
  ) {}

  start(runId: string, parentRunId?: string, metadata?: unknown): string[] {
    const discarded = this.finish(runId);
    if (this.runs.size >= 4096) {
      const oldestRoot = [...this.runs].find(([, run]) => run.parentRunId === undefined || !this.runs.has(run.parentRunId))?.[0] ?? this.runs.keys().next().value;
      if (oldestRoot !== undefined) discarded.push(...this.finish(oldestRoot));
    }
    const parent = parentRunId === undefined ? undefined : this.runs.get(parentRunId);
    const inherited = parent?.threadId;
    const exposed = record(metadata);
    const hasExposedThread = exposed !== undefined
      && Object.prototype.hasOwnProperty.call(exposed, "thread_id");
    const candidate = hasExposedThread ? validThreadId(exposed.thread_id) : undefined;
    // Ordinary callbacks may see a parent's ambient config while a child has a
    // hidden per-call override. Only graph-tagged metadata proves that context.
    let threadId: string | undefined;
    let untrustedThreadIds: readonly string[];
    let graphProven: boolean;
    if (this.boundIdentity && parent === undefined) {
      threadId = this.boundIdentity.threadId;
      untrustedThreadIds = threadIds(threadId, candidate);
      graphProven = false;
    } else if (exposed && (
      typeof exposed.langgraph_node === "string"
      || typeof exposed.langgraph_step === "number"
    )) {
      threadId = nativeThreadId(undefined, exposed, inherited, this.currentConfig());
      untrustedThreadIds = NO_THREAD_IDS;
      graphProven = true;
    } else if (hasExposedThread) {
      if (candidate === undefined) {
        threadId = undefined;
        untrustedThreadIds = NO_THREAD_IDS;
        graphProven = false;
      } else if (parent?.graphProven && candidate === inherited) {
        threadId = inherited;
        untrustedThreadIds = NO_THREAD_IDS;
        graphProven = true;
      } else if (parent && (
        candidate === inherited || parent.untrustedThreadIds.includes(candidate)
      )) {
        threadId = undefined;
        untrustedThreadIds = parent.untrustedThreadIds;
        graphProven = false;
      } else {
        threadId = candidate;
        untrustedThreadIds = threadIds(candidate);
        graphProven = false;
      }
    } else if (parent?.graphProven) {
      threadId = inherited;
      untrustedThreadIds = NO_THREAD_IDS;
      graphProven = true;
    } else {
      threadId = undefined;
      untrustedThreadIds = parent?.untrustedThreadIds ?? NO_THREAD_IDS;
      graphProven = false;
    }
    this.runs.set(runId, { threadId, untrustedThreadIds, parentRunId, graphProven });
    if (parentRunId !== undefined && parentRunId !== runId) {
      const children = this.children.get(parentRunId) ?? new Set<string>();
      children.add(runId);
      this.children.set(parentRunId, children);
    }
    return discarded;
  }

  /** The outermost tracked ancestor, which scopes verdicts deferred by its descendants. */
  root(runId: string): string {
    const visited = new Set([runId]);
    let current = runId;
    for (;;) {
      const parent = this.runs.get(current)?.parentRunId;
      if (parent === undefined || visited.has(parent) || !this.runs.has(parent)) {
        return current;
      }
      visited.add(parent);
      current = parent;
    }
  }

  get(runId: string): string | undefined {
    const run = this.runs.get(runId);
    return run ? run.threadId : this.boundIdentity?.threadId;
  }

  finish(runId: string): string[] {
    const pending = [runId];
    const seen = new Set<string>();
    while (pending.length) {
      const id = pending.pop()!;
      if (seen.has(id)) continue;
      seen.add(id);
      pending.push(...this.children.get(id) ?? []);
      this.children.delete(id);
      const parent = this.runs.get(id)?.parentRunId;
      this.runs.delete(id);
      if (parent !== undefined) {
        const siblings = this.children.get(parent);
        siblings?.delete(id);
        if (siblings?.size === 0) this.children.delete(parent);
      }
    }
    return [...seen];
  }
}
