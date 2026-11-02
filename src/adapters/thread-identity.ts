// Copyright (c) 2026 Silmaril Security Inc. All rights reserved.

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

export function validThreadId(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
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
  parentRunId: string | undefined;
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
    const inherited = parentRunId === undefined ? undefined : this.runs.get(parentRunId)?.threadId;
    const exposed = record(metadata);
    // Ordinary callbacks may see a parent's ambient config while a child has a
    // hidden per-call override. Only graph-tagged metadata proves that context.
    const threadId = this.boundIdentity && (parentRunId === undefined || !this.runs.has(parentRunId)) ? this.boundIdentity.threadId
      : exposed && Object.prototype.hasOwnProperty.call(exposed, "thread_id")
        ? typeof exposed.langgraph_node === "string"
          ? nativeThreadId(undefined, exposed, inherited, this.currentConfig())
          : validThreadId(exposed.thread_id)
        : inherited;
    this.runs.set(runId, { threadId, parentRunId });
    if (parentRunId !== undefined && parentRunId !== runId) {
      const children = this.children.get(parentRunId) ?? new Set<string>();
      children.add(runId);
      this.children.set(parentRunId, children);
    }
    return discarded;
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
