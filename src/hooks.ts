// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

export const HookLabel = {
  USER_INPUT: "user_input",
  SYSTEM_PROMPT: "system_prompt",
  TOOL_CALL: "tool_call",
  TOOL_RESPONSE: "tool_response",
  LLM_OUTPUT: "llm_output",
  UNKNOWN: "unknown",
} as const;

export type HookLabel = (typeof HookLabel)[keyof typeof HookLabel];

export const FirewallHook = {
  LLM_START: "on_llm_start",
  CHAT_MODEL_START: "on_chat_model_start",
  TOOL_START: "on_tool_start",
  RETRIEVER_START: "on_retriever_start",
  LLM_END: "on_llm_end",
  TOOL_END: "on_tool_end",
  RETRIEVER_END: "on_retriever_end",
} as const;

export type FirewallHook = (typeof FirewallHook)[keyof typeof FirewallHook];

export const DEFAULT_HOOKS: ReadonlySet<FirewallHook> = new Set<FirewallHook>([
  FirewallHook.LLM_START,
  FirewallHook.CHAT_MODEL_START,
]);

export const INPUT_HOOKS: ReadonlySet<FirewallHook> = new Set<FirewallHook>([
  FirewallHook.LLM_START,
  FirewallHook.CHAT_MODEL_START,
  FirewallHook.TOOL_START,
  FirewallHook.RETRIEVER_START,
]);

export const OUTPUT_HOOKS: ReadonlySet<FirewallHook> = new Set<FirewallHook>([
  FirewallHook.LLM_END,
  FirewallHook.TOOL_END,
  FirewallHook.RETRIEVER_END,
]);

export const ALL_HOOKS: ReadonlySet<FirewallHook> = new Set<FirewallHook>([
  ...INPUT_HOOKS,
  ...OUTPUT_HOOKS,
]);

export const FIREWALL_HOOK_TO_LABEL: Readonly<Record<FirewallHook, HookLabel>> = {
  [FirewallHook.CHAT_MODEL_START]: HookLabel.USER_INPUT,
  [FirewallHook.LLM_START]: HookLabel.USER_INPUT,
  [FirewallHook.TOOL_START]: HookLabel.TOOL_CALL,
  [FirewallHook.TOOL_END]: HookLabel.TOOL_RESPONSE,
  [FirewallHook.RETRIEVER_START]: HookLabel.TOOL_CALL,
  [FirewallHook.RETRIEVER_END]: HookLabel.TOOL_RESPONSE,
  [FirewallHook.LLM_END]: HookLabel.LLM_OUTPUT,
};

const FIREWALL_HOOK_VALUES: ReadonlySet<string> = new Set(Object.values(FirewallHook));

export function resolveHooks(
  hooks: Iterable<FirewallHook | string> | undefined,
): ReadonlySet<FirewallHook> {
  if (hooks === undefined) {
    return DEFAULT_HOOKS;
  }
  const resolved = new Set<FirewallHook>();
  for (const h of hooks) {
    if (!FIREWALL_HOOK_VALUES.has(h)) {
      throw new Error(`Invalid FirewallHook value: ${String(h)}`);
    }
    resolved.add(h as FirewallHook);
  }
  return resolved;
}

export function prependHook(text: string, hook: HookLabel | string | undefined | null): string {
  if (hook === undefined || hook === null) {
    return text;
  }
  if (hook === HookLabel.UNKNOWN) {
    return text;
  }
  return `[HOOK:${hook}] ${text}`;
}

export function prependToolName(text: string, toolName: string | undefined | null): string {
  if (toolName === undefined || toolName === null) {
    return text;
  }
  return `[TOOL:${toolName}] ${text}`;
}
