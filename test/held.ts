// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

import { vi } from "vitest";

import { Firewall, type FirewallOptions, type HookLabel } from "../src/index.js";

export interface HeldCall {
  text: string;
  hook: HookLabel | undefined;
  conversationId: unknown;
}

export interface HeldFirewall {
  firewall: Firewall;
  calls: HeldCall[];
  /** Resolves once the first classification has reached the firewall. */
  started: Promise<void>;
  /** Lets every held classification return its verdict. */
  release: () => void;
}

/** A firewall whose classifications stay open until the test releases them. */
export function heldFirewall(
  predictions: ReadonlyArray<"BENIGN" | "MALICIOUS"> = ["BENIGN"],
  options: Partial<FirewallOptions> = {},
): HeldFirewall {
  const firewall = new Firewall({
    apiKey: "sk-test",
    apiUrl: "https://api.test.invalid/classify",
    ...options,
  });
  const calls: HeldCall[] = [];
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  let markStarted!: () => void;
  const started = new Promise<void>((resolve) => { markStarted = resolve; });
  firewall.classify = vi.fn(async (text, classifyOptions) => {
    const prediction = predictions[Math.min(calls.length, predictions.length - 1)]!;
    calls.push({
      text,
      hook: classifyOptions?.hook,
      conversationId: classifyOptions?.metadata?.conversationId,
    });
    markStarted();
    await released;
    const mode = classifyOptions?.mode ?? firewall.mode;
    return Object.freeze({
      prediction,
      score: prediction === "MALICIOUS" ? 0.9 : 0.1,
      threshold: 0.5,
      ...(mode === undefined ? {} : { mode }),
    });
  }) as typeof firewall.classify;
  return { firewall, calls, started, release };
}
