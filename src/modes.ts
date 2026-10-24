import type { FirewallMode } from "./types.js";

/** Validate JavaScript/configuration inputs before any fail-open adapter path. */
export function validateMode(value: unknown): FirewallMode | undefined {
  if (value === undefined || value === "shadow" || value === "warn" || value === "block") {
    return value;
  }
  throw new Error("Firewall: mode must be shadow, warn, or block");
}
