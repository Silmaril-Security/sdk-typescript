// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type {
  ConcreteGovernanceResource,
  McpToolResourceResolution,
} from "./types.js";

const GOVERNANCE_RESOURCE_KINDS: ReadonlySet<string> = new Set([
  "agent",
  "tool",
  "mcp_server",
  "mcp_tool",
  "plugin",
  "skill",
  "extension",
]);

function nonEmptyIdentity(value: unknown): value is string {
  return typeof value === "string" && /\S/u.test(value);
}

export function validateGovernanceResource(
  name: string,
  value: unknown,
): ConcreteGovernanceResource {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`Firewall: ${name} must be a governance resource object`);
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.some((key) => key !== "kind" && key !== "id" && key !== "parentId")) {
    throw new Error(`Firewall: ${name} contains an unsupported field`);
  }
  if (typeof record.kind !== "string" || !GOVERNANCE_RESOURCE_KINDS.has(record.kind)) {
    throw new Error(`Firewall: ${name}.kind is not a supported governance resource kind`);
  }
  if (!nonEmptyIdentity(record.id)) {
    throw new Error(`Firewall: ${name}.id must be a non-empty string`);
  }
  if (record.kind === "mcp_tool") {
    if (!nonEmptyIdentity(record.parentId)) {
      throw new Error(`Firewall: ${name}.parentId is required for mcp_tool`);
    }
  } else if (record.parentId !== undefined) {
    throw new Error(`Firewall: ${name}.parentId is only valid for mcp_tool`);
  }
  return value as ConcreteGovernanceResource;
}

export function validateIdentityRevision(name: string, value: unknown): string {
  if (!nonEmptyIdentity(value)) {
    throw new Error(`Firewall: ${name} must be a non-empty string`);
  }
  return value;
}

function hostAlias(serverId: string): string {
  return serverId.replaceAll("-", "_");
}

/**
 * Resolves a host MCP dispatch name only against authoritative configured IDs.
 * Exact configured IDs win before a unique host-safe alias.
 */
export function resolveMcpToolResource(
  configuredServerIds: readonly string[],
  toolName: string,
): McpToolResourceResolution {
  const match = /^mcp__(.+?)__(.+)$/u.exec(toolName) ?? /^MCP:([^:]+):(.+)$/u.exec(toolName);
  if (!match?.[1] || !match[2]) {
    return Object.freeze({ status: "unresolved", reason: "unrecognized_tool_name" });
  }

  const dispatchServerId = match[1];
  const toolId = match[2];
  const uniqueServerIds = [...new Set(configuredServerIds)];
  const exact = uniqueServerIds.find((serverId) => serverId === dispatchServerId);
  if (exact !== undefined) {
    return Object.freeze({
      status: "resolved",
      resource: Object.freeze({ kind: "mcp_tool", id: toolId, parentId: exact }),
    });
  }

  const aliases = uniqueServerIds.filter((serverId) => hostAlias(serverId) === dispatchServerId);
  if (aliases.length === 1) {
    return Object.freeze({
      status: "resolved",
      resource: Object.freeze({ kind: "mcp_tool", id: toolId, parentId: aliases[0]! }),
    });
  }
  if (aliases.length > 1) {
    return Object.freeze({
      status: "ambiguous",
      serverIds: Object.freeze([...aliases].sort()),
    });
  }
  return Object.freeze({ status: "unresolved", reason: "unknown_server" });
}

export function validateThreshold(name: string, value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`Firewall: ${name} must be a finite number between 0 and 1, got ${value}`);
  }
  return value;
}

export function validateOptionalThreshold(name: string, value: unknown): number | undefined {
  return value === undefined ? undefined : validateThreshold(name, value);
}

export function validateHookThresholds<T extends string>(
  name: string,
  values: Partial<Record<T, number>> | undefined,
): Partial<Record<T, number>> {
  const validated: Partial<Record<T, number>> = {};
  for (const [hook, value] of Object.entries(values ?? {}) as Array<[T, unknown]>) {
    if (value === undefined) {
      continue;
    }
    validated[hook] = validateThreshold(`${name}[${JSON.stringify(hook)}]`, value);
  }
  return validated;
}
