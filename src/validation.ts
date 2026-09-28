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

function hasLineTerminator(value: string): boolean {
  return value.includes("\n")
    || value.includes("\r")
    || value.includes("\u2028")
    || value.includes("\u2029");
}

/**
 * Accepts only spellings that have a nonempty server and tool around a
 * delimiter. Line terminators stay rejected where an anchored dot would
 * reject them. The configured catalog, not the first delimiter, chooses
 * the server boundary.
 */
function mcpDispatchBody(
  toolName: string,
): { readonly delimiter: "__" | ":"; readonly body: string } | undefined {
  if (toolName.startsWith("mcp__")) {
    const body = toolName.slice("mcp__".length);
    const delimiter = body.indexOf("__", 1);
    if (delimiter < 1 || body.slice(delimiter + 2).length === 0 || hasLineTerminator(body)) {
      return undefined;
    }
    return { delimiter: "__", body };
  }

  if (toolName.startsWith("MCP:")) {
    const body = toolName.slice("MCP:".length);
    const delimiter = body.indexOf(":");
    if (delimiter < 1) {
      return undefined;
    }
    const toolId = body.slice(delimiter + 1);
    if (toolId.length === 0 || hasLineTerminator(toolId)) {
      return undefined;
    }
    return { delimiter: ":", body };
  }

  return undefined;
}

function matchingServerPrefixes(
  serverIds: readonly string[],
  body: string,
  delimiter: "__" | ":",
  serverPrefix: (serverId: string) => string,
): string[] {
  const matches: string[] = [];
  const seen = new Set<string>();
  for (const serverId of serverIds) {
    if (serverId.length === 0 || seen.has(serverId)) {
      continue;
    }
    seen.add(serverId);
    const prefix = `${serverPrefix(serverId)}${delimiter}`;
    if (body.startsWith(prefix) && body.length > prefix.length) {
      matches.push(serverId);
    }
  }
  return matches;
}

function resolvedMcpTool(serverId: string, toolId: string): McpToolResourceResolution {
  return Object.freeze({
    status: "resolved",
    resource: Object.freeze({ kind: "mcp_tool", id: toolId, parentId: serverId }),
  });
}

/**
 * Resolves a host MCP dispatch name only against authoritative configured IDs.
 * Exact configured prefixes win before a unique hyphen-to-underscore alias.
 */
export function resolveMcpToolResource(
  configuredServerIds: readonly string[],
  toolName: string,
): McpToolResourceResolution {
  const dispatch = mcpDispatchBody(toolName);
  if (dispatch === undefined) {
    return Object.freeze({ status: "unresolved", reason: "unrecognized_tool_name" });
  }

  const uniqueServerIds = [...new Set(configuredServerIds)];
  const exact = matchingServerPrefixes(
    uniqueServerIds,
    dispatch.body,
    dispatch.delimiter,
    (serverId) => serverId,
  );
  if (exact.length > 1) {
    return Object.freeze({
      status: "ambiguous",
      serverIds: Object.freeze([...exact].sort()),
    });
  }
  if (exact.length === 1) {
    const serverId = exact[0]!;
    return resolvedMcpTool(
      serverId,
      dispatch.body.slice(serverId.length + dispatch.delimiter.length),
    );
  }

  const aliases = matchingServerPrefixes(
    uniqueServerIds,
    dispatch.body,
    dispatch.delimiter,
    hostAlias,
  );
  if (aliases.length > 1) {
    return Object.freeze({
      status: "ambiguous",
      serverIds: Object.freeze([...aliases].sort()),
    });
  }
  if (aliases.length === 1) {
    const serverId = aliases[0]!;
    return resolvedMcpTool(
      serverId,
      dispatch.body.slice(hostAlias(serverId).length + dispatch.delimiter.length),
    );
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
