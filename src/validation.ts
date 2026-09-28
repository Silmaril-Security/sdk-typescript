// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

import type {
  ConcreteGovernanceResource,
  McpConfiguredServer,
  McpDispatchCatalog,
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

function toolIdAfterPrefix(body: string, prefix: string): string | undefined {
  if (!body.startsWith(prefix) || body.length <= prefix.length) {
    return undefined;
  }
  const toolId = body.slice(prefix.length);
  return nonEmptyIdentity(toolId) ? toolId : undefined;
}

interface DispatchMatch {
  readonly serverId: string;
  readonly toolId: string;
}

function rememberMatch(
  matches: DispatchMatch[],
  seen: Set<string>,
  serverId: string,
  toolId: string,
): void {
  const canonical = `${serverId}\u0000${toolId}`;
  if (seen.has(canonical)) {
    return;
  }
  seen.add(canonical);
  matches.push({ serverId, toolId });
}

/** Later entries for one canonical id contribute aliases; they do not replace it. */
function mergedServers(servers: readonly McpConfiguredServer[]): McpConfiguredServer[] {
  const aliasesById = new Map<string, Set<string>>();
  const order: string[] = [];
  for (const server of servers) {
    let aliases = aliasesById.get(server.id);
    if (aliases === undefined) {
      aliases = new Set<string>();
      aliasesById.set(server.id, aliases);
      order.push(server.id);
    }
    for (const alias of server.aliases ?? []) {
      if (alias.length > 0) {
        aliases.add(alias);
      }
    }
  }
  return order.map((id) => {
    const aliases = [...(aliasesById.get(id) ?? [])];
    return aliases.length === 0 ? { id } : { id, aliases };
  });
}

/** Exact id, explicit aliases, and the hyphen-to-underscore spelling of the id. */
function dispatchKeys(server: McpConfiguredServer): readonly string[] {
  const keys = new Set<string>();
  if (server.id.length > 0) {
    keys.add(server.id);
    keys.add(hostAlias(server.id));
  }
  for (const alias of server.aliases ?? []) {
    if (alias.length > 0) {
      keys.add(alias);
    }
  }
  keys.delete("");
  return [...keys];
}

function serverOnlyMatches(
  servers: readonly McpConfiguredServer[],
  body: string,
  delimiter: "__" | ":",
): DispatchMatch[] {
  const matches: DispatchMatch[] = [];
  const seen = new Set<string>();
  for (const server of mergedServers(servers)) {
    for (const key of dispatchKeys(server)) {
      const toolId = toolIdAfterPrefix(body, `${key}${delimiter}`);
      if (toolId === undefined) {
        continue;
      }
      rememberMatch(matches, seen, server.id, toolId);
    }
  }
  return matches;
}

function fullCatalogMatches(catalog: McpDispatchCatalog, toolName: string): DispatchMatch[] {
  const servers = new Map<string, McpConfiguredServer>();
  for (const server of mergedServers(catalog.servers)) {
    servers.set(server.id, server);
  }
  const matches: DispatchMatch[] = [];
  const seen = new Set<string>();
  for (const tool of catalog.tools ?? []) {
    if (tool.id.length === 0) {
      continue;
    }
    const server = servers.get(tool.parentId);
    if (server === undefined) {
      continue;
    }
    for (const key of dispatchKeys(server)) {
      // A separator inside a key or tool id can reconstruct the same raw name
      // as another configured pair. Those pairs stay distinct candidates.
      if (toolName !== `mcp__${key}__${tool.id}` && toolName !== `MCP:${key}:${tool.id}`) {
        continue;
      }
      rememberMatch(matches, seen, server.id, tool.id);
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

function isDispatchCatalog(
  configured: readonly string[] | McpDispatchCatalog,
): configured is McpDispatchCatalog {
  return !Array.isArray(configured);
}

function finishDispatchMatches(matches: readonly DispatchMatch[]): McpToolResourceResolution {
  if (matches.length > 1) {
    return Object.freeze({
      status: "ambiguous",
      serverIds: Object.freeze([...new Set(matches.map((match) => match.serverId))].sort()),
    });
  }
  const match = matches[0];
  if (match !== undefined) {
    return resolvedMcpTool(match.serverId, match.toolId);
  }
  return Object.freeze({ status: "unresolved", reason: "unknown_server" });
}

/**
 * Resolves a raw `mcp__` or `MCP:` dispatch name.
 * A string array is a server-only catalog. A catalog object with `tools`
 * matches complete configured spellings and ignores a tool whose parent is
 * not configured. Without `tools`, the exact suffix after a server key is
 * the tool id when it contains a non-whitespace character, including `__`
 * or `:`. A whitespace-only suffix stays unresolved and is not trimmed.
 * Exact ids, explicit aliases, and hyphen-to-underscore server spellings
 * are equal candidates.
 */
export function resolveMcpToolResource(
  configuredServerIds: readonly string[],
  toolName: string,
): McpToolResourceResolution;
export function resolveMcpToolResource(
  catalog: McpDispatchCatalog,
  toolName: string,
): McpToolResourceResolution;
export function resolveMcpToolResource(
  configured: readonly string[] | McpDispatchCatalog,
  toolName: string,
): McpToolResourceResolution {
  const catalog: McpDispatchCatalog = isDispatchCatalog(configured)
    ? configured
    : { servers: configured.map((id) => ({ id })) };
  const dispatch = mcpDispatchBody(toolName);
  if (dispatch === undefined) {
    return Object.freeze({ status: "unresolved", reason: "unrecognized_tool_name" });
  }
  const matches = catalog.tools === undefined
    ? serverOnlyMatches(catalog.servers, dispatch.body, dispatch.delimiter)
    : fullCatalogMatches(catalog, toolName);
  return finishDispatchMatches(matches);
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
