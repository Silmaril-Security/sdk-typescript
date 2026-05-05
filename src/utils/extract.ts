// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

const SKIP_ROLES: ReadonlySet<string> = new Set(["ai", "assistant"]);
const SYSTEM_ROLES: ReadonlySet<string> = new Set(["system"]);
const TOOL_ROLES: ReadonlySet<string> = new Set(["tool", "function"]);

type MessageContent = string | ReadonlyArray<string | { type?: string; text?: string }>;

interface DucktypedMessage {
  role?: string;
  type?: string;
  content?: MessageContent;
}

interface DucktypedGeneration {
  text?: string;
}

interface DucktypedLLMResult {
  generations?: ReadonlyArray<ReadonlyArray<DucktypedGeneration>>;
}

interface DucktypedDocument {
  pageContent?: string;
}

function extractContentText(content: MessageContent | undefined): string {
  if (typeof content === "string") {
    return content;
  }
  if (Array.isArray(content)) {
    const parts: string[] = [];
    for (const block of content) {
      if (typeof block === "string") {
        parts.push(block);
      } else if (block && typeof block === "object" && block.type === "text") {
        parts.push(block.text ?? "");
      }
    }
    return parts.join(" ");
  }
  return "";
}

function getRole(message: DucktypedMessage): string {
  if (message.role !== undefined) {
    return message.role.toLowerCase();
  }
  if (typeof message.type === "string") {
    return message.type.toLowerCase();
  }
  return "";
}

export function extractTextFromMessages(
  messages: ReadonlyArray<DucktypedMessage>,
  options: { includeSystem?: boolean; includeTool?: boolean } = {},
): string {
  const includeSystem = options.includeSystem ?? true;
  const includeTool = options.includeTool ?? true;
  const parts: string[] = [];
  for (const message of messages) {
    const role = getRole(message);
    if (SKIP_ROLES.has(role)) {
      continue;
    }
    if (!includeSystem && SYSTEM_ROLES.has(role)) {
      continue;
    }
    if (!includeTool && TOOL_ROLES.has(role)) {
      continue;
    }
    const text = extractContentText(message.content);
    const stripped = text.trim();
    if (stripped) {
      parts.push(stripped);
    }
  }
  return parts.join("\n");
}

export function extractTextFromPrompts(prompts: readonly string[]): string {
  return prompts
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
    .join("\n");
}

export function extractTextFromToolInput(inputStr: string): string {
  return inputStr.trim();
}

export function extractTextFromLLMResult(response: DucktypedLLMResult): string {
  const parts: string[] = [];
  for (const genList of response.generations ?? []) {
    for (const gen of genList) {
      const text = (gen.text ?? "").trim();
      if (text) {
        parts.push(text);
      }
    }
  }
  return parts.join("\n");
}

export function extractTextFromDocuments(documents: ReadonlyArray<DucktypedDocument>): string {
  const parts: string[] = [];
  for (const doc of documents) {
    const text = (doc.pageContent ?? "").trim();
    if (text) {
      parts.push(text);
    }
  }
  return parts.join("\n");
}
