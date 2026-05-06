// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

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
