// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

// Python str.strip() uses Unicode White_Space plus U+001C–U+001F; U+FEFF stays nonblank.
// eslint-disable-next-line no-control-regex -- The separator range intentionally matches Python.
const PYTHON_NONBLANK = /[^\p{White_Space}\u001c-\u001f]/u;

export function isPythonNonblankString(value: unknown): value is string {
  return typeof value === "string" && PYTHON_NONBLANK.test(value);
}
