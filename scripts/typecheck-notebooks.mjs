#!/usr/bin/env node
// Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
//
// Typecheck every code cell of every example notebook against the installed
// SDK types. Extracts TS code cells from `.ipynb` JSON, concatenates them into
// a single `async` function so top-level `await` is legal, and runs
// `tsc --noEmit` on the result. Runs as `npm run typecheck:notebooks` and is
// intended to run in CI so API breakage surfaces before anyone executes the
// notebook in a browser.

import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = resolve(SCRIPT_DIR, "..");
const EXAMPLES_DIR = resolve(SDK_ROOT, "examples");
const OUT_DIR = resolve(EXAMPLES_DIR, ".notebook-typecheck");

function isTsCodeCell(cell) {
  if (cell.cell_type !== "code") {
    return false;
  }
  const lang = cell.metadata?.vscode?.languageId ?? cell.metadata?.language_info?.name;
  if (lang && !/^(typescript|ts|javascript|js)$/i.test(lang)) {
    return false;
  }
  return true;
}

function cellBody(cell) {
  return Array.isArray(cell.source) ? cell.source.join("") : cell.source ?? "";
}

function buildModule(notebookPath) {
  const nb = JSON.parse(readFileSync(notebookPath, "utf8"));
  const tsCells = nb.cells.filter(isTsCodeCell);
  const bodies = tsCells.map((cell, i) => {
    const body = cellBody(cell)
      .split("\n")
      .map((line) => (line.length > 0 ? `  ${line}` : line))
      .join("\n");
    return `  // ---- cell ${i} ----\n${body}`;
  });
  // Wrapping in an async function lets cells use top-level `await` and keeps
  // const/let identifiers function-scoped, so re-runs of the notebook do not
  // collide with global declarations in other notebooks sharing the same
  // typecheck project. Imports must stay at module scope, so we hoist them.
  const imports = [];
  const nonImports = [];
  for (const body of bodies) {
    const lines = body.split("\n");
    for (const line of lines) {
      const stripped = line.trimStart();
      if (stripped.startsWith("import ")) {
        imports.push(stripped);
      } else {
        nonImports.push(line);
      }
    }
  }
  return (
    imports.join("\n") +
    "\n\nexport async function notebook(): Promise<void> {\n" +
    nonImports.join("\n") +
    "\n}\n"
  );
}

function writeTsconfig() {
  const tsconfig = {
    compilerOptions: {
      target: "es2022",
      module: "nodenext",
      moduleResolution: "nodenext",
      strict: true,
      skipLibCheck: true,
      noEmit: true,
      allowImportingTsExtensions: false,
      types: ["node"],
    },
    include: ["*.ts"],
  };
  writeFileSync(join(OUT_DIR, "tsconfig.json"), JSON.stringify(tsconfig, null, 2));
}

function main() {
  rmSync(OUT_DIR, { recursive: true, force: true });
  mkdirSync(OUT_DIR, { recursive: true });

  const notebooks = readdirSync(EXAMPLES_DIR)
    .filter((f) => f.endsWith(".ipynb") && !f.startsWith("."))
    .sort();

  if (notebooks.length === 0) {
    console.log("No notebooks found in examples/");
    return;
  }

  for (const nb of notebooks) {
    const source = buildModule(join(EXAMPLES_DIR, nb));
    const outFile = join(OUT_DIR, `${nb.replace(/\.ipynb$/, "")}.ts`);
    writeFileSync(outFile, source);
    console.log(`  extracted: ${nb} -> ${outFile}`);
  }

  writeTsconfig();

  console.log("\nRunning tsc against extracted notebook modules...");
  try {
    execFileSync("npx", ["tsc", "-p", OUT_DIR], { stdio: "inherit", cwd: EXAMPLES_DIR });
    console.log("\n  all notebook cells typecheck cleanly.");
  } catch (err) {
    process.exit(err.status ?? 1);
  }
}

main();
