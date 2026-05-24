import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "adapters/vercel": "src/adapters/vercel.ts",
    "adapters/langchain": "src/adapters/langchain.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  target: "es2022",
  platform: "node",
  external: ["@langchain/core", "ai"],
});
