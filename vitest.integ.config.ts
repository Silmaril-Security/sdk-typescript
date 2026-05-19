import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test-integ/**/*.test.ts"],
    environment: "node",
    globals: false,
    clearMocks: true,
    restoreMocks: true,
  },
});
