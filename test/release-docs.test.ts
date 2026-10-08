import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

it("pins the README reproducible install to the package release version", () => {
  const { version } = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  ) as { version: string };
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  const install = readme.match(/^npm install @silmaril-security\/sdk@(\S+)$/m);

  expect(install, "README must include a reproducible SDK install command").not.toBeNull();
  expect(install![1]).toBe(version);
});
