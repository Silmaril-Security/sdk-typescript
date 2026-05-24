# Changelog

All notable changes to the Silmaril Firewall TypeScript SDK are documented here.

## 0.4.1 - 2026-05-24

- Recover the `0.4.x` npm release by moving to `0.4.1`. The `v0.4.0` Git tag
  exists, but `@silmaril-security/sdk@0.4.0` was never published to npm.
- Support Vercel AI SDK v5 and v6 with the `ai` peer range
  `^5.0.0 || ^6.0.0`.
- Keep optional LangChain.js types out of the root package declarations so core
  consumers can typecheck without installing `@langchain/core`.
- Add typed ESM and CommonJS export conditions, plus explicit adapter subpath
  exports for `@silmaril-security/sdk/adapters/vercel` and
  `@silmaril-security/sdk/adapters/langchain`.
- Add public repository hygiene docs for contribution and vulnerability
  reporting.

## 0.4.0 - Skipped on npm

- Do not install this version. The Git tag exists, but the npm package was not
  published.
