# Changelog

All notable changes to the Silmaril Firewall TypeScript SDK are documented here.

## 0.5.0 - 2026-07-15

- Send every `classify()` input as one complete event without client chunking.
- Preserve exact `metadata.conversationId` and emit one
  `metadata.silmaril.request_id` per event.
- Require the backend `prediction` field for enforcement while preserving
  optional outcome scores.
- Remove the public `sanitizeText`, `chunkText`, `MAX_INPUT_TOKENS`,
  `CHUNK_WINDOW`, `CHUNK_OVERLAP`, `MAX_INPUT_CHARS`, `CHUNK_WINDOW_CHARS`,
  `CHUNK_OVERLAP_CHARS`, and `DEFAULT_CHUNK_CONCURRENCY` exports, plus the
  `FirewallOptions.chunkConcurrency` option.

## 0.4.2 - 2026-06-02

- Add typed firewall outcome constants, ordered outcome lists, descriptions,
  type guards, and response normalizers.
- Type `BlockResult.primaryOutcome`, `outcomeScores`, `detectorScores`, and
  `detectorCounts` around the canonical outcome taxonomy.
- Document simple outcome routing examples for direct `classify()` results.

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
