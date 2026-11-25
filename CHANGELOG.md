# Changelog

## 1.0.0

The SDK now calls `POST /v2/classify` and returns its decision. This is a
breaking release for code that reads classification results; no configuration
changes are needed.

- Call `/v2/classify`. The existing `apiUrl` option is accepted unchanged: the
  SDK removes a trailing slash and a final `/classify` or `/v2/classify` path,
  keeps the query string, and appends `/v2/classify`. An `apiUrl` that is not
  an absolute URL now throws from the constructor instead of from the first
  request.
- Work against runtimes without `/v2/classify`. When that call answers 403,
  404, or 405, the SDK sends the same request to `/classify`, returns that
  response, success or error, and remembers a successful fallback on the
  client instance. `action`, `source`, `outcome`, `governance`, and `modelId`
  are derived from the `/classify` response; `confidence` and `severity` are
  null on the wire and absent from the result. A successful response without
  a `results` key is read as a `/classify` response whichever path returned
  it.
- Replace the result fields. `BlockResult` carries `action`, `source`,
  `confidence`, `severity`, `outcome`, `governance`, `modelId`, `review`, and
  `mode`. Add the `FirewallAction`, `Confidence`, and `Severity` types.
- Add `BlockResult.modelId`, the identifier of the model release that
  classified the item, for provenance.
- Enforce on `action` alone: `protect()` and every adapter block on any
  `action` other than `allow` when the effective mode is `block`. Evidence
  fields are passed through without validation and never affect enforcement.
- Require every response to carry a `results` array with one item per input
  and a string `action` on each item.
- Remove `prediction`, `score`, `threshold`, `primaryOutcome`,
  `outcomeScores`, `detectorScores`, and `detectorCounts` from `BlockResult`,
  and `score` and `threshold` from `FirewallBlockedException`, whose message
  no longer quotes them. Remove the `Prediction`, `PrimaryOutcome`,
  `HarmfulOutcome`, and `UnknownOutcome` types and the
  `normalizePrimaryOutcome`, `normalizeHarmfulOutcome`, and
  `normalizeHarmfulOutcomeMap` functions.
- Remove the benign outcome. `outcome` is absent on an allow, so
  `Outcome.Benign`, `PRIMARY_OUTCOMES`, `isPrimaryOutcome`, and
  `KnownPrimaryOutcome` are gone and `OUTCOME_DESCRIPTIONS` has no benign
  entry. `HARMFUL_OUTCOMES`, `isHarmfulOutcome`, and `KnownHarmfulOutcome`
  remain.
- `mode` keeps its precedence: the requested mode, then a `mode` on a
  `/classify` fallback response, then Block. A `/v2/classify` response carries
  no mode.

Migration:

| 0.x | 1.0.0 |
|---|---|
| `prediction` | `action` (`"allow"` or `"block"`) |
| `primaryOutcome` | `outcome` |
| `score`, `threshold` | `confidence`, `severity` |
| `predictions` (batch response) | `results` (every response) |

`confidence` and `severity` are ordered labels rather than numbers. They
describe the Firewall's assessment of the item and are set only when that
assessment is the reason for the block; they are absent on an allow, on a
block that came from a governance policy, and on a block the Firewall reached
without that assessment. Releases in the `0.x` line keep working against
`/classify`, which is frozen.

## 0.11.0

- Breaking: rename the tenant acceptable-use policy outcome to `abuse`.
  `Outcome.Abuse` replaces the tenant-specific member, and
  `KnownPrimaryOutcome`, `KnownHarmfulOutcome`, `PRIMARY_OUTCOMES`,
  `HARMFUL_OUTCOMES`, and `OUTCOME_DESCRIPTIONS` list `abuse` in the same
  position. Responses that still carry the previous label continue to decode
  as an `UnknownOutcome` string.

## 0.10.3

- Match Python `str.strip()` when validating optional governance
  `identity_revision` and `reason` evidence. Omitted and null values remain
  compatible, and accepted nonblank strings remain unmodified.

## 0.10.2

- Reject blank and Python-whitespace-only primary outcome labels and harmful
  score/count map keys while preserving nonblank open-ended labels verbatim.
  This includes Python's separator controls, NEL, and non-ASCII spaces while
  retaining U+FEFF as nonblank.

## 0.10.1

- Reject missing, null, string, non-finite, or out-of-range response `score`
  and `threshold` values instead of coercing them during single or batch
  verdict decoding.
- Reject non-finite or out-of-range `outcome_scores` and `detector_scores`
  values while continuing to require non-negative integer `detector_counts`.
- Reject present blank or whitespace-only governance `reason` and
  `identity_revision` evidence. Omitted and null legacy evidence remains valid,
  and nonblank strings are returned without trimming.

## 0.10.0

- Classify model output by default: `LLM_END` joins `DEFAULT_HOOKS` for the
  LangChain handler, and `scanOutput` defaults to `true` in both Vercel
  adapters. On AI SDK 7, Block-mode streams now deliver each text block only
  after its verdict unless `scanOutput: false` is passed.
- Read generated text and tool calls from `content` parts in the AI SDK 5/6
  middleware. Earlier releases read only the legacy `text` and `toolCalls`
  fields, so `scanOutput` and `scanToolCalls` did not run on generate results.
- Add `Firewall.protect()`, which runs a call while its input is classified,
  withholds the result of a blocked input, and aborts the call's signal when
  the block arrives first.
- Add a `parallel` option to the LangChain handler,
  `protectLangChainRunnable()`, the Deep Agents middleware, and both Vercel
  adapters. Input and tool-result checks run beside the model call; tool-call
  and model-output checks still wait for their verdict.
- Classify in the background in Shadow mode for the LangChain handler and Deep
  Agents middleware unless `failOpen` is `false`.
- Send classifications that share `metadata.conversationId` in the order they
  were started, including the `protect()` output check. Add `maxConcurrent`
  and `maxQueued` client options and `flush()`. Background classifications
  are also capped at `maxConcurrent * maxQueued` across all conversations.
- Copy `metadata` and `governance` when a queued classification starts, and
  stop a queued classification waiting once its caller's `signal` aborts.
- With `parallel`, concurrent LangChain tool starts wait for the same pending
  checks, a landed block is raised at every later boundary of the run, and
  the Vercel and Deep Agents adapters send their checks through the client's
  in-flight limit. Shadow-mode Deep Agents caches a remote notification once
  its background classification completes.

## 0.9.1

- Add a separate AI SDK 7 `LanguageModelV4Middleware` export at
  `@silmaril-security/sdk/adapters/vercel-v4`, with content-part generation
  checks, per-ID text/tool-input stream handling, ordered bounded Block-mode
  buffering, final tool-call byte verification/reclassification, and exact
  Node 22 contract coverage. Keep the existing AI SDK 5/6 v3 adapter and
  `Firewall.asMiddleware()` unchanged.
- Raise the optional `@langchain/core` peer floor to the retained secure
  intervals `>=0.3.80 <1 || >=1.1.8`, and test the 0.3.80 boundary.
- Resolve released string and qualified 1.16.x model-object profiles before
  protected general-purpose subagent assembly. Preserve disabled/customized
  profiles, parent tools/skills, tool prototypes, and matching static
  middleware overrides without hidden replacement or registry mutation.
- Bound Deep Agents compatibility to `>=1.16.0 <1.17.0`, and add protected
  compiled-subagent `isolated` / `fork` mode while preserving exact graph,
  Firewall-client, and original-mode ownership checks.

## 0.9.0

- Support native remote Deep Agents subagents with parent delegation/result checks
  and independently protected child graphs. Preserve child thread identity, parent
  lineage and async task lifecycle, and inspect background result notifications.
- Qualify isolated/fork launches, updates, checks, cancellation and failures using
  real framework graphs and SDK transport against a loopback Agent Protocol peer.

- Require Deep Agents 1.16.0 or newer within the 1.x line for the qualified
  remote lifecycle contract. Other optional integration ranges remain unchanged.

## 0.8.2

- Omit ambiguous callback-only child conversation attribution when ordinary
  metadata repeats an unresolved native-root or metadata candidate, including
  after missing or alternating metadata in deeper callbacks, while preserving
  protected-root, graph-proven, distinct child, and concurrent identities.
- Verify model-start and model-end behavior in source and built ESM/CJS package
  regressions using forwarded parent metadata and hidden child-native config.

## 0.8.1

- Preserve native thread defaults and config factories on runnables configured
  before `protectLangChainRunnable()`. Install the protection boundary inside
  existing native bindings so defaults, invocation overrides, callbacks and
  config factories resolve once before conversation identity is captured.
- Verify pre-bound invoke, batch and streaming behavior and native override
  precedence in source tests and the built ESM/CJS package release gate.

## 0.8.0

- Use each invocation’s native framework thread ID for LangChain, LangGraph,
  and Deep Agents conversation correlation, including reusable and concurrent
  agents, tool completion, and protected subagents. Threadless events remain
  independent; run and request IDs are never used as conversation identity.
- Add `protectLangChainRunnable()` for direct model/tool calls and native
  invocation overrides that upstream callbacks do not expose. Standard invoke,
  batch, stream, config, retry, and listener composition retain protection.
- **Breaking:** remove adapter `conversationId` / `conversation_id` options.
  Pass only the framework’s native `configurable.thread_id` at invocation time.
  Removed options raise an actionable migration error for JavaScript callers.
  Direct `classify()` metadata APIs are unchanged.

## 0.7.10

- Require detector counts in single and batch classification responses to be
  nonnegative integers while preserving valid floating-point scores and
  forward-compatible unknown keys. No unrelated features are included.

## 0.7.9

- Reject invalid runtime mode values in clients, per-call overrides, and all
  framework adapters before requests or fail-open handling. Valid modes and
  legacy defaults retain their existing behavior.

## 0.7.8

- Add explicit `standard` and `deep` review selection for clients and individual
  classify calls, with per-call precedence and legacy omission behavior.
- Verify top-level review acknowledgements before returning results or invoking
  adapter callbacks, and expose non-retryable `ReviewCompatibilityError` for
  missing or mismatched acknowledgements.
- Preserve review defaults through Vercel, LangChain, and Deep Agents adapters
  without adding adapter-specific review options.

## 0.7.7

- Preserve optional governance response evidence for the canonical resource,
  identity revision, and open-ended decision reason when supplied by the
  serving runtime.

## 0.7.6

- Send typed governance resources in the runtime's top-level `resource` and
  aligned `resources` fields, preserving compatibility attribution metadata.
- Reject invalid canonical resource references before submitting a request.
  Caller-supplied agent metadata remains attribution, not authenticated identity.

All notable changes to the Silmaril Firewall TypeScript SDK are documented here.

## 0.7.5 - 2026-10-12

- Correct the mode documentation for current mode-less Gateway responses and
  Python/Rust wire contracts: explicit local client, call, and adapter overrides
  remain authoritative. With no request or response mode, direct TypeScript
  calls return decisions without local enforcement while the Vercel, LangChain,
  and Deep Agents adapters retain their existing Block fallback behavior.

## 0.7.4 - 2026-10-09

- Ship the corrected README with its reproducible install command pinned to
  `0.7.4`; the immutable npm `0.7.3` artifact retained the previous release pin.

## 0.7.3 - 2026-10-07

- Honor effective Warn and Shadow modes when applying the Deep Agents
  repeated-denial cap, including after genuine denial messages are reconstructed.
- Correct the README to document native redirect refusals as `TypeError`
  transport failures rather than `SilmarilApiError` responses.

## 0.7.2 - 2026-10-05

- Clear the attempt timeout immediately on caller cancellation, including when
  retry-response body disposal never settles. This prevents residual timers
  from keeping command-hook processes alive beyond their shared deadline.
- Make retried-response cleanup respect caller cancellation and attempt timeouts
  even when a stream cancellation promise never settles.

## 0.7.1 - 2026-10-04

- Reject malformed batch responses and result counts that do not match the
  serialized request, including retried requests whose caller inputs change.

## 0.7.0 - 2026-09-30

- Add optional Deep Agents middleware and protected constructors for root, general-purpose,
  declarative, and explicitly protected compiled subagents. The compiled graph factory
  records middleware installation and constructors reject unverified graphs.
- Declare optional peer dependencies for Deep Agents:
  `deepagents@^1.14.1`, `langchain@^1.5.10`, `@langchain/langgraph@^1.4.10`, and
  existing `@langchain/core@>=0.3.0`.
- Enforce input, tool-call, tool-result, and non-streamed model-output decisions in
  Block mode with safe continuation and a repeated-denial cap (`maxBlockedAttempts`,
  default `3`). Shadow and Warn report decisions without changing content.
- Enable LangChain tool start/end callbacks by default and send the LangChain run ID
  as correlation metadata alongside a distinct classification request ID per event.

## 0.6.3 - 2026-09-24

- Add an optional `signal` option to `classify()` and `classifyBatch()`.
  Aborting stops the in-flight request or the 429 retry wait, rejects with the
  signal's reason, and leaves sibling calls on the same client unaffected. An
  already-aborted signal rejects without sending a request.
- Combine the caller signal with the existing per-attempt `timeoutMs` without
  changing timeout behavior, and release the abort listener and timer once an
  attempt finishes.
- Discard a retried 429 response body before backing off so a retry does not
  leak the connection.
- Serialize each request payload once before retries, so mutating the objects
  passed to a call can no longer change an in-flight logical event.
- Reject a `timeoutMs` above 2147483647 ms in the constructor instead of
  letting a timer silently collapse it to an immediate abort.
- Document that `Firewall` state is immutable and one client is reusable for
  concurrent promises within a runtime, while each worker thread owns its own
  client.

## 0.6.2 - 2026-08-24

- Align the runtime `sdk_version` metadata with the published package version.
- Add a release invariant test so package metadata and runtime provenance cannot
  drift in future releases.

## 0.6.1 - 2026-08-24

- Add typed governance request context for agents, hooks, principals, and
  governed resources under the SDK-controlled Silmaril metadata namespace.
- Normalize governance decisions returned by Firewall without replacing the
  existing threat-classification result.
- Treat governance blocks as adapter block candidates while preserving the
  existing effective Block mode as the only enforcement gate.
- Distinguish governance-policy denials from threat-score denials in adapter
  diagnostics.

## 0.6.0 - 2026-08-22

- Add the existing `shadow | warn | block` request mode contract to single and
  batch classification, with the backend remaining authoritative when mode is
  omitted.
- Return the backend-resolved effective mode on current-backend classification
  results.
- Keep an explicit request mode authoritative when a legacy or mixed-version
  backend omits or disagrees about `mode`. When both request and response omit
  mode, leave the result mode unset so integrations can preserve their pre-0.6
  behavior without increasing enforcement.
- Retain `shadowMode` compatibility: `true` requests Shadow, `false` requests
  Block, and explicit `mode` takes precedence.
- Make LangChain and Vercel adapters enforce only an effective Block decision;
  Shadow and Warn preserve the host flow.

## 0.5.1 - 2026-07-29

- Add typed support for `code_generation`, `story_script_generation`,
  `game_generation`, `website_generation`, `traditional_ai_abuse`, and the
  tenant acceptable-use policy outcome now named `abuse`.
- Extend ordered outcome collections, descriptions, guards, normalization
  fixtures, exports, and documentation without changing the `/classify` wire
  shape.

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
