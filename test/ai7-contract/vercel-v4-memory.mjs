import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CHILD_FLAG = "SILMARIL_V4_MEMORY_CHILD";
const MAX_OLD_SPACE_MIB = 64;
const MAX_RETAINED_HEAP_MIB = 40;
const SEGMENT_COUNT = 12_000;
const PAYLOAD_BYTES = 12 * 1024;
const BLOCKED_SEGMENT = Math.floor(SEGMENT_COUNT / 2);
const BLOCKED_MARKER = "silmaril-blocked-memory-probe";

if (process.env[CHILD_FLAG] !== "1") {
  const child = spawnSync(process.execPath, [
    "--expose-gc",
    `--max-old-space-size=${MAX_OLD_SPACE_MIB}`,
    fileURLToPath(import.meta.url),
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      [CHILD_FLAG]: "1",
    },
    maxBuffer: 4 * 1024 * 1024,
    timeout: 120_000,
  });

  assert.equal(
    child.status,
    0,
    [
      `Vercel v4 bounded-memory child failed (status=${child.status}, signal=${child.signal})`,
      child.stdout,
      child.stderr,
    ].filter(Boolean).join("\n"),
  );
  const reportLine = child.stdout.trim().split("\n").at(-1);
  assert.ok(reportLine, "bounded-memory child did not report a result");
  const report = JSON.parse(reportLine);
  assert.ok(
    report.peakHeapBytes < MAX_RETAINED_HEAP_MIB * 1024 * 1024,
    `retained heap ${report.peakHeapBytes} exceeded ${MAX_RETAINED_HEAP_MIB} MiB`,
  );
  assert.equal(report.classifications, SEGMENT_COUNT);
  assert.equal(report.blockErrors, 1);
  assert.equal(report.blockedDeltas, 0);
  assert.equal(report.outputParts, SEGMENT_COUNT * 3 - 1);
} else {
  await runChild();
}

async function runChild() {
  assert.equal(typeof globalThis.gc, "function", "child requires --expose-gc");
  const [{ Firewall }, { createMiddlewareV4 }] = await Promise.all([
    import("../../dist/index.js"),
    import("../../dist/adapters/vercel-v4.js"),
  ]);

  let classifications = 0;
  const firewall = new Firewall({
    apiKey: "memory-contract-only",
    apiUrl: "https://example.invalid/classify",
  });
  firewall.classify = async (text) => {
    classifications++;
    const blocked = text.includes(BLOCKED_MARKER);
    return {
      prediction: blocked ? "MALICIOUS" : "BENIGN",
      score: blocked ? 0.9 : 0.1,
      threshold: 0.5,
      mode: "block",
    };
  };

  const middleware = createMiddlewareV4(firewall, {
    scanInput: false,
    scanOutput: true,
    maxBufferedBytes: 256 * 1024,
    maxBufferedParts: 100_000,
  });
  const result = await middleware.wrapStream({
    params: { prompt: [] },
    doStream: async () => ({ stream: streamFrom(events()) }),
  });

  let outputParts = 0;
  let blockErrors = 0;
  let blockedDeltas = 0;
  let lastSequence = -1;
  let peakHeapBytes = 0;
  for await (const part of result.stream) {
    outputParts++;
    if (part.type === "error") {
      blockErrors++;
    } else {
      assert.ok(
        Number.isSafeInteger(part.sequence) && part.sequence > lastSequence,
        `stream order regressed at sequence ${part.sequence}`,
      );
      lastSequence = part.sequence;
    }
    if (typeof part.delta === "string" && part.delta.includes(BLOCKED_MARKER)) {
      blockedDeltas++;
    }
    if (outputParts % 128 === 0) {
      globalThis.gc();
      peakHeapBytes = Math.max(peakHeapBytes, process.memoryUsage().heapUsed);
    }
  }
  globalThis.gc();
  peakHeapBytes = Math.max(peakHeapBytes, process.memoryUsage().heapUsed);

  console.log(JSON.stringify({
    peakHeapBytes,
    outputParts,
    blockErrors,
    blockedDeltas,
    classifications,
  }));
}

async function* events() {
  let sequence = 0;
  const start = (index) => ({
    type: "text-start",
    id: `t${index}`,
    sequence: sequence++,
  });
  const delta = (index) => ({
    type: "text-delta",
    id: `t${index}`,
    delta: payload(index),
    sequence: sequence++,
  });
  const end = (index) => ({
    type: "text-end",
    id: `t${index}`,
    sequence: sequence++,
  });

  yield start(0);
  yield delta(0);
  yield start(1);
  yield delta(1);
  for (let completed = 0; completed < SEGMENT_COUNT - 1; completed++) {
    yield end(completed);
    const next = completed + 2;
    if (next < SEGMENT_COUNT) {
      yield start(next);
      yield delta(next);
    }
  }
  yield end(SEGMENT_COUNT - 1);
  yield {
    type: "finish",
    sequence: sequence++,
    finishReason: { unified: "stop", raw: "stop" },
    usage: { inputTokens: {}, outputTokens: {} },
  };
}

function payload(index) {
  const buffer = Buffer.allocUnsafe(PAYLOAD_BYTES);
  for (let offset = 0; offset < buffer.length; offset += 4) {
    buffer.writeUInt32LE((index * 2_654_435_761 + offset) >>> 0, offset);
  }
  const prefix = index === BLOCKED_SEGMENT ? BLOCKED_MARKER : `safe-${index}`;
  return `${prefix}:${buffer.toString("base64")}`;
}

function streamFrom(iterable) {
  const iterator = iterable[Symbol.asyncIterator]();
  return new ReadableStream({
    async pull(controller) {
      const next = await iterator.next();
      if (next.done) {
        controller.close();
      } else {
        controller.enqueue(next.value);
      }
    },
    async cancel(reason) {
      await iterator.return?.(reason);
    },
  });
}
