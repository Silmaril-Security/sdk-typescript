import assert from "node:assert/strict";
import { createRequire } from "node:module";

import {
  Firewall as EsmFirewall,
  ReviewCompatibilityError as EsmReviewCompatibilityError,
} from "@silmaril-security/sdk";
import { createDeepAgentsMiddleware as createEsmDeepAgentsMiddleware } from
  "@silmaril-security/sdk/adapters/deepagents";
import { createLangChainHandler as createEsmLangChainHandler } from
  "@silmaril-security/sdk/adapters/langchain";

const require = createRequire(import.meta.url);
const {
  Firewall: CjsFirewall,
  ReviewCompatibilityError: CjsReviewCompatibilityError,
} = require("@silmaril-security/sdk");
const { createDeepAgentsMiddleware: createCjsDeepAgentsMiddleware } = require(
  "@silmaril-security/sdk/adapters/deepagents",
);
const { createLangChainHandler: createCjsLangChainHandler } = require(
  "@silmaril-security/sdk/adapters/langchain",
);

const ORIGINAL_FETCH = globalThis.fetch;
const API_URL = "https://package.test.invalid/classify";

function response(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function captureClassifyError(firewall) {
  const classify = firewall.classify.bind(firewall);
  let captured;
  firewall.classify = async (...args) => {
    try {
      return await classify(...args);
    } catch (error) {
      captured = error;
      throw error;
    }
  };
  return () => captured;
}

async function verifyLangChainCompatibility(suite) {
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    return response({
      prediction: "BENIGN",
      score: 0.1,
      threshold: 0.5,
      review: "standard",
    });
  };
  const firewall = new suite.Firewall({
    apiKey: "package-test",
    apiUrl: API_URL,
    review: "deep",
  });
  const capturedError = captureClassifyError(firewall);
  const loggerCalls = [];
  const handler = await suite.createLangChainHandler(firewall, {
    failOpen: true,
    logger: (...args) => loggerCalls.push(args),
  });

  const propagated = await handler.handleLLMStart(
    {},
    ["package review test"],
    `${suite.name}-langchain`,
  ).then(() => undefined, (error) => error);

  assert.ok(propagated instanceof suite.ReviewCompatibilityError);
  assert.strictEqual(propagated, capturedError());
  assert.equal(fetchCalls, 1);
  assert.equal(loggerCalls.length, 0);
}

async function verifyDeepAgentsCompatibility(suite) {
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    return response({
      prediction: "BENIGN",
      score: 0.1,
      threshold: 0.5,
    });
  };
  const firewall = new suite.Firewall({
    apiKey: "package-test",
    apiUrl: API_URL,
    review: "deep",
  });
  const capturedError = captureClassifyError(firewall);
  const middleware = suite.createDeepAgentsMiddleware(firewall, {
    failOpen: true,
  });
  let handlerCalls = 0;

  const propagated = await middleware.wrapToolCall(
    {
      toolCall: { id: "package-call", name: "search", args: { query: "safe" } },
      state: { messages: [] },
      runtime: {},
    },
    async () => {
      handlerCalls += 1;
      return "unreachable";
    },
  ).then(() => undefined, (error) => error);

  assert.ok(propagated instanceof suite.ReviewCompatibilityError);
  assert.strictEqual(propagated, capturedError());
  assert.equal(fetchCalls, 1);
  assert.equal(handlerCalls, 0);
}

async function verifyUnrelatedErrorsFailOpen(suite) {
  const langChainError = new Error(`${suite.name} unrelated LangChain error`);
  const langChainFirewall = new suite.Firewall({
    apiKey: "package-test",
    apiUrl: API_URL,
  });
  langChainFirewall.classify = async () => {
    throw langChainError;
  };
  const loggerCalls = [];
  const langChainHandler = await suite.createLangChainHandler(langChainFirewall, {
    failOpen: true,
    logger: (...args) => loggerCalls.push(args),
  });

  await langChainHandler.handleLLMStart({}, ["safe"], `${suite.name}-ordinary`);
  assert.equal(loggerCalls.length, 1);
  assert.strictEqual(loggerCalls[0][1], langChainError);

  const deepAgentsError = new Error(`${suite.name} unrelated Deep Agents error`);
  const deepAgentsFirewall = new suite.Firewall({
    apiKey: "package-test",
    apiUrl: API_URL,
  });
  deepAgentsFirewall.classify = async () => {
    throw deepAgentsError;
  };
  const middleware = suite.createDeepAgentsMiddleware(deepAgentsFirewall, {
    failOpen: true,
  });
  let handlerCalls = 0;
  const result = await middleware.wrapToolCall(
    {
      toolCall: { id: "ordinary-call", name: "search", args: { query: "safe" } },
      state: { messages: [] },
      runtime: {},
    },
    async () => {
      handlerCalls += 1;
      return "safe result";
    },
  );

  assert.equal(result, "safe result");
  assert.equal(handlerCalls, 1);
}

async function runSuite(suite) {
  await verifyLangChainCompatibility(suite);
  await verifyDeepAgentsCompatibility(suite);
  await verifyUnrelatedErrorsFailOpen(suite);
}

try {
  await runSuite({
    name: "ESM",
    Firewall: EsmFirewall,
    ReviewCompatibilityError: EsmReviewCompatibilityError,
    createLangChainHandler: createEsmLangChainHandler,
    createDeepAgentsMiddleware: createEsmDeepAgentsMiddleware,
  });
  await runSuite({
    name: "CJS",
    Firewall: CjsFirewall,
    ReviewCompatibilityError: CjsReviewCompatibilityError,
    createLangChainHandler: createCjsLangChainHandler,
    createDeepAgentsMiddleware: createCjsDeepAgentsMiddleware,
  });
  console.log("Built-package review compatibility checks passed for ESM and CJS");
} finally {
  globalThis.fetch = ORIGINAL_FETCH;
}
