import { createServer } from "node:http";
import { once } from "node:events";
import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { fakeModel } from "@langchain/core/testing";
import { tool } from "@langchain/core/tools";
import { MemorySaver } from "@langchain/langgraph";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { Firewall, HookLabel } from "../src/index.js";
import { createDeepAgentsMiddleware, createProtectedDeepAgent, SAFE_OUTPUT_MESSAGE, SAFE_TOOL_MESSAGE } from "../src/adapters/deepagents.js";

function firewall(block = true) {
  const fw = new Firewall({ apiKey: "test", apiUrl: "https://unused.invalid/classify" });
  fw.classify = vi.fn(async (text) => ({
    prediction: block && text.includes("unsafe") ? "MALICIOUS" : "BENIGN",
    score: block && text.includes("unsafe") ? 0.9 : 0.1, threshold: 0.5, mode: "block",
  })) as typeof fw.classify;
  return fw;
}

const taskId = "00000000-0000-0000-0000-000000000001";
interface Thread { thread_id: string; metadata: Record<string, unknown>; status: string; values: { messages?: unknown[] } }
interface Run { thread_id: string; run_id: string; status: string }
interface Body { input: { messages: unknown[] }; config?: { configurable?: Record<string, unknown> }; metadata?: Record<string, unknown>; multitask_strategy?: string }

async function peer() {
  const threads = new Map<string, Thread>();
  const runs = new Map<string, Run>();
  const requests: Array<{ method: string; path: string; body: Body }> = [];
  const state = { child: undefined as ReturnType<typeof createProtectedDeepAgent> | undefined, tamper: false, fail: false, errors: [] as unknown[] };
  const server = createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      const body = JSON.parse(Buffer.concat(chunks).toString() || "{}") as Body;
      const path = (req.url ?? "").split("?")[0]!;
      const parts = path.split("/").filter(Boolean);
      requests.push({ method: req.method!, path, body });
      const send = (data: unknown, status = 200) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(data)); };
      if (state.fail) return send({ detail: "remote launch unavailable" }, 400);
      if (req.method === "POST" && path === "/threads") {
        const id = `00000000-0000-0000-0000-${String(threads.size + 1).padStart(12, "0")}`;
        const thread = { thread_id: id, metadata: body.metadata ?? {}, status: "idle", values: {} };
        threads.set(id, thread); return send(thread);
      }
      if (req.method === "POST" && parts.length === 3 && parts[2] === "runs") {
        const thread = threads.get(parts[1]!)!;
        const output = await state.child!.invoke(body.input as never, {
          ...body.config, configurable: { ...body.config?.configurable, thread_id: thread.thread_id }, metadata: thread.metadata,
        });
        thread.values = { messages: [{ type: "ai", content: state.tamper ? "unsafe remote result" : output.messages.at(-1)?.content }] };
        const run = { thread_id: thread.thread_id, run_id: `run-${runs.size + 1}`, status: "success" };
        runs.set(run.run_id, run); return send(run);
      }
      if (req.method === "POST" && parts[4] === "cancel") { runs.get(parts[3]!)!.status = "interrupted"; return send({}); }
      if (req.method === "GET" && parts.length === 2) return send(threads.get(parts[1]!));
      if (req.method === "GET" && parts.length === 4) return send(runs.get(parts[3]!));
      if (req.method === "GET" && parts.length === 3) return send([...runs.values()].filter(r => r.thread_id === parts[1]).reverse());
      return send({ error: "unexpected path " + path }, 404);
    } catch (error) {
      state.errors.push(error);
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "Agent Protocol test handler failed" }));
    }
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const address = server.address(); if (!address || typeof address === "string") throw new Error("No test port");
  return { state, threads, requests, url: `http://127.0.0.1:${address.port}`, close: async () => {
    server.closeAllConnections(); server.close(); await once(server, "close");
    if (state.errors.length) throw new AggregateError(state.errors, "Agent Protocol test handler failed");
  } };
}

type Peer = Awaited<ReturnType<typeof peer>>;
function attachChild(p: Peer, fw: Firewall, simple = false) {
  const executed: string[] = [];
  const search = tool(async ({ query }) => { executed.push(query); return "unsafe tool result"; }, {
    name: "search", description: "Search test corpus", schema: z.object({ query: z.string() }),
  });
  const model = simple ? fakeModel().respond(new AIMessage("safe child answer")).respond(new AIMessage("safe child answer")) : fakeModel()
    .respondWithTools([{ name: "search", args: { query: "unsafe action" }, id: "child-1" }])
    .respondWithTools([{ name: "search", args: { query: "safe action" }, id: "child-2" }])
    .respond(new AIMessage("unsafe final answer"))
    .respondWithTools([{ name: "search", args: { query: "unsafe action" }, id: "child-3" }])
    .respondWithTools([{ name: "search", args: { query: "safe action" }, id: "child-4" }])
    .respond(new AIMessage("unsafe final answer"));
  p.state.child = createProtectedDeepAgent(fw, { model, tools: [search], checkpointer: new MemorySaver() });
  return executed;
}
function parent(p: Peer, fw: Firewall, model: ReturnType<typeof fakeModel>, mode: "isolated" | "fork" = "isolated") {
  return createProtectedDeepAgent(fw, { model, subagents: [{
    name: "research", description: "Remote research", graphId: "research", url: p.url,
    mode, notifyParent: false, updateStrategy: "enqueue", headers: { "x-test-auth": "local-only" },
  }] });
}

describe("protected remote Deep Agents", () => {
  it.each(["isolated", "fork"] as const)("protects both graphs and preserves %s lifecycle", async (mode) => {
    const p = await peer();
    try {
      const childFirewall = firewall(), parentFirewall = firewall();
      const executed = attachChild(p, childFirewall);
      const model = fakeModel()
        .respondWithTools([{ name: "start_async_task", args: { description: "safe research", agentName: "research" }, id: "start" }])
        .respondWithTools([{ name: "check_async_task", args: { taskId }, id: "check" }])
        .respondWithTools([{ name: "update_async_task", args: { taskId, message: "safe update" }, id: "update" }])
        .respondWithTools([{ name: "list_async_tasks", args: {}, id: "list" }])
        .respondWithTools([{ name: "cancel_async_task", args: { taskId }, id: "cancel" }])
        .respond(new AIMessage("done"));
      const out = await parent(p, parentFirewall, model, mode).invoke({ messages: [new HumanMessage("hello")] }, { configurable: { thread_id: "parent-thread" } });
      expect(out.asyncTasks?.[taskId]?.status).toBe("cancelled");
      expect(executed).toEqual(["safe action", "safe action"]);
      const childCalls = vi.mocked(childFirewall.classify).mock.calls;
      expect(childCalls.every(([, opts]) => opts?.metadata?.conversationId === taskId)).toBe(true);
      expect(childCalls.every(([, opts]) => (opts?.metadata?.langgraph as Record<string, unknown>)?.parent_thread_id === "parent-thread")).toBe(true);
      expect(vi.mocked(parentFirewall.classify).mock.calls.every(([, opts]) => opts?.metadata?.conversationId === "parent-thread")).toBe(true);
      for (const hook of [HookLabel.TOOL_CALL, HookLabel.TOOL_RESPONSE, HookLabel.LLM_OUTPUT]) expect(childCalls.some(([text, opts]) => text.includes("unsafe") && opts?.hook === hook)).toBe(true);
      expect(p.requests.some(r => r.path.endsWith("/cancel"))).toBe(true);
      const launches = p.requests.filter(r => r.method === "POST" && r.path.endsWith("/runs"));
      expect(launches[1]?.body.multitask_strategy).toBe("enqueue");
      expect(launches[0]!.body.input.messages.length).toBe(mode === "fork" ? 2 : 1);
    } finally { await p.close(); }
  });

  it("blocks unsafe delegation before remote execution", async () => {
    const p = await peer();
    try {
      const model = fakeModel().respondWithTools([{ name: "start_async_task", args: { description: "unsafe delegation", agentName: "research" }, id: "start" }]).respond(new AIMessage("done"));
      const out = await parent(p, firewall(), model).invoke({ messages: [new HumanMessage("hello")] });
      expect(p.requests).toEqual([]);
      expect(out.messages.filter(ToolMessage.isInstance).some((m: ToolMessage) => m.content === SAFE_TOOL_MESSAGE)).toBe(true);
    } finally { await p.close(); }
  });

  it("protects the child's input independently", async () => {
    const p = await peer();
    try {
      const childFirewall = firewall(); const executed = attachChild(p, childFirewall);
      const model = fakeModel().respondWithTools([{ name: "start_async_task", args: { description: "unsafe child input", agentName: "research" }, id: "start" }]).respond(new AIMessage("done"));
      await parent(p, firewall(false), model).invoke({ messages: [new HumanMessage("hello")] });
      expect(executed).toEqual([]);
      expect(p.threads.get(taskId)?.values.messages).toEqual([{ type: "ai", content: SAFE_OUTPUT_MESSAGE }]);
    } finally { await p.close(); }
  });

  it("withholds a tampered remote result and retains its task state", async () => {
    const p = await peer();
    try {
      attachChild(p, firewall(), true); p.state.tamper = true;
      const model = fakeModel().respondWithTools([{ name: "start_async_task", args: { description: "safe", agentName: "research" }, id: "start" }])
        .respondWithTools([{ name: "check_async_task", args: { taskId }, id: "check" }]).respond(new AIMessage("done"));
      const fw = firewall(); const out = await parent(p, fw, model).invoke({ messages: [new HumanMessage("hello")] });
      expect(out.asyncTasks?.[taskId]?.status).toBe("success");
      expect(out.messages.filter(ToolMessage.isInstance).find((m: ToolMessage) => m.tool_call_id === "check")?.content).toBe(SAFE_TOOL_MESSAGE);
      expect(vi.mocked(fw.classify).mock.calls.some(([text, opts]) => text.includes("unsafe remote result") && opts?.hook === HookLabel.TOOL_RESPONSE)).toBe(true);
    } finally { await p.close(); }
  });

  it("preserves visible launch failures without inventing a task", async () => {
    const p = await peer();
    try {
      p.state.fail = true;
      const model = fakeModel().respondWithTools([{ name: "start_async_task", args: { description: "safe", agentName: "research" }, id: "start" }]).respond(new AIMessage("done"));
      const out = await parent(p, firewall(), model).invoke({ messages: [new HumanMessage("hello")] });
      expect(Object.keys(out.asyncTasks ?? {})).toEqual([]);
      expect(out.messages.filter(ToolMessage.isInstance).some((m: ToolMessage) => String(m.content).includes("Failed to launch"))).toBe(true);
    } finally { await p.close(); }
  });

  it("keeps concurrent remote child identities separate", async () => {
    const p = await peer();
    try {
      const childFirewall = firewall(); attachChild(p, childFirewall, true);
      const model = fakeModel().respondWithTools([
        { name: "start_async_task", args: { description: "safe one", agentName: "research" }, id: "one" },
        { name: "start_async_task", args: { description: "safe two", agentName: "research" }, id: "two" },
      ]).respond(new AIMessage("done"));
      const out = await parent(p, firewall(), model).invoke({ messages: [new HumanMessage("hello")] }, { configurable: { thread_id: "parent" } });
      expect(Object.keys(out.asyncTasks ?? {})).toHaveLength(2);
      const calls = vi.mocked(childFirewall.classify).mock.calls;
      expect(new Set(calls.map(([, opts]) => opts?.metadata?.conversationId))).toEqual(new Set(Object.keys(out.asyncTasks ?? {})));
      expect(calls.every(([, opts]) => (opts?.metadata?.langgraph as Record<string, unknown>)?.parent_thread_id === "parent")).toBe(true);
    } finally { await p.close(); }
  });

  it("filters a native notification once and reapplies its blocked replacement after resume", async () => {
    const p = await peer();
    try {
      attachChild(p, firewall(), true); p.state.tamper = true;
      const fw = firewall();
      const model = fakeModel().respondWithTools([{ name: "start_async_task", args: { description: "safe", agentName: "research" }, id: "start" }])
        .respond(new AIMessage("done")).respond(new AIMessage("done again"));
      const agent = createProtectedDeepAgent(fw, { model, checkpointer: new MemorySaver(), subagents: [{
        name: "research", description: "Remote", graphId: "research", url: p.url, notifyParent: true,
      }] });
      const config = { configurable: { thread_id: "parent-resume" } };
      const first = await agent.invoke({ messages: [new HumanMessage("hello")] }, config);
      expect(first.messages.some((message: HumanMessage) => JSON.stringify(message.content).includes("unsafe remote result")
        && (message.additional_kwargs.lc_source === "async_subagent" || "deepagents_notification" in message.additional_kwargs))).toBe(true);
      await agent.invoke({ messages: [new HumanMessage("safe newer question")] }, config);
      expect(model.calls.every(call => call.messages.every(message => !JSON.stringify(message.content).includes("unsafe remote result")))).toBe(true);
      const checks = vi.mocked(fw.classify).mock.calls.filter(([text, opts]) => text.includes("unsafe remote result")
        && opts?.hook === HookLabel.TOOL_RESPONSE && opts?.toolName === "async_subagent");
      expect(checks).toHaveLength(1);
    } finally { await p.close(); }
  });

  it("binds notification checks to thread and content and retries failed checks", async () => {
    const fw = firewall(); const middleware = createDeepAgentsMiddleware(fw);
    const request = (thread: string, content: string) => {
      const messages = [new HumanMessage({ id: "note", content, additional_kwargs: { lc_source: "async_subagent" } }), new HumanMessage("safe")];
      return { messages, state: { messages }, runtime: { configurable: { thread_id: thread } } };
    };
    for (const [thread, text] of [["one", "safe note"], ["one", "safe note"], ["two", "safe note"], ["one", "unsafe changed note"]]) {
      await middleware.wrapModelCall!(request(thread!, text!) as never, async () => new AIMessage("done"));
    }
    expect(vi.mocked(fw.classify).mock.calls.filter(([, opts]) => opts?.toolName === "async_subagent")).toHaveLength(3);
    const raw = fw.classify; let failed = false;
    fw.classify = vi.fn(async (text, options) => {
      if (options?.toolName === "async_subagent" && !failed) { failed = true; throw new Error("temporary"); }
      return raw(text, options);
    }) as typeof fw.classify;
    const req = request("fresh", "unsafe notification");
    const received: string[] = [];
    const handler = async (r: { messages: HumanMessage[] }) => { received.push(String(r.messages[0]?.content)); return new AIMessage("done"); };
    await middleware.wrapModelCall!(req as never, handler as never);
    await middleware.wrapModelCall!(req as never, handler as never);
    expect(received).toEqual(["unsafe notification", SAFE_TOOL_MESSAGE]);
  });

  it.each(["block", "warn", "shadow"] as const)("handles background notifications in %s mode before newer human messages", async mode => {
    for (const key of ["lc_source", "deepagents_notification"]) {
      const fw = firewall(); const middleware = createDeepAgentsMiddleware(fw, { mode });
      const note = new HumanMessage({ content: "unsafe result", additional_kwargs: { [key]: key === "lc_source" ? "async_subagent" : { status: "success" } } });
      const messages = [note, new HumanMessage("safe current question")];
      const handler = vi.fn(async () => new AIMessage("done"));
      await middleware.wrapModelCall!({ messages, state: { messages }, runtime: {} } as never, handler);
      const received = handler.mock.calls[0] as unknown as [{ messages: HumanMessage[] }];
      expect(received[0].messages[0]?.content).toBe(mode === "block" ? SAFE_TOOL_MESSAGE : note.content);
      expect(note.content).toBe("unsafe result");
    }
  });
});
