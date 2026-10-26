#!/usr/bin/env node
// Signathing MCP stdio bridge. No dependencies.
//
// Forwards MCP JSON-RPC messages (one per line on stdin, as MCP clients send
// them over stdio) to the remote Signathing MCP server over HTTPS, adding your
// API key. Use it only for clients that cannot speak Streamable HTTP MCP
// themselves; everything else should connect to https://signathing.com/api/mcp
// directly (OAuth or a bearer key).
//
//   SIGNATHING_API_KEY=sk_live_... npx github:jacejb/signathing-mcp
//
// Without a key the bridge still starts: initialize and ping are answered
// here, tool discovery (tools/list) is forwarded and works unauthenticated,
// and a tools/call comes back as a JSON-RPC error that says to set the key.
// That keeps directory health checks and "what tools are there" working,
// while nothing that touches an account runs without credentials.

import { createInterface } from "node:readline";

const URL = process.env.SIGNATHING_MCP_URL || "https://signathing.com/api/mcp";
const KEY = process.env.SIGNATHING_API_KEY || "";
const VERSION = "1.1.1";
const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];
if (!KEY) {
  process.stderr.write("signathing-mcp: SIGNATHING_API_KEY is not set; tool calls will be refused until it is (create one at https://signathing.com/dashboard/api)\n");
}

const out = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");

function local(message) {
  const id = message.id ?? null;
  const method = message.method || "";
  if (method.startsWith("notifications/")) return { handled: true, reply: null };
  if (method === "initialize") {
    const asked = message.params && typeof message.params.protocolVersion === "string" ? message.params.protocolVersion : "";
    return {
      handled: true,
      reply: {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "signathing", title: "Signathing e-signature", version: VERSION },
          instructions: KEY
            ? "Send PDFs for e-signature through Signathing. Every signing event lands in a public hash-chained evidence log; use get_evidence and the verifier to check a finished document."
            : "SIGNATHING_API_KEY is not set on this bridge. Tool discovery works; tool calls will fail until a key from https://signathing.com/dashboard/api is provided.",
        },
      },
    };
  }
  if (method === "ping") return { handled: true, reply: { jsonrpc: "2.0", id, result: {} } };
  return { handled: false };
}

async function forward(message) {
  const headers = { "content-type": "application/json", accept: "application/json" };
  if (KEY) headers.authorization = `Bearer ${KEY}`;
  const res = await fetch(URL, { method: "POST", headers, body: JSON.stringify(message) });
  if (res.status === 202) return null; // notification accepted
  const text = await res.text();
  try {
    const parsed = JSON.parse(text);
    // The server answers an unauthenticated request with id null; give the
    // caller back its own id so the error lands on the right request.
    if (parsed && typeof parsed === "object" && parsed.id === null && message.id !== undefined) parsed.id = message.id;
    return parsed;
  } catch {
    return { jsonrpc: "2.0", id: message.id ?? null, error: { code: -32603, message: `Signathing answered ${res.status}: ${text.slice(0, 200)}` } };
  }
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
// Requests still in flight when stdin closes get to finish before we exit.
const inflight = new Set();
rl.on("line", (line) => {
  const p = handle(line).catch(() => undefined);
  inflight.add(p);
  p.finally(() => inflight.delete(p));
});
async function handle(line) {
  const trimmed = line.trim();
  if (!trimmed) return;
  let message;
  try {
    message = JSON.parse(trimmed);
  } catch {
    out({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    return;
  }
  const l = local(message);
  if (l.handled) {
    if (l.reply) out(l.reply);
    return;
  }
  try {
    const reply = await forward(message);
    if (reply) out(reply);
  } catch (error) {
    out({ jsonrpc: "2.0", id: message.id ?? null, error: { code: -32603, message: `Could not reach Signathing: ${error?.message || error}` } });
  }
}
rl.on("close", () => {
  Promise.allSettled([...inflight]).then(() => process.exit(0));
});
