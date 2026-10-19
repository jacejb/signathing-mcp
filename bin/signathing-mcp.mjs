#!/usr/bin/env node
// Signathing MCP stdio bridge. Node 18+, no dependencies.
//
// Forwards MCP JSON-RPC from a stdio-only client (newline-delimited JSON on
// stdin) to the remote Signathing MCP server over HTTPS, adding your API key.
// Most clients can talk to https://signathing.com/api/mcp directly; use this
// only when yours cannot.
//
//   SIGNATHING_API_KEY=sk_live_... npx github:jacejb/signathing-mcp
//
// Optional: SIGNATHING_MCP_URL to point at another host.

import { createInterface } from "node:readline";

const URL = process.env.SIGNATHING_MCP_URL || "https://signathing.com/api/mcp";
const KEY = process.env.SIGNATHING_API_KEY || "";
if (!KEY) {
  process.stderr.write("signathing-mcp: set SIGNATHING_API_KEY (create one at https://signathing.com/dashboard/api)\n");
  process.exit(2);
}

const out = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");

async function forward(message) {
  const res = await fetch(URL, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", authorization: `Bearer ${KEY}` },
    body: JSON.stringify(message),
  });
  if (res.status === 202) return null; // notification accepted
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return { jsonrpc: "2.0", id: message.id ?? null, error: { code: -32603, message: `Signathing answered ${res.status}: ${text.slice(0, 200)}` } };
  }
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", async (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let message;
  try {
    message = JSON.parse(trimmed);
  } catch {
    out({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    return;
  }
  try {
    const reply = await forward(message);
    if (reply) out(reply);
  } catch (error) {
    out({ jsonrpc: "2.0", id: message.id ?? null, error: { code: -32603, message: `Could not reach Signathing: ${error?.message || error}` } });
  }
});
rl.on("close", () => process.exit(0));
