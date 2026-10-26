#!/usr/bin/env node
// Signathing agent loop: send a document, wait for the signature, pull the
// evidence package, and verify it against the public evidence log without
// trusting the sender, the agent, or Signathing. Node 18+, no dependencies.
// Public domain.
//
//   SIGNATHING_API_KEY=sk_live_... node agent-loop.mjs --name "Pat Lee" --email pat@example.com
//   SIGNATHING_API_KEY=sk_live_... node agent-loop.mjs --name "Pat Lee" --phone 2705550142 --pdf contract.pdf
//
// Options:
//   --name, --email, --phone   the one signer (email or phone, either one)
//   --pdf <file>               the PDF to send; without it a one-page sample is generated
//   --title <text>             document title (default "Agent loop test")
//   --wait <minutes>           how long to wait for the signature (default 30)
//   --out <dir>                where evidence.json, original.pdf and signed.pdf land (default ./agent-loop-<id>)
//
// What it prints is the point: an agent that runs this has a certified PDF
// whose hashes, events and public-log entries it checked itself. Get a key
// at https://signathing.com/dashboard/api (100 documents a month free, no card).

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const BASE = process.env.SIGNATHING_BASE || "https://signathing.com";
const KEY = process.env.SIGNATHING_API_KEY;
const argv = process.argv.slice(2);
const opt = (name, dflt = null) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : dflt;
};
if (!KEY || !KEY.startsWith("sk_live_")) die("Set SIGNATHING_API_KEY to a key from https://signathing.com/dashboard/api");
const signer = { name: opt("name"), email: opt("email"), phone: opt("phone") };
if (!signer.name || (!signer.email && !signer.phone)) die("Give --name and an --email or --phone for the signer.");
const title = opt("title", "Agent loop test");
const waitMinutes = Number(opt("wait", "30")) || 30;
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const step = (n, m) => console.log(`\n[${n}] ${m}`);
const ok = (m) => console.log("  ok   " + m);
const note = (m) => console.log("  note " + m);
function die(m) {
  console.error("error: " + m);
  process.exit(1);
}
async function api(path, init = {}) {
  const res = await fetch(`${BASE}/api/v1${path}`, { ...init, headers: { Authorization: `Bearer ${KEY}`, ...(init.headers || {}) } });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${init.method || "GET"} ${path} -> ${res.status} ${body.slice(0, 300)}`);
  }
  return res;
}

// ---------------------------------------------------------------------------
// 1. The document. A real agent brings its own PDF; this builds a one-pager
//    so the loop runs with nothing else on disk.
step(1, "Document");
let pdf;
const pdfPath = opt("pdf");
if (pdfPath) {
  pdf = readFileSync(pdfPath);
  ok(`read ${pdfPath} (${pdf.length} bytes)`);
} else {
  pdf = samplePdf([title, "", `Prepared by an agent at ${new Date().toISOString()}.`, "", "By signing, the signer confirms they received this test document.", "", "Signature: ______________________________"]);
  ok(`generated a one-page sample PDF (${pdf.length} bytes)`);
}
const originalSha = sha256(pdf);
ok(`SHA-256 of the original: ${originalSha}`);

// ---------------------------------------------------------------------------
// 2. Send it. One multipart POST; the signer gets a private link by email or
//    text. The response carries the signing link too, so a demo can be signed
//    at once instead of waiting for the inbox.
step(2, "Send for signature");
const form = new FormData();
form.set("file", new Blob([pdf], { type: "application/pdf" }), pdfPath ? pdfPath.split(/[\\/]/).pop() : "agent-loop.pdf");
form.set("title", title);
form.set("message", "Sent by the Signathing agent loop example.");
form.set("signers", JSON.stringify([{ name: signer.name, ...(signer.email ? { email: signer.email } : {}), ...(signer.phone ? { phone: signer.phone } : {}) }]));
form.set("fields", JSON.stringify([{ id: "sig1", type: "signature", signerIndex: 0, page: 1, x: 22, y: 20, w: 40, h: 5 }]));
const created = await (await api("/documents", { method: "POST", body: form })).json();
ok(`document ${created.id} (${created.status}); billing ${JSON.stringify(created.billing ?? {})}`);
if (created.original_sha256 !== originalSha) die(`the server's original_sha256 (${created.original_sha256}) is not the file we sent`);
ok("server's original_sha256 matches the bytes we sent");
const link = created.signers?.[0]?.signing_url;
if (link) note(`signing link (also delivered to the signer): ${link}`);

const outDir = opt("out", `./agent-loop-${created.id}`);
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "original.pdf"), pdf);

// ---------------------------------------------------------------------------
// 3. Wait for the signature. A production agent would use the webhook
//    (document.completed); polling keeps this example to one file.
step(3, `Waiting for ${signer.name} to sign (up to ${waitMinutes} min)`);
const deadline = Date.now() + waitMinutes * 60_000;
let doc = created;
while (doc.status !== "completed") {
  if (["voided", "declined", "expired"].includes(doc.status)) die(`document ended as ${doc.status}`);
  if (Date.now() > deadline) die("timed out waiting for the signature; the document stays open, run get_document later");
  await new Promise((r) => setTimeout(r, 5000));
  doc = await (await api(`/documents/${created.id}`)).json();
  const s = doc.signers?.[0];
  if (process.stdout.isTTY) process.stdout.write(`  ${new Date().toISOString().slice(11, 19)} status=${doc.status} signer=${s?.status}\r`);
  else if (Date.now() % 30000 < 5000) console.log(`  ${new Date().toISOString().slice(11, 19)} status=${doc.status} signer=${s?.status}`);
}
console.log();
ok(`completed at ${doc.completed_at}; signed PDF SHA-256 ${doc.signed_sha256}; sealed=${doc.sealed}`);

// ---------------------------------------------------------------------------
// 4. Pull the evidence package and the certified PDF.
step(4, "Evidence package and certified PDF");
const evidence = await (await api(`/documents/${created.id}/evidence`)).json();
writeFileSync(join(outDir, "evidence.json"), JSON.stringify(evidence, null, 2));
const signed = Buffer.from(await (await api(`/documents/${created.id}/download?which=signed`)).arrayBuffer());
writeFileSync(join(outDir, "signed.pdf"), signed);
ok(`evidence.json (${evidence.events.length} events) and signed.pdf (${signed.length} bytes) written to ${outDir}`);
if (sha256(signed) !== evidence.document.signed_sha256) die("the signed PDF we downloaded does not hash to document.signed_sha256");
ok("signed PDF hashes to document.signed_sha256");
if (evidence.document.original_sha256 !== originalSha) die("evidence.document.original_sha256 is not our original");
ok("evidence package names our original's hash");

// ---------------------------------------------------------------------------
// 5. Verify independently. The public verifier recomputes every hash, checks
//    every event against the public log, and (once the UTC day is sealed)
//    checks the day head against the Internet Archive snapshot and the
//    OpenTimestamps proof. It is a separate program on purpose: a stranger
//    can run it on a package you hand them.
step(5, "Independent verification");
const verifierPath = join(outDir, "verify-signathing.mjs");
if (!existsSync(verifierPath)) {
  const src = await (await fetch(`${BASE}/verifier/verify-signathing.mjs`)).text();
  writeFileSync(verifierPath, src);
  note(`downloaded the verifier from ${BASE}/verifier/verify-signathing.mjs (also in github.com/jacejb/signathing-mcp)`);
}
const run = spawnSync(process.execPath, [verifierPath, join(outDir, "evidence.json"), join(outDir, "original.pdf"), join(outDir, "signed.pdf")], { encoding: "utf8" });
process.stdout.write(run.stdout);
if (run.stderr) process.stderr.write(run.stderr);
if (run.status !== 0) die("the verifier reported a failure (see above)");

// ---------------------------------------------------------------------------
// 6. The two things a human might actually look at.
step(6, "Public checks anyone can repeat");
const code = evidence.signers[0]?.verification_code;
if (code) {
  const v = await (await fetch(`${BASE}/api/verify?code=${encodeURIComponent(code)}`)).json();
  if (!v.found || v.signedSha256 !== evidence.document.signed_sha256) die("the public verification code lookup does not match the package");
  ok(`verification code ${code} resolves publicly to this document and its signed hash (${BASE}/verify?code=${code})`);
}
const lastChain = [...evidence.events].reverse().find((e) => e.chain)?.chain;
if (lastChain) {
  ok(`last event is public log entry #${lastChain.seq} (${lastChain.log_url})`);
  if (lastChain.day_sealed) ok(`its day ${lastChain.day} is sealed: head ${lastChain.day_sealed.head_hash.slice(0, 16)}..., Internet Archive ${lastChain.day_sealed.archive_url || "pending"}, Bitcoin block ${lastChain.day_sealed.bitcoin_height || "pending"}`);
  else note(`day ${lastChain.day} seals at 00:00 UTC; run the verifier on evidence.json again after that for the Internet Archive and OpenTimestamps checks`);
}
console.log(`\nVERIFIED: document ${created.id}, signed by ${signer.name}, ${evidence.events.length} events, all hashes and public-log entries recomputed. Files in ${outDir}.`);

// ---------------------------------------------------------------------------
// A minimal PDF writer: one US Letter page of Helvetica lines. Enough for a
// test document; bring a real PDF for anything else.
function samplePdf(lines) {
  const esc = (s) => s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
  const content = ["BT", "/F1 14 Tf", "72 720 Td", "18 TL", ...lines.map((l, i) => `${i ? "T* " : ""}(${esc(l)}) Tj`), "ET"].join("\n");
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`,
  ];
  let out = "%PDF-1.4\n";
  const offsets = [];
  objects.forEach((o, i) => {
    offsets.push(Buffer.byteLength(out));
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = Buffer.byteLength(out);
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map((o) => String(o).padStart(10, "0") + " 00000 n \n").join("")}trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}
