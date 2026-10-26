#!/usr/bin/env node
// Signathing evidence verifier. Node 18+, no dependencies. Public domain.
//
//   node verify-signathing.mjs evidence.json [original.pdf] [signed.pdf] [--offline] [--ots-dir <dir>]
//   node verify-signathing.mjs --day <YYYY-MM-DD> <head_hash> [proof.ots]
//
// Checks, in order:
//   1. The PDFs you hold hash to the SHA-256 values in the package, and the
//      signed PDF carries a digital seal when the package says it does.
//   2. Every event's canonical preimage hashes to its detail_hash.
//   3. Every event's chain entry hash recomputes from (prev_hash, seq, at,
//      type, fingerprint, detail_hash), and the document fingerprint
//      recomputes from the document id and original SHA-256.
//   4. (online) Each entry in Signathing's public log is byte-identical to the
//      one in the package, the entries before and after it link to it, and the
//      sealed day head published at /api/evidence/days matches.
//   5. The OpenTimestamps proof of each sealed day (downloaded, or read from
//      --ots-dir, e.g. a clone of github.com/jacejb/signathing-evidence-log
//      with its days/ folder): the proof's digest is the day's head hash, every
//      step recomputes, and (online) the Bitcoin block it names has that
//      merkle root. The --day form runs only this check for one day.
// Nothing here needs an account or trusts the package's issuer: a forged
// package fails step 3, 4 or 5 unless the forger also controls the public log,
// the Internet Archive's copies of it, the Bitcoin blockchain, and every
// verifier that ran before. The digital seal itself is validated by a PDF
// reader (pdfsig, Acrobat) against https://signathing.com/.well-known/signathing-seal.pem

import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const argv = process.argv.slice(2);
const offline = argv.includes("--offline");
const otsDirIdx = argv.indexOf("--ots-dir");
const otsDir = otsDirIdx >= 0 ? argv[otsDirIdx + 1] : null;
const dayIdx = argv.indexOf("--day");
// Positional args: everything that is not a flag or a flag's value. (A bug
// until Oct 26 2026: with no --ots-dir or --day present the index math
// compared against -1 + 1 and dropped the first positionals, so the main
// documented invocation printed the usage line.)
const taken = new Set();
if (otsDirIdx >= 0) taken.add(otsDirIdx + 1);
if (dayIdx >= 0) [1, 2, 3].forEach((k) => taken.add(dayIdx + k));
const args = argv.filter((a, i) => !a.startsWith("--") && !taken.has(i));

const sha = (x) => createHash("sha256").update(x).digest("hex");
let failures = 0;
const ok = (m) => console.log("  ok   " + m);
const bad = (m) => { failures++; console.log("  FAIL " + m); };
const note = (m) => console.log("  note " + m);

// ---------------------------------------------------------------------------
// OpenTimestamps (.ots) support: enough of the format to recompute a proof.
// Reference: python-opentimestamps. Ops: sha256 0x08, sha1 0x02, ripemd160
// 0x03, reverse 0xf2, hexlify 0xf3, append 0xf0, prepend 0xf1. Attestations:
// pending (calendar uri) 83dfe30d2ef90c8e, bitcoin (block height) 0588960d73d71901.
const OTS_MAGIC = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
function otsParse(file) {
  if (!file.subarray(0, OTS_MAGIC.length).equals(OTS_MAGIC)) throw new Error("not an .ots file (bad magic)");
  const pos = { i: OTS_MAGIC.length };
  const varuint = () => { let v = 0, shift = 0; for (;;) { const b = file[pos.i++]; if (b === undefined) throw new Error("truncated"); v += (b & 0x7f) * 2 ** shift; if (!(b & 0x80)) return v; shift += 7; } };
  const varbytes = () => { const n = varuint(); const out = file.subarray(pos.i, pos.i + n); pos.i += n; return out; };
  const version = varuint();
  if (version !== 1) throw new Error(`unsupported version ${version}`);
  if (file[pos.i++] !== 0x08) throw new Error("file hash op is not sha256");
  const digest = Buffer.from(file.subarray(pos.i, pos.i + 32));
  pos.i += 32;
  const attestations = []; // { msg, kind, height | uri }
  const apply = (tag, msg) => {
    switch (tag) {
      case 0x08: return createHash("sha256").update(msg).digest();
      case 0x02: return createHash("sha1").update(msg).digest();
      case 0x03: return createHash("ripemd160").update(msg).digest();
      case 0xf2: return Buffer.from(msg).reverse();
      case 0xf3: return Buffer.from(msg.toString("hex"), "utf8");
      case 0xf0: return Buffer.concat([msg, varbytes()]);
      case 0xf1: return Buffer.concat([varbytes(), msg]);
      default: throw new Error(`unknown op 0x${tag.toString(16)}`);
    }
  };
  const readAttestation = (msg) => {
    const tag = file.subarray(pos.i, pos.i + 8).toString("hex");
    pos.i += 8;
    const payload = varbytes();
    if (tag === "0588960d73d71901") { let v = 0, shift = 0, j = 0; for (;;) { const b = payload[j++]; v += (b & 0x7f) * 2 ** shift; if (!(b & 0x80)) break; shift += 7; } attestations.push({ msg, kind: "bitcoin", height: v }); }
    else if (tag === "83dfe30d2ef90c8e") { let n = 0, shift = 0, j = 0; for (;;) { const b = payload[j++]; n += (b & 0x7f) * 2 ** shift; if (!(b & 0x80)) break; shift += 7; } attestations.push({ msg, kind: "pending", uri: payload.subarray(j, j + n).toString("utf8") }); }
    else attestations.push({ msg, kind: "unknown", tag });
  };
  const timestamp = (msg, depth) => {
    if (depth > 256) throw new Error("too deep");
    const branch = (tag) => { if (tag === 0x00) readAttestation(msg); else timestamp(apply(tag, msg), depth + 1); };
    let tag = file[pos.i++];
    while (tag === 0xff) { branch(file[pos.i++]); tag = file[pos.i++]; }
    branch(tag);
  };
  timestamp(digest, 0);
  return { digest, attestations };
}

async function checkOtsProof(day, headHash, proofBytes, online) {
  let proof;
  try { proof = otsParse(proofBytes); } catch (e) { bad(`day ${day}: .ots proof does not parse (${e.message})`); return; }
  proof.digest.toString("hex") === headHash ? ok(`day ${day}: .ots proof is for the sealed head ${headHash.slice(0, 16)}...`) : bad(`day ${day}: .ots proof digest ${proof.digest.toString("hex")} is not the sealed head`);
  const bitcoin = proof.attestations.filter((a) => a.kind === "bitcoin");
  const pending = proof.attestations.filter((a) => a.kind === "pending");
  if (!bitcoin.length) { note(`day ${day}: no Bitcoin attestation yet (pending at ${pending.map((p) => p.uri).join(", ") || "no calendar"}); the calendars anchor within hours`); return; }
  for (const a of bitcoin) {
    const merkleRootLE = a.msg; // internal byte order; explorers show it reversed
    if (!online) { note(`day ${day}: proof commits to Bitcoin block ${a.height} with merkle root ${Buffer.from(merkleRootLE).reverse().toString("hex")} (rerun online to check the block)`); continue; }
    try {
      const hashRes = await fetch(`https://blockstream.info/api/block-height/${a.height}`);
      if (!hashRes.ok) throw new Error(`block-height ${hashRes.status}`);
      const blockHash = (await hashRes.text()).trim();
      const block = await (await fetch(`https://blockstream.info/api/block/${blockHash}`)).json();
      const expected = Buffer.from(merkleRootLE).reverse().toString("hex");
      block.merkle_root === expected
        ? ok(`day ${day}: Bitcoin block ${a.height} (${new Date(block.timestamp * 1000).toISOString()}) has merkle root ${expected.slice(0, 16)}..., so the head existed before that block`)
        : bad(`day ${day}: Bitcoin block ${a.height} merkle root ${block.merkle_root} differs from the proof's ${expected}`);
    } catch (e) {
      note(`day ${day}: could not reach a block explorer (${e.message}); the proof commits to block ${a.height}`);
    }
  }
}

async function otsBytesFor(day, base, otsUrl) {
  if (otsDir) {
    const f = join(otsDir, `${day}.ots`);
    if (existsSync(f)) return readFileSync(f);
    const g = join(otsDir, "days", `${day}.ots`);
    if (existsSync(g)) return readFileSync(g);
  }
  if (offline) return null;
  const url = otsUrl || `${base}/api/evidence/days/${day}.ots`;
  const res = await fetch(url);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

// ---------------------------------------------------------------------------
// --day mode: one sealed day's proof, no package needed.
if (dayIdx >= 0) {
  const day = argv[dayIdx + 1];
  const head = argv[dayIdx + 2];
  const file = argv[dayIdx + 3] && !argv[dayIdx + 3].startsWith("--") ? argv[dayIdx + 3] : null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day || "") || !/^[0-9a-f]{64}$/.test(head || "")) {
    console.error("usage: node verify-signathing.mjs --day YYYY-MM-DD <head_hash hex> [proof.ots] [--offline]");
    process.exit(2);
  }
  console.log(`Signathing evidence log, sealed day ${day}`);
  const bytes = file ? readFileSync(file) : await otsBytesFor(day, "https://signathing.com", null);
  if (!bytes) bad(`no proof for ${day} (not published yet, or run online)`);
  else await checkOtsProof(day, head, bytes, !offline);
  console.log(failures ? `\n${failures} check(s) FAILED` : "\nAll checks passed");
  process.exit(failures ? 1 : 0);
}

if (!args[0]) {
  console.error("usage: node verify-signathing.mjs evidence.json [original.pdf] [signed.pdf] [--offline] [--ots-dir <dir>]");
  process.exit(2);
}
const pkg = JSON.parse(readFileSync(args[0], "utf8"));

console.log(`Signathing evidence package for document ${pkg.document.id} ("${pkg.document.title}"), status ${pkg.document.status}`);

// 1. Files
if (args[1]) {
  const h = sha(readFileSync(args[1]));
  h === pkg.document.original_sha256 ? ok(`original PDF matches ${h}`) : bad(`original PDF hashes to ${h}, package says ${pkg.document.original_sha256}`);
}
if (args[2]) {
  const signedBytes = readFileSync(args[2]);
  const h = sha(signedBytes);
  h === pkg.document.signed_sha256 ? ok(`signed PDF matches ${h}`) : bad(`signed PDF hashes to ${h}, package says ${pkg.document.signed_sha256}`);
  const tail = signedBytes.subarray(Math.max(0, signedBytes.length - 2000000)).toString("latin1");
  const sigDict = /\/Type\s*\/Sig\b/;
  const byteRange = /\/ByteRange\s*\[/;
  const sealed = sigDict.test(tail) && byteRange.test(tail);
  if (pkg.document.sealed_at) {
    sealed
      ? ok(`signed PDF carries a digital seal (validate it with pdfsig or Acrobat; certificate ${pkg.document.seal?.fingerprint_sha256 || ""})`)
      : bad("package says sealed but the PDF has no signature dictionary");
  } else {
    note("this document was completed before sealing was enabled, or sealing was off");
  }
}

// 2 + 3. Hashes inside the package
const fp = sha(`signathing-doc:${pkg.document.id}:${pkg.document.original_sha256}`);
fp === pkg.document.fingerprint ? ok(`fingerprint recomputes (${fp.slice(0, 16)}...)`) : bad(`fingerprint mismatch: computed ${fp}`);

const canonical = (p) => JSON.stringify({ event_id: p.event_id, request_id: p.request_id, signer_id: p.signer_id, type: p.type, at: p.at, detail: p.detail, ip: p.ip, user_agent: p.user_agent, original_sha256: p.original_sha256, signed_sha256: p.signed_sha256 });
const chained = [];
for (const ev of pkg.events) {
  const c = canonical(ev.preimage);
  if (c !== ev.canonical) bad(`event ${ev.preimage.event_id}: canonical string differs from the package's`);
  const dh = sha(c);
  if (dh !== ev.detail_hash) bad(`event ${ev.preimage.event_id}: detail_hash mismatch`);
  if (!ev.chain) { note(`event ${ev.preimage.event_id} (${ev.preimage.type}) is not in the chain yet`); continue; }
  const eh = sha(`${ev.chain.prev_hash}\n${ev.chain.seq}\n${ev.preimage.at}\n${ev.preimage.type}\n${fp}\n${dh}`);
  eh === ev.chain.hash ? ok(`event ${ev.preimage.event_id} ${ev.preimage.type} -> chain seq ${ev.chain.seq}`) : bad(`event ${ev.preimage.event_id}: chain hash mismatch at seq ${ev.chain.seq}`);
  chained.push(ev);
}

const base = pkg.issuer?.site || "https://signathing.com";
const sealedDays = new Map(); // day -> { head_hash, ots_url }
for (const ev of chained) if (ev.chain.day_sealed) sealedDays.set(ev.chain.day, { head_hash: ev.chain.day_sealed.head_hash, ots_url: ev.chain.day_sealed.ots_url || null });

// 4. Public log
if (!offline && chained.length) {
  const seqs = chained.map((e) => e.chain.seq);
  const from = Math.max(1, Math.min(...seqs) - 1);
  const to = Math.max(...seqs) + 1;
  try {
    const log = await (await fetch(`${base}/api/evidence/log?from=${from}&to=${to}`)).json();
    const bySeq = new Map(log.entries.map((e) => [e.seq, e]));
    for (const ev of chained) {
      const pub = bySeq.get(ev.chain.seq);
      if (!pub) { bad(`seq ${ev.chain.seq} is not in the public log`); continue; }
      const same = pub.hash === ev.chain.hash && pub.prev_hash === ev.chain.prev_hash && pub.detail_hash === ev.detail_hash && pub.fingerprint === fp && pub.at === ev.preimage.at && pub.type === ev.preimage.type;
      same ? ok(`seq ${ev.chain.seq} is identical in the public log`) : bad(`seq ${ev.chain.seq} differs in the public log`);
      const next = bySeq.get(ev.chain.seq + 1);
      if (next && next.prev_hash !== ev.chain.hash) bad(`seq ${ev.chain.seq + 1} does not link back to seq ${ev.chain.seq}`);
      const prev = bySeq.get(ev.chain.seq - 1);
      if (prev && prev.hash !== ev.chain.prev_hash) bad(`seq ${ev.chain.seq} does not link back to seq ${ev.chain.seq - 1}`);
    }
    // Recompute every link in the fetched slice.
    let prevHash = null;
    for (const e of log.entries) {
      if (prevHash !== null && e.prev_hash !== prevHash) bad(`public log: seq ${e.seq} prev_hash does not match seq ${e.seq - 1}`);
      const eh = sha(`${e.prev_hash}\n${e.seq}\n${e.at}\n${e.type}\n${e.fingerprint}\n${e.detail_hash}`);
      if (eh !== e.hash) bad(`public log: seq ${e.seq} hash does not recompute`);
      prevHash = e.hash;
    }
    ok(`public log slice ${from} to ${to} recomputes end to end`);
    const days = await (await fetch(`${base}/api/evidence/days`)).json();
    for (const day of [...new Set(chained.map((e) => e.chain.day))]) {
      const d = days.days.find((x) => x.day === day);
      if (!d) { note(`day ${day} is not sealed yet (days seal after midnight UTC)`); continue; }
      const inPkg = sealedDays.get(day);
      const sealedOk = inPkg ? d.head_hash === inPkg.head_hash : true;
      sealedOk ? ok(`day ${day} sealed head matches (${d.archive_url ? "archived: " + d.archive_url : "archive pending"})`) : bad(`day ${day}: sealed head in the package differs from the public one`);
      if (!sealedDays.has(day)) sealedDays.set(day, { head_hash: d.head_hash, ots_url: d.ots_url || null });
      else if (d.ots_url && !sealedDays.get(day).ots_url) sealedDays.get(day).ots_url = d.ots_url;
    }
  } catch (e) {
    note(`could not reach the public log (${e.message}); rerun with network or --offline`);
  }
}

// 5. OpenTimestamps proofs of the sealed days
for (const [day, info] of sealedDays) {
  try {
    const bytes = await otsBytesFor(day, base, info.ots_url);
    if (!bytes) { note(`day ${day}: no OpenTimestamps proof ${offline ? "in --ots-dir" : "published yet"}`); continue; }
    await checkOtsProof(day, info.head_hash, bytes, !offline);
  } catch (e) {
    note(`day ${day}: could not fetch the OpenTimestamps proof (${e.message})`);
  }
}

console.log(failures ? `\n${failures} check(s) FAILED` : "\nAll checks passed");
process.exit(failures ? 1 : 0);
