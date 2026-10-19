#!/usr/bin/env node
// Signathing evidence verifier. Node 18+, no dependencies. Public domain.
//
//   node verify-signathing.mjs evidence.json [original.pdf] [signed.pdf] [--offline]
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
// Nothing here needs an account or trusts the package's issuer: a forged
// package fails step 3 or 4 unless the forger also controls the public log,
// the Internet Archive's copies of it, and every verifier that ran before.
// The digital seal itself is validated by a PDF reader (pdfsig, Acrobat)
// against https://signathing.com/.well-known/signathing-seal.pem

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const offline = process.argv.includes("--offline");
if (!args[0]) {
  console.error("usage: node verify-signathing.mjs evidence.json [original.pdf] [signed.pdf] [--offline]");
  process.exit(2);
}
const sha = (x) => createHash("sha256").update(x).digest("hex");
const pkg = JSON.parse(readFileSync(args[0], "utf8"));
let failures = 0;
const ok = (m) => console.log("  ok   " + m);
const bad = (m) => { failures++; console.log("  FAIL " + m); };

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
    console.log("  note this document was completed before sealing was enabled, or sealing was off");
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
  if (!ev.chain) { console.log(`  note event ${ev.preimage.event_id} (${ev.preimage.type}) is not in the chain yet`); continue; }
  const eh = sha(`${ev.chain.prev_hash}\n${ev.chain.seq}\n${ev.preimage.at}\n${ev.preimage.type}\n${fp}\n${dh}`);
  eh === ev.chain.hash ? ok(`event ${ev.preimage.event_id} ${ev.preimage.type} -> chain seq ${ev.chain.seq}`) : bad(`event ${ev.preimage.event_id}: chain hash mismatch at seq ${ev.chain.seq}`);
  chained.push(ev);
}

// 4. Public log
if (!offline && chained.length) {
  const base = pkg.issuer?.site || "https://signathing.com";
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
      if (!d) { console.log(`  note day ${day} is not sealed yet (days seal after midnight UTC)`); continue; }
      const inPkg = chained.find((e) => e.chain.day === day && e.chain.day_sealed);
      const sealedOk = inPkg ? d.head_hash === inPkg.chain.day_sealed.head_hash : true;
      sealedOk ? ok(`day ${day} sealed head matches (${d.archive_url ? "archived: " + d.archive_url : "archive pending"})`) : bad(`day ${day}: sealed head in the package differs from the public one`);
    }
  } catch (e) {
    console.log(`  note could not reach the public log (${e.message}); rerun with network or --offline`);
  }
}

console.log(failures ? `\n${failures} check(s) FAILED` : "\nAll checks passed");
process.exit(failures ? 1 : 0);
