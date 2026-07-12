#!/usr/bin/env node
// fetch-chain — connect to a TLS/mTLS server, print its certificate chain,
// and save the CA and intermediate certificates as PEM files.
// If the server omits the root (they usually do), the chain is completed
// from the system CA store (or --castore bundles), with actual signature
// verification of each added link.
//
// Zero dependencies; Node ≥ 16.

import tls from "node:tls";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { X509Certificate } from "node:crypto";

const SYSTEM_BUNDLES = [
  "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
  "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
  "/etc/ssl/ca-bundle.pem",             // openSUSE
  "/etc/ssl/cert.pem",                  // Alpine, macOS
];

const USAGE = `usage: fetch-chain.mjs <host>[:port] [options]
       (IPv6: fetch-chain.mjs [2001:db8::1]:8443 or a bare address)

options:
  --port <n>        port if not given as host:port     (default 443)
  --sni <name>      SNI servername                     (default: host)
  --cert <file>     client certificate for mTLS (PEM)
  --key <file>      client private key for mTLS (PEM)
  --outdir <dir>    where to save PEM files            (default: chain/)
  --castore <file>  PEM bundle used to complete the chain (repeatable;
                    default: the system CA store — note that system
                    stores hold roots only; for missing intermediates
                    point this at pkitree's intermediates.pem)
  --include-leaf    also save the leaf certificate
  -h, --help        this text

Certificate verification of the server is disabled on purpose: the point
is to retrieve chains from private/unknown PKIs. Certificates added from
the CA store, however, are only accepted if they cryptographically
verify the chain link.`;

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

function parseArgs(argv) {
  const opts = { port: 443, outdir: "chain", castore: [], includeLeaf: false };
  const pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--port":         opts.port = Number(argv[++i]); break;
      case "--sni":          opts.sni = argv[++i]; break;
      case "--cert":         opts.cert = argv[++i]; break;
      case "--key":          opts.key = argv[++i]; break;
      case "--outdir":       opts.outdir = argv[++i]; break;
      case "--castore":      opts.castore.push(argv[++i]); break;
      case "--include-leaf": opts.includeLeaf = true; break;
      case "-h": case "--help": console.log(USAGE); process.exit(0);
      default:
        if (a.startsWith("-")) fail(`unknown option ${a}\n\n${USAGE}`);
        pos.push(a);
    }
  }
  if (pos.length !== 1) fail(`expected exactly one host argument\n\n${USAGE}`);
  // host forms: name, name:port, [v6]:port, [v6], bare v6 (no port possible)
  let host, port;
  const bracketed = pos[0].match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) [, host, port] = bracketed;
  else if ((pos[0].match(/:/g) || []).length > 1) host = pos[0]; // bare IPv6
  else [host, port] = pos[0].split(":");
  opts.host = host;
  if (port) opts.port = Number(port);
  if (!Number.isInteger(opts.port) || opts.port < 1 || opts.port > 65535)
    fail(`invalid port: ${opts.port}`);
  if (!!opts.cert !== !!opts.key) fail("--cert and --key must be given together");
  return opts;
}

function toPem(der) {
  return "-----BEGIN CERTIFICATE-----\n"
    + der.toString("base64").match(/.{1,64}/g).join("\n")
    + "\n-----END CERTIFICATE-----\n";
}

/* ---------- chain records: one uniform shape for server + store certs ---------- */

const nameOf = (dn) => dn?.CN || dn?.O || "(unknown)";                    // tls peer cert DN object
const cnOf = (s) => s.match(/^CN=(.*)$/m)?.[1] ?? s.match(/^O=(.*)$/m)?.[1] ?? "(unknown)"; // X509Certificate DN string
const dnStr = (dn) => Object.entries(dn ?? {})                            // full DN, tls object form
  .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("+") : v}`).join(", ") || "(unknown)";
const dnFlat = (s) => s.split("\n").join(", ");                           // full DN, X509Certificate form

// Walk the issuerCertificate linked list; a self-signed root points at itself.
function presentedChain(peerCert) {
  const records = [];
  const seen = new Set();
  for (let c = peerCert; c && !seen.has(c.fingerprint256); c = c.issuerCertificate) {
    seen.add(c.fingerprint256);
    records.push({
      cn: nameOf(c.subject), subject: dnStr(c.subject), issuer: dnStr(c.issuer),
      validTo: c.valid_to, raw: c.raw,
      selfSigned: JSON.stringify(c.subject) === JSON.stringify(c.issuer),
      fromStore: false,
    });
  }
  return records;
}

function loadStore(files) {
  const pool = [];
  const pemRe = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  for (const f of files) {
    if (!fs.existsSync(f)) continue;
    for (const block of fs.readFileSync(f, "utf8").match(pemRe) ?? []) {
      try { pool.push(new X509Certificate(block)); } catch { /* skip junk */ }
    }
  }
  return pool;
}

// System store: first OS bundle found + Node's bundled Mozilla roots
// (tls.rootCertificates also picks up NODE_EXTRA_CA_CERTS).
function systemPool() {
  const bundle = SYSTEM_BUNDLES.find(f => fs.existsSync(f));
  const pool = bundle ? loadStore([bundle]) : [];
  for (const pem of tls.rootCertificates) {
    try { pool.push(new X509Certificate(pem)); } catch { /* skip junk */ }
  }
  return pool;
}

// Append missing issuers from the CA store; each link must verify cryptographically.
// Handles cross-signed tops (e.g. GTS Root R1 signed by a since-removed GlobalSign
// root): if the top's own subject+key exist self-signed in the store, that root is
// the modern trust anchor and is appended instead.
function completeChain(records, storeFiles) {
  if (records[records.length - 1].selfSigned) return;
  const pool = storeFiles.length ? loadStore(storeFiles) : systemPool();
  if (!pool.length) {
    console.error("note: no CA store found — chain completion skipped");
    return;
  }
  const spki = (c) => c.publicKey.export({ type: "spki", format: "der" });
  const push = (c) => records.push({
    cn: cnOf(c.subject), subject: dnFlat(c.subject), issuer: dnFlat(c.issuer),
    validTo: c.validTo, raw: c.raw, selfSigned: c.checkIssued(c), fromStore: true,
  });
  let top = new X509Certificate(records[records.length - 1].raw);
  const seen = new Set([top.fingerprint256]);
  while (!top.checkIssued(top)) {
    const next =
      pool.find(p => top.checkIssued(p) && top.verify(p.publicKey))          // real issuer
      ?? pool.find(p => p.subject === top.subject && p.checkIssued(p)        // self-signed
                     && spki(p).equals(spki(top)));                          //   sibling of a
    if (!next || seen.has(next.fingerprint256)) break;                       //   cross-signed top
    seen.add(next.fingerprint256);
    push(next);
    top = next;
  }
  if (!records[records.length - 1].selfSigned)
    console.error("note: root not found — server chain incomplete and no CA store match "
      + "(try --castore with the PKI's CA bundle)");
}

/* ---------- output ---------- */

const roleOf = (r, index) =>
  index === 0 ? "leaf" : r.selfSigned ? "root" : "intermediate";
const sanitize = (s) => s.replace(/[^A-Za-z0-9._-]+/g, "_");

function printChain(records) {
  const rows = records.map((r, i) => [
    String(i), roleOf(r, i), r.subject, r.issuer, r.validTo, r.fromStore ? "CA store" : "server",
  ]);
  const head = ["#", "role", "subject", "issuer", "not after", "source"];
  const w = head.map((h, col) => Math.max(h.length, ...rows.map(r => r[col].length)));
  const line = (r) => r.map((cell, col) => cell.padEnd(w[col])).join("  ");
  console.log(line(head));
  for (const r of rows) console.log(line(r));
}

function saveChain(records, opts) {
  fs.mkdirSync(opts.outdir, { recursive: true });
  const saved = [];
  records.forEach((r, i) => {
    const role = roleOf(r, i);
    if (role === "leaf" && !opts.includeLeaf) return;
    const file = path.join(opts.outdir,
      `${String(i).padStart(2, "0")}-${role}-${sanitize(r.cn)}.pem`);
    fs.writeFileSync(file, toPem(r.raw));
    saved.push(file);
  });
  return saved;
}

/* ---------- main ---------- */

function readFileOr(file, what) {
  try { return fs.readFileSync(file); }
  catch (e) { fail(`cannot read ${what} ${file}: ${e.message}`); }
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  let done = false;
  const socket = tls.connect({
    host: opts.host,
    port: opts.port,
    servername: opts.sni ?? (net.isIP(opts.host) ? undefined : opts.host), // RFC 6066: no IP literals in SNI
    rejectUnauthorized: false,
    cert: opts.cert && readFileOr(opts.cert, "client certificate"),
    key: opts.key && readFileOr(opts.key, "client key"),
  }, () => {
    console.log(`connected: ${opts.host}:${opts.port} `
      + `(${socket.getProtocol()}, ${socket.getCipher().name})`
      + `${opts.cert ? ", client certificate presented" : ""}\n`);
    const records = presentedChain(socket.getPeerCertificate(true));
    socket.end();
    if (!records.length) fail("server presented no certificate");
    completeChain(records, opts.castore);
    printChain(records);
    const saved = saveChain(records, opts);
    console.log(saved.length
      ? `\nsaved:\n${saved.map(f => "  " + f).join("\n")}`
      : "\nnothing saved (only a leaf was presented; use --include-leaf to save it)");
    done = true; // late TLS alerts (e.g. "certificate required" in TLS 1.3) are harmless now
  });
  socket.setTimeout(10000, () => { if (!done) fail("connection timed out"); });
  socket.on("error", (e) => { if (!done) fail(
    `${e.message}${opts.cert ? "" : " (does the server require a client certificate? try --cert/--key)"}`); });
}

main();
