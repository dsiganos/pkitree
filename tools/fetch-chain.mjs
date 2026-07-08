#!/usr/bin/env node
// fetch-chain — connect to a TLS/mTLS server, print its certificate chain,
// and save the CA and intermediate certificates as PEM files.
//
// Zero dependencies; Node ≥ 16.

import tls from "node:tls";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const USAGE = `usage: fetch-chain.mjs <host>[:port] [options]

options:
  --port <n>        port if not given as host:port     (default 443)
  --sni <name>      SNI servername                     (default: host)
  --cert <file>     client certificate for mTLS (PEM)
  --key <file>      client private key for mTLS (PEM)
  --outdir <dir>    where to save PEM files            (default: chain/)
  --include-leaf    also save the leaf certificate
  -h, --help        this text

Certificate verification is disabled on purpose: the point is to
retrieve chains from private/unknown PKIs. Do not treat a successful
connection as trust.`;

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

function parseArgs(argv) {
  const opts = { port: 443, outdir: "chain", includeLeaf: false };
  const pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--port":         opts.port = Number(argv[++i]); break;
      case "--sni":          opts.sni = argv[++i]; break;
      case "--cert":         opts.cert = argv[++i]; break;
      case "--key":          opts.key = argv[++i]; break;
      case "--outdir":       opts.outdir = argv[++i]; break;
      case "--include-leaf": opts.includeLeaf = true; break;
      case "-h": case "--help": console.log(USAGE); process.exit(0);
      default:
        if (a.startsWith("-")) fail(`unknown option ${a}\n\n${USAGE}`);
        pos.push(a);
    }
  }
  if (pos.length !== 1) fail(`expected exactly one host argument\n\n${USAGE}`);
  const [host, port] = pos[0].split(":");
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

// Walk the issuerCertificate linked list; a self-signed root points at itself.
function chainOf(peerCert) {
  const chain = [];
  const seen = new Set();
  for (let c = peerCert; c && !seen.has(c.fingerprint256); c = c.issuerCertificate) {
    seen.add(c.fingerprint256);
    chain.push(c);
  }
  return chain;
}

function roleOf(cert, index) {
  if (index === 0) return "leaf";
  const selfSigned = JSON.stringify(cert.subject) === JSON.stringify(cert.issuer);
  return selfSigned ? "root" : "intermediate";
}

const nameOf = (dn) => dn?.CN || dn?.O || "(unknown)";
const sanitize = (s) => s.replace(/[^A-Za-z0-9._-]+/g, "_");

function printChain(chain) {
  const rows = chain.map((c, i) => [
    String(i), roleOf(c, i), nameOf(c.subject), nameOf(c.issuer), c.valid_to,
  ]);
  const head = ["#", "role", "subject", "issuer", "not after"];
  const w = head.map((h, col) => Math.max(h.length, ...rows.map(r => r[col].length)));
  const line = (r) => r.map((cell, col) => cell.padEnd(w[col])).join("  ");
  console.log(line(head));
  for (const r of rows) console.log(line(r));
}

function saveChain(chain, opts) {
  fs.mkdirSync(opts.outdir, { recursive: true });
  const saved = [];
  chain.forEach((c, i) => {
    const role = roleOf(c, i);
    if (role === "leaf" && !opts.includeLeaf) return;
    const file = path.join(opts.outdir,
      `${String(i).padStart(2, "0")}-${role}-${sanitize(nameOf(c.subject))}.pem`);
    fs.writeFileSync(file, toPem(c.raw));
    saved.push(file);
  });
  return saved;
}

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
    servername: opts.sni ?? opts.host,
    rejectUnauthorized: false,
    cert: opts.cert && readFileOr(opts.cert, "client certificate"),
    key: opts.key && readFileOr(opts.key, "client key"),
  }, () => {
    console.log(`connected: ${opts.host}:${opts.port} `
      + `(${socket.getProtocol()}, ${socket.getCipher().name})`
      + `${opts.cert ? ", client certificate presented" : ""}\n`);
    const chain = chainOf(socket.getPeerCertificate(true));
    socket.end();
    if (!chain.length) fail("server presented no certificate");
    printChain(chain);
    const saved = saveChain(chain, opts);
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
