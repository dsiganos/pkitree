// fetch-chain tool: mTLS against a local openssl s_server (fixture PKI),
// chain completion from --castore, and cross-signed-top resolution.
// Skips (exit 0) if openssl is unavailable.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawn, spawnSync, execFileSync } from "node:child_process";

const HERE = path.dirname(new URL(import.meta.url).pathname);
const FIX = (f) => path.join(HERE, "fixtures", f);
const TOOL = path.join(HERE, "..", "tools", "fetch-chain.mjs");
const PORT = 18443;

if (spawnSync("openssl", ["version"]).status !== 0) {
  console.log("SKIP  openssl not available");
  process.exit(0);
}

let failures = 0;
const check = (ok, msg) => { console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`); if (!ok) failures++; };
const run = (args) => execFileSync("node", [TOOL, ...args], { encoding: "utf8" });

// --- mTLS + castore completion against a local server ---------------------
const srv = spawn("openssl", ["s_server", "-accept", String(PORT), "-quiet",
  "-cert", FIX("mtls-server.crt"), "-key", FIX("mtls-server.key"),
  "-cert_chain", FIX("mtls-inter.crt"),
  "-Verify", "2", "-CAfile", FIX("mtls-ca-bundle.pem")], { stdio: "ignore" });
await new Promise(r => setTimeout(r, 800));

try {
  const outdir = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-chain-test-"));
  const out = run([`localhost:${PORT}`,
    "--cert", FIX("mtls-client.crt"), "--key", FIX("mtls-client.key"),
    "--castore", FIX("mtls-ca-bundle.pem"), "--outdir", outdir]);
  check(/client certificate presented/.test(out), "mTLS handshake with client cert");
  check(/leaf\s+CN=localhost/.test(out), "leaf listed");
  check(/root\s+CN=Test Root CA\s+CN=Test Root CA.*CA store/.test(out), "root completed from --castore");
  const saved = fs.readdirSync(outdir);
  check(saved.some(f => /intermediate/.test(f)) && saved.some(f => /root/.test(f)),
    "intermediate and root saved as PEM");
  fs.rmSync(outdir, { recursive: true, force: true });
} finally {
  srv.kill();
}

// --- cross-signed top resolves to its self-signed sibling -----------------
// (import the tool as a library by swapping main() for exports)
const libPath = path.join(os.tmpdir(), `fc-lib-${process.pid}.mjs`);
fs.writeFileSync(libPath, fs.readFileSync(TOOL, "utf8")
  .replace(/^main\(\);$/m, "export { completeChain };"));
const { completeChain } = await import(libPath);
fs.unlinkSync(libPath);

const { X509Certificate } = await import("node:crypto");
const rec = (f) => {
  const c = new X509Certificate(fs.readFileSync(FIX(f)));
  return { cn: "x", subject: c.subject.split("\n").join(", "), issuer: c.issuer.split("\n").join(", "),
    validTo: c.validTo, raw: c.raw, selfSigned: c.checkIssued(c), fromStore: false };
};
const records = [rec("wr2.pem"), rec("gts-r1-cross.pem")];
completeChain(records, [FIX("gts-r1-self.pem")]); // store has only the self-signed sibling
const last = records[records.length - 1];
check(last.selfSigned && last.fromStore && /CN=GTS Root R1/.test(last.subject),
  "cross-signed top resolved to self-signed sibling from store");

process.exit(failures ? 1 : 0);
