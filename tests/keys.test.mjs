// Private key parsing and cert matching against real OpenSSL-generated files.
import { pemFixture, fixture, check, finish, reset } from "./harness.mjs";
import fs from "node:fs";

const der = (f) => {
  const t = fs.readFileSync(fixture(f), "utf8");
  const b64 = t.replace(/-----[^-]+-----/g, "").replace(/[^A-Za-z0-9+/=]/g, "");
  return new Uint8Array(Buffer.from(b64, "base64"));
};

for (const [crt, key, label] of [
  ["rsa.crt", "rsa.key",       "RSA PKCS#8"],
  ["rsa.crt", "rsa-pkcs1.key", "RSA PKCS#1"],
  ["ec.crt",  "ec-pkcs8.key",  "EC PKCS#8"],
  ["ec.crt",  "ec-sec1.key",   "EC SEC1"],
]) {
  const c = parseCert(der(crt), crt);
  const k = await parsePrivateKeyBytes(der(key));
  check(c.pubId === k.pubId, `${label}: key matches its cert (${k.info})`);
}

// negative: RSA key must not match EC cert
const ec = parseCert(der("ec.crt"), "ec.crt");
const rk = await parsePrivateKeyBytes(der("rsa.key"));
check(ec.pubId !== rk.pubId, "negative: RSA key vs EC cert");

// encrypted PEM detection
const enc = keyPemBlocks("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----");
check(enc.length === 1 && enc[0].encrypted, "encrypted PEM detected and flagged");

// filename merging: same key in two formats stays one entry, both names kept
reset();
addCertBytes(der("rsa.crt"), "server.crt");
addCertBytes(der("rsa.crt"), "bundle.pem");
await addKey(der("rsa.key"), "server.key");
await addKey(der("rsa-pkcs1.key"), "backup.key");
await addKey(der("rsa.key"), "server.key");
check(certs.length === 1 && keys.length === 1, "duplicates deduped");
check(certs[0].sourceNames.join()==="server.crt,bundle.pem", "cert keeps both filenames");
check(keys[0].names.join()==="server.key,backup.key", "key keeps both filenames, no repeat");
check(cardHTML(certs[0],0).includes("private key: server.key, backup.key"), "badge lists both key files");

finish();
