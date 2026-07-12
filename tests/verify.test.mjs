// Signature verification coverage: P-521, Ed25519, RSA-PSS (positive and
// negative), against real OpenSSL-signed certificates.
import { pemFixture, check, finish } from "./harness.mjs";

const load = (f) => parseCert(pemFixture(f)[0], f);

// self-signed positives: the cert's own key must verify its signature
for (const [f, label] of [
  ["p521.crt",    "ECDSA P-521"],
  ["ed25519.crt", "Ed25519"],
  ["rsa-pss.crt", "RSA-PSS SHA-256"],
]) {
  const c = load(f);
  check(await verifySig(c, c) === "ok", `${label}: self-signature verifies (${c.sigAlg.label})`);
}

// PSS params were actually parsed, not defaulted
const pss = load("rsa-pss.crt");
check(pss.pss?.hash === "SHA-256" && pss.pss?.saltLength === 32,
  `PSS params decoded: ${pss.pss?.hash}, salt ${pss.pss?.saltLength}`);

// negatives: wrong key of the same algorithm family must FAIL, not "unsupported"
check(await verifySig(load("ed25519.crt"), load("ed25519-b.crt")) === "fail",
  "Ed25519 vs wrong key fails");
check(await verifySig(load("rsa-pss.crt"), load("rsa.crt")) === "fail",
  "RSA-PSS vs wrong key fails");

// classic algorithms still work (regression)
check(await verifySig(load("ec.crt"), load("ec.crt")) === "ok", "P-256 still verifies");
check(await verifySig(load("rsa.crt"), load("rsa.crt")) === "ok", "RSA PKCS#1 v1.5 still verifies");

finish();
