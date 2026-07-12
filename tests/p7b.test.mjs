// PKCS#7 (.p7b) ingestion: DER SignedData cert bag and PEM PKCS7 blocks.
import fs from "node:fs";
import { fixture, check, finish, reset } from "./harness.mjs";

// DER bundle → p7bCerts extracts both CA certs
const der = new Uint8Array(fs.readFileSync(fixture("bundle.p7b")));
const bag = p7bCerts(der);
check(bag.length === 2, `DER .p7b yields 2 certs (got ${bag.length})`);
for (const b of bag) addCertBytes(b, "bundle.p7b");
check(certs.length === 2, "both certs parse and load");
const cns = certs.map(c => c.subject.map.CN).sort();
check(cns.join() === "Test Issuing CA,Test Root CA", `expected CNs (got ${cns.join()})`);
const f = await buildForest();
check(f.links.get(certs.find(c => c.subject.map.CN === "Test Issuing CA").id)?.verify === "ok",
  "chain from .p7b builds and verifies");

// PEM PKCS7 block → pemBlocks handles it transparently
reset();
const pem = fs.readFileSync(fixture("bundle-p7.pem"), "utf8");
const blocks = pemBlocks(pem);
check(blocks.length === 2, `PEM PKCS7 yields 2 certs (got ${blocks.length})`);

// non-PKCS#7 DER (a plain cert) is not misparsed as a bundle
const plain = pemBlocks(fs.readFileSync(fixture("rsa.crt"), "utf8"))[0];
check(p7bCerts(plain).length === 0, "plain cert is not a PKCS#7 bundle");

finish();
