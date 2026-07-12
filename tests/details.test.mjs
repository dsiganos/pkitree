// Full-details view: extension decoding and PEM round-trip, against an
// OpenSSL-generated cert with a rich extension set.
import { pemFixture, check, finish } from "./harness.mjs";

const [bytes] = pemFixture("rich-ext.crt");
const c = parseCert(bytes, "rich-ext.crt");
c.fp256 = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", c.raw)), ":");
const d = fullDetailsHTML(c);

check(/DNS:demo\.example, DNS:www\.demo\.example, IP:192\.0\.2\.1/.test(d), "SAN: DNS + IP decoded");
check(/digitalSignature, keyEncipherment/.test(d), "key usage bits decoded");
check(/key usage \(critical\)/.test(d), "critical flag shown");
check(/serverAuth, clientAuth/.test(d), "EKU names decoded");
check(/caIssuers http:\/\/ca\.demo\.example\/ca\.crt/.test(d) && /OCSP http:\/\/ocsp\.demo\.example/.test(d), "AIA URLs decoded");
check(/http:\/\/crl\.demo\.example\/demo\.crl/.test(d), "CRL distribution point decoded");
check(d.includes(c.fp256), "SHA-256 fingerprint shown");
check(/v3/.test(d) && /ecdsa-with-SHA256/.test(d), "version and signature algorithm shown");

// PEM in the details round-trips to an identical cert
const pem = d.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)[0];
check(parseCert(pemBlocks(pem)[0], "rt").id === c.id, "PEM round-trips to identical cert");

finish();
