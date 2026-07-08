# pkitree architecture

Client-side X.509 chain analyzer. One HTML file, zero dependencies, no
build step. Deployed raw via GitHub Pages. Nothing the user loads ever
leaves the browser.

## Files

| File | Role |
|---|---|
| `index.html` | The entire application: markup, CSS, JS |
| `roots.pem` | Mozilla root store snapshot (~120 certs, via curl.se) |
| `intermediates.pem` | Mozilla/CCADB intermediate preload list (~1800 certs) |
| `Makefile` | Dev/deploy helpers; `refresh-cas` regenerates the two .pem files |
| `tools/fetch-chain.mjs` | CLI: fetch a (m)TLS server's chain, save CA/intermediates as PEM (see tools/README.md) |

The .pem data files are optional: the app runs without them; only the
"Match public CAs" button needs them, fetched same-origin (CCADB and
Mozilla's CDN send no CORS headers, so a same-origin mirror is the only
proxy-free option).

## Pipeline

```
files / paste / demo / CA store
        │
        ▼
  pemBlocks() ──── PEM → DER (also raw DER accepted if first byte 0x30)
        │
        ▼
  derParse() ───── hand-rolled TLV reader → nested {tag, offsets, children}
        │
        ▼
  parseCert() ──── tbs fields, DNs, validity, SPKI, SKI/AKI/basicConstraints,
        │          pubId (public-key fingerprint), dedupe by serial+subject
        ▼
  buildForest() ── link each cert to its issuer:
        │            1. AKI = SKI  (immune to name collisions / key rollover)
        │            2. issuer DN = subject DN  (fallback)
        │          then verifySig() on every link
        ▼
  render() ─────── tree of cards grouped: trust anchors / incomplete chains /
                   unmatched private keys; summary counters
```

Everything re-runs from scratch on each change — no incremental state
beyond the `certs[]` and `keys[]` arrays.

## Signature verification

WebCrypto (`crypto.subtle.verify`) on the raw `tbsCertificate` bytes:

- RSA PKCS#1 v1.5 with SHA-256/384/512
- ECDSA P-256/P-384 (DER signature converted to raw r‖s first)
- Everything else (SHA-1, RSA-PSS, Ed25519, P-521) → link labelled
  "matched by name only"; SHA-1 additionally badged as weak

A link therefore has two independent properties: *how it matched*
(AKI⇒SKI vs DN) and *whether the signature verified* (✓ / ✗ / n.a.).

## Private keys

Accepted: PKCS#8, PKCS#1 (RSA), SEC1 (EC) — PEM or DER. Encrypted keys
are detected and refused (no password handling).

Matching is by public key, not filename: RSA → modulus+exponent, EC →
uncompressed point. If an EC key lacks the embedded public point, it is
imported into WebCrypto and the point recovered from the JWK export.
Both certs and keys reduce to a `pubId` string; equality = match.
Matched certs get a badge; orphan keys get their own section.

## Public CA matching

"Match public CAs" fetches the two .pem files (lazily, once), parses
all ~1950 certs into a pool, then repeatedly scans loaded certs for
missing issuers and copies in pool certs that resolve them — leaf pulls
its intermediate, intermediate pulls its root. Only certs that complete
a chain are added; the pool itself is never displayed.

## Demo generator

A minimal DER *writer* (TLV, OID, Name, UTCTime) plus WebCrypto keygen
and signing builds two 3-tier hierarchies in-browser: Alpha Corp
(P-256/SHA-256) and Beta Corp (P-384/SHA-384), with correct SKI/AKI
linkage so verification genuinely passes. Each leaf's private key is
exported as PKCS#8 and fed through the normal key-matching path.

## Security / privacy model

- No network I/O with user data, ever. The only fetches are the two
  same-origin CA data files (public data, inbound only).
- Private keys are parsed solely to derive a public-key fingerprint;
  key material is not stored beyond the page session and not shown.
- No cookies, no storage, no analytics. Refresh = clean slate.

## Testing

No test harness in-repo. Parser changes are validated against real
OpenSSL-generated material by extracting the page's `<script>` and
running it in Node (`vm.runInThisContext` + a DOM stub) — Node ≥ 19
provides the same WebCrypto API. See CLAUDE.md constraint: always test
against real OpenSSL output, not just the in-browser demo certs.

## Deployment

GitHub Pages serves the repo root, branch `main`, no build. `make
deploy` pushes and polls the Pages API until the rebuild reports
`built`. `make refresh-cas` should be run periodically (and committed)
to keep the CA snapshots current.
