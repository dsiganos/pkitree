# pkitree

**X.509 certificate hierarchy analyzer that runs entirely in your
browser.** Drop certificates (and private keys) on the page and see
how they connect — chains rebuilt, signatures actually verified,
nothing uploaded anywhere.

**Live: https://dsiganos.github.io/pkitree/**

## What it does

- **Chain building** from AKI ⇒ SKI key identifiers, with issuer/subject
  DN matching as fallback — resilient to CA name collisions and key
  rollover
- **Real signature verification** via WebCrypto (RSA SHA-256/384/512,
  ECDSA P-256/P-384); a ✓ means the parent's key verified the child,
  not just that the names line up
- **Private key matching**: drop PKCS#8 / PKCS#1 / SEC1 keys (PEM or
  DER) and they're matched to their certificates by public key
- **Public CA completion**: one click completes chains against the
  Mozilla root store and the CCADB intermediate preload list (served
  same-origin — no third-party requests)
- **Cross-signing aware**: cross-signed CA variants are detected by
  shared public key, badged, and the tree stays stable regardless of
  load order
- **Full detail on demand**: every extension decoded (SAN, key usage,
  EKU, AIA, CRL DPs…), SHA-256 fingerprint, PEM export; compact view
  for when you only care about the relationships
- **Built-in demo**: generates two multi-branch PKIs in-browser —
  including an expired cert, an expiring cert, and a cross-signed
  root — so you can try everything without any files

## Privacy

Everything is client-side: parsing, verification, and key matching
happen in the page via WebCrypto. Certificates and private keys never
leave the browser; there are no cookies, no storage, no analytics.
The only network requests are for the app's own public CA data files.

## fetch-chain

`tools/fetch-chain.mjs` is a companion CLI (Node, zero dependencies)
that connects to a TLS/mTLS server, prints its chain, and saves the
CA/intermediate certificates as PEM — completing missing roots from
your system CA store, including cross-signed cases. See
[tools/README.md](tools/README.md).

## Development

```sh
make serve        # local server on :8080
make test         # test suite (Node ≥ 19; openssl for the tool test)
make refresh-cas  # update roots.pem / intermediates.pem from Mozilla data
make deploy       # push + wait for GitHub Pages to build this commit
```

The app is a single self-contained `index.html` with no dependencies
and no build step. See [ARCHITECTURE.md](ARCHITECTURE.md) for how it
works, and [docs/cross-signing.md](docs/cross-signing.md) for a deep
dive on cross-signed roots.
