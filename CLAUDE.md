# pkitree

Client-side X.509 certificate hierarchy analyzer. Single self-contained
HTML file (index.html), zero dependencies, deployed via GitHub Pages.

## Architecture
- Hand-rolled DER/ASN.1 parser (no external libs — keep it that way)
- Chain building: AKI ⇒ SKI key-identifier match first, issuer/subject
  DN match as fallback
- Signature verification via WebCrypto: RSA SHA-256/384/512,
  ECDSA P-256/P-384; others fall back to "name match only" labelling
- "Load demo chain" generates a 3-tier ECDSA PKI in-browser with a
  minimal DER writer

## Constraints
- Must stay a single file with no build step (Pages serves it raw)
- Everything client-side — certs must never leave the browser
- Test parser changes against real OpenSSL-generated certs

## Backlog
- AIA fetching of missing intermediates (needs a Cloudflare Worker
  CORS proxy)
- Export tree as SVG/PNG
