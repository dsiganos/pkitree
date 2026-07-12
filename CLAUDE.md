# pkitree

Client-side X.509 certificate hierarchy analyzer. Single self-contained
HTML file (index.html), zero dependencies, deployed via GitHub Pages.

## Architecture
- Hand-rolled DER/ASN.1 parser (no external libs — keep it that way)
- Chain building: AKI ⇒ SKI key-identifier match first, issuer/subject
  DN match as fallback
- Signature verification via WebCrypto: RSA PKCS#1 v1.5 + PSS
  (SHA-256/384/512), ECDSA P-256/P-384/P-521, Ed25519; SHA-1 and
  unknown algs fall back to "name match only" labelling
- "Load demo chains" generates two multi-branch ECDSA PKIs in-browser
  (root, two intermediates, device/web/www leaves incl. an expired and
  a soon-expiring one, plus device private keys) with a minimal DER
  writer; Alpha's root is also cross-signed by Beta's root to demo
  cross-sign handling
- Private keys (PKCS#8 / PKCS#1 / SEC1, PEM or DER) are parsed locally
  and matched to certs by public key; encrypted keys are unsupported
- "Match public CAs" completes chains from roots.pem (curl.se Mozilla
  bundle) + intermediates.pem (Mozilla Remote Settings preload list),
  fetched same-origin (CCADB itself has no CORS); only certs that
  complete a loaded chain are added. Refresh via `make refresh-cas`

## Constraints
- App stays a single HTML file with no build step (Pages serves it
  raw); roots.pem / intermediates.pem are optional same-origin data
  files — the app must work without them
- Everything client-side — user certs/keys must never leave the browser
- Test parser changes against real OpenSSL-generated certs

## Backlog
- AIA fetching of missing intermediates via Cloudflare Worker CORS
  proxy — for private PKIs not covered by the CCADB data files;
  must be opt-in (reveals issuer URLs to the proxy)
- Export tree as SVG/PNG
