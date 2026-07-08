# tools

## fetch-chain.mjs

Connects to a TLS or mTLS server, prints the certificate chain it
presents, and saves the CA / intermediate certificates as PEM files
(ready to drop into pkitree). If the server omits the root — they
usually do — the chain is completed from the system CA store
(OS bundle + Node's Mozilla roots, incl. NODE_EXTRA_CA_CERTS), or
from `--castore <bundle>` for private PKIs; store-sourced links are
accepted only if the signature verifies. Node ≥ 16, no dependencies.

Certificate verification is intentionally disabled — the point is to
retrieve chains from private/unknown PKIs. A successful connection
implies nothing about trust.

```
usage: fetch-chain.mjs <host>[:port] [options]

  --port <n>        port if not given as host:port     (default 443)
  --sni <name>      SNI servername                     (default: host)
  --cert <file>     client certificate for mTLS (PEM)
  --key <file>      client private key for mTLS (PEM)
  --outdir <dir>    where to save PEM files            (default: chain/)
  --castore <file>  PEM bundle used to complete the chain (repeatable;
                    default: the system CA store — note that system
                    stores hold roots only; for missing intermediates
                    point this at pkitree's intermediates.pem)
  --include-leaf    also save the leaf certificate
```

### Examples

Public server:

```
$ node tools/fetch-chain.mjs github.com
connected: github.com:443 (TLSv1.3, TLS_AES_128_GCM_SHA256)

#  role          subject                                         issuer                                          not after
0  leaf          github.com                                      Sectigo Public Server Authentication CA DV E36  Sep 30 23:59:59 2026 GMT
1  intermediate  Sectigo Public Server Authentication CA DV E36  Sectigo Public Server Authentication Root E46   Mar 21 23:59:59 2036 GMT
2  intermediate  Sectigo Public Server Authentication Root E46   USERTrust ECC Certification Authority           Jan 18 23:59:59 2038 GMT
3  root          USERTrust ECC Certification Authority           USERTrust ECC Certification Authority           Jan 18 23:59:59 2038 GMT

saved:
  chain/01-intermediate-Sectigo_Public_Server_Authentication_CA_DV_E36.pem
  chain/02-intermediate-Sectigo_Public_Server_Authentication_Root_E46.pem
  chain/03-root-USERTrust_ECC_Certification_Authority.pem
```

mTLS server with a private PKI: client certificate presented, the
server sends only leaf + intermediate, and the root is found in the
bundle given with --castore:

```
$ node tools/fetch-chain.mjs internal.corp:8443 --cert client.crt --key client.key \
    --castore corp-cas.pem --outdir corp-chain
connected: internal.corp:8443 (TLSv1.3, TLS_AES_256_GCM_SHA384), client certificate presented

#  role          subject          issuer           not after                 source
0  leaf          internal.corp    Test Issuing CA  Aug  7 22:32:29 2026 GMT  server
1  intermediate  Test Issuing CA  Test Root CA     Aug  7 22:32:29 2026 GMT  server
2  root          Test Root CA     Test Root CA     Aug  7 22:32:29 2026 GMT  CA store

saved:
  corp-chain/01-intermediate-Test_Issuing_CA.pem
  corp-chain/02-root-Test_Root_CA.pem
```

Forgetting the client cert produces a hint:

```
$ node tools/fetch-chain.mjs internal.corp:8443
error: ... alert certificate required ... (does the server require a client certificate? try --cert/--key)
```

The `source` column shows where each cert came from: `server` =
presented in (or linked during) the TLS handshake, `CA store` = added
by chain completion, cryptographically verified against its child.
