# Root CA cross-signing — report

Triggered by a real case: fetching the chain of `viper-staging.iris.audio`
reported *root not found* even though the site chains to a perfectly
trusted Google root. The cause is cross-signing and the gradual removal
of an old GlobalSign root from trust stores. This report explains the
mechanism and the specific incident.

## How cross-signing works

A certificate is not "the CA". It is a *signed statement about a public
key*: "issuer I vouches that subject S controls key K". Nothing stops
two different issuers from making the same statement about the same
key. The result is two certificates with the **same subject and same
public key** but different issuers and signatures:

```
        ┌───────────────────────────┐     ┌───────────────────────────────┐
        │ subject: GTS Root R1      │     │ subject: GTS Root R1          │
        │ key:     K (same key!)    │     │ key:     K (same key!)        │
        │ issuer:  GTS Root R1      │     │ issuer:  GlobalSign Root CA   │
        │ (self-signed root)        │     │ (cross-signed variant)        │
        └───────────────────────────┘     └───────────────────────────────┘
```

Because certificates issued *by* GTS Root R1 are signed with key K,
**either** certificate above validates them. A chain can therefore
terminate at whichever variant the validator can anchor:

```
leaf ← WR3 ← GTS Root R1 (self-signed)                    ← modern store
leaf ← WR3 ← GTS Root R1 (cross) ← GlobalSign Root CA     ← legacy store
```

Path building is the key insight: the chain a server sends is a
*suggestion*, not the truth. Validators (browsers, OpenSSL 1.1+) build
their own path from the leaf to whatever anchor they hold, and are free
to shortcut a cross-signed chain at the self-signed sibling.

## Why CAs cross-sign

- **Bootstrapping a new root.** Getting a root into every OS, browser
  and IoT stack takes 5–10 years. A brand-new root cross-signed by an
  established one is instantly trusted everywhere the old root is.
  This is the GTS case, and also how Let's Encrypt started (ISRG Root
  X1 cross-signed by IdenTrust's DST Root CA X3).
- **CA acquisitions / rebranding** — new corporate root, old trust.
- **Algorithm/keysize migrations** — new-generation root vouched for
  by the previous generation during the overlap.

The cost: the cross-cert inherits the old root's lifetime and fate.
When the old root expires or is distrusted, chains that *depend* on
the cross path break — famously, DST Root CA X3's expiry in September
2021 broke old Android devices and, notoriously, OpenSSL 1.0.x clients
that couldn't shortcut to ISRG Root X1.

## The incident

Google created the GTS Root R1–R4 hierarchy in 2016 and had GTS Root
R1 cross-signed by **GlobalSign Root CA** (R1, a 1998-era root, expires
2028-01-28) so Google-issued certificates would work on devices that
predate the GTS roots. Google's servers still send the legacy-friendly
chain:

```
leaf ← WR3 ← GTS Root R1 (cross-signed by GlobalSign Root CA)
```

Meanwhile GlobalSign Root CA has been dropped from current trust
stores (verified empirically: absent from this machine's
`ca-certificates.crt` and from the current curl.se Mozilla snapshot;
the self-signed GTS Root R1, valid to 2036, is present instead). So:

- Old validators: anchor at GlobalSign Root CA → works.
- Modern validators: ignore the cross link, anchor at self-signed
  GTS Root R1 → works.
- Naive tooling that only walks "find the issuer of the top cert":
  finds nothing → *"root not found"*, incorrectly.

## What fetch-chain does now

`completeChain` first tries the literal path (find the top cert's
issuer in the CA store, verify the signature). If that fails, it
checks whether the store holds a **self-signed certificate with the
same subject and byte-identical public key (SPKI)** as the chain top —
the cross-signed top's sibling — and appends it as the trust anchor:

```
#  role          subject           issuer                 source
1  intermediate  CN=GTS Root R1    CN=GlobalSign Root CA  server
2  root          CN=GTS Root R1    CN=GTS Root R1         CA store
```

The same-key check matters: subject names are not unique, but a
matching SPKI proves both certificates describe the same CA key, so
every signature made by that CA verifies against either.

## See it yourself

```sh
# the two GTS Root R1 variants, same key, different issuers:
node tools/fetch-chain.mjs google.com --outdir /tmp/g
openssl x509 -in /tmp/g/02-intermediate-GTS_Root_R1.pem -noout -subject -issuer
openssl x509 -in /tmp/g/02-intermediate-GTS_Root_R1.pem -noout -pubkey | sha256sum
# compare against the self-signed variant from your system store:
awk 'BEGIN{RS="-----END CERTIFICATE-----\n"} /GTS Root R1/{print $0 RS}' \
    /etc/ssl/certs/ca-certificates.crt | head -30
```

In pkitree itself, load a Google chain and both variants of GTS Root
R1 if you have them: the AKI ⇒ SKI matching handles cross-signs
naturally, since both variants carry the same SKI.
