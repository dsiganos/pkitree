// Chain-quality warnings: conditions a real validator rejects even when the
// signature verifies — pathlen violations, CA:FALSE issuers, missing
// keyCertSign, expired issuers.
import { pemFixture, check, finish, reset } from "./harness.mjs";

const add = (f) => { for (const b of pemFixture(f)) addCertBytes(b, f); };
const linkOf = (f, cn) => f.links.get(certs.find(c => c.subject.map.CN === cn).id);

// pathlen:0 root with a subordinate CA
add("plroot.crt"); add("plsub.crt");
let f = await buildForest();
check(linkOf(f, "Bad Sub CA")?.verify === "ok", "pathlen case: signature itself is valid");
check(linkOf(f, "Bad Sub CA")?.warns.some(w => /pathlen exceeded \(Pathlen0 Root pathlen:0\)/.test(w)),
  "pathlen exceeded warning");
check(certs.find(c => c.subject.map.CN === "Pathlen0 Root").pathLen === 0, "pathLen parsed");

// CA:FALSE cert that issued a child
reset(); add("noca.crt"); add("nocachild.crt");
f = await buildForest();
check(linkOf(f, "child-of-nonca")?.warns.some(w => /issuer is not a CA/.test(w)),
  "CA:FALSE issuer warning");

// CA whose keyUsage lacks keyCertSign
reset(); add("kuca.crt"); add("kuchild.crt");
f = await buildForest();
check(linkOf(f, "child-of-kuca")?.warns.some(w => /lacks keyCertSign/.test(w)),
  "missing keyCertSign warning");
check(certs.find(c => c.subject.map.CN === "No CertSign CA").keyUsage.join() === "digitalSignature",
  "keyUsage bits stored on cert");

// expired issuer (synthetic — fixtures can't be issued in the past)
const mk = (id, {notAfter = new Date(Date.now() + 864e5), isCA = true, selfIssued = false} = {}) => ({
  id, subject: {str: "CN=" + id, map: {CN: id}}, issuer: {str: "x"},
  notBefore: new Date(0), notAfter, isCA, selfIssued,
});
const P = mk("expired-root", {notAfter: new Date(Date.now() - 864e5), selfIssued: true});
const K = mk("valid-child", {isCA: false});
const links = new Map([[K.id, {parent: P, how: "t", verify: "ok"}]]);
const forest = {links, roots: [P], childrenOf: (c) => c === P ? [K] : []};
addChainWarnings(forest);
check(links.get(K.id).warns.some(w => /issuer expired/.test(w)), "expired issuer warning");

// negative: a clean chain produces no warnings
reset(); add("mtls-root.crt"); add("mtls-inter.crt"); add("mtls-server.crt");
f = await buildForest();
check([...f.links.values()].every(l => !l.warns?.length), "clean chain: no warnings");

// warnings appear in the link note and count as issues
reset(); add("noca.crt"); add("nocachild.crt");
f = await buildForest();
const note = linkNoteHTML(f.links.get(certs.find(c => c.subject.map.CN === "child-of-nonca").id));
check(note.includes("⚠") && /issuer is not a CA/.test(note), "warning rendered in link note");

finish();
