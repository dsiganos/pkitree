// Demo generator: structure, signatures, expiry states, cross-signing, rendering.
import { dom, check, finish, reset } from "./harness.mjs";

const demo = await makeDemoChains();
for (const [b, n] of demo.certs) addCertBytes(b, n);
for (const [b, n] of demo.keys) await addKey(b, n);

check(certs.length === 15, `15 certs (got ${certs.length})`);
check(keys.length === 2, "2 device keys");

const f = await buildForest();
const byCN = (cn) => certs.find(c => c.subject.map.CN === cn);

// tree shape per org
for (const org of ["Alpha Corp", "Beta Corp"]) {
  const kids = f.childrenOf(byCN(`${org} Root CA`)).map(c => c.subject.map.CN).sort();
  check(kids.includes(`${org} Issuing CA`) && kids.includes(`${org} TLS CA`),
    `${org}: root has both intermediates`);
  check(f.childrenOf(byCN(`${org} Issuing CA`)).length === 3
     && f.childrenOf(byCN(`${org} TLS CA`)).length === 1,
    `${org}: 3 leaves under Issuing CA, 1 under TLS CA`);
}
check([...f.links.values()].every(l => l.verify === "ok"), `all ${f.links.size} links verified`);

// expiry states
const now = new Date(), soon = new Date(Date.now() + 30 * 864e5);
check(byCN("device-002.alpha.demo").notAfter < now, "device-002 expired");
const web = byCN("web.beta.demo");
check(web.notAfter > now && web.notAfter < soon, "web cert in the expiring-soon window");
// Alpha's TLS CA is expired; its www leaf link must carry the expired-issuer warning
const tlsCA = byCN("Alpha Corp TLS CA");
check(tlsCA.notAfter < now, "Alpha TLS CA expired");
const wwwLink = f.links.get(byCN("www.alpha.demo").id);
check(wwwLink?.warns?.some(w => /issuer expired/.test(w)), "www.alpha leaf flags expired issuer");

// keys attach to device-001 leaves only
check(certs.every(c => keys.some(k => k.pubId === c.pubId) === /^device-001\./.test(c.subject.map.CN)),
  "keys match device-001 leaves only");

// cross-signing: Beta root vouches for Alpha's root key
const variants = certs.filter(c => c.subject.map.CN === "Alpha Corp Root CA");
check(variants.length === 2 && variants[0].pubId === variants[1].pubId,
  "two Alpha root variants share one key");
const crossV = variants.find(c => !c.selfIssued), selfV = variants.find(c => c.selfIssued);
check(f.links.get(crossV.id)?.parent.subject.map.CN === "Beta Corp Root CA"
   && f.links.get(crossV.id)?.verify === "ok",
  "cross variant verified under Beta root (P-384 over P-256)");
check(f.links.get(byCN("Alpha Corp Issuing CA").id)?.parent === selfV,
  "intermediates prefer the self-signed variant");
check(f.roots.filter(c => c.selfIssued).length === 2, "exactly 2 trust anchors");
check(cardHTML(crossV, 0).includes(">cross-signed<") && cardHTML(selfV, 0).includes(">cross-signed<"),
  "both variants badged cross-signed");

// parent preference is load-order independent
const bytes = demo.certs.map(([b]) => b);
for (const order of [bytes, [...bytes].reverse()]) {
  reset();
  for (const b of order) addCertBytes(b, "x");
  const f2 = await buildForest();
  const issuing = certs.find(c => c.subject.map.CN === "Alpha Corp Issuing CA");
  check(f2.links.get(issuing.id)?.parent.selfIssued === true,
    "Issuing CA parent self-signed (order " + (order === bytes ? "fwd" : "rev") + ")");
}

// rendering: tree separators + dashed cross-sign hint
reset();
for (const [b, n] of demo.certs) addCertBytes(b, n);
await render();
const out = dom.forest.innerHTML;
check((out.match(/<div class="tree">/g) || []).length === 2, "2 tree wrappers");
check((out.match(/cross-hint/g) || []).length === 1
   && /same CA key as the cross-signed variant issued by O=Beta Corp/.test(out),
  "dashed hint above Alpha anchor names Beta's DN");

finish();
