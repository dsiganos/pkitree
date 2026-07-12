// Shared test harness: loads the page's <script> into this Node realm with a
// minimal DOM stub. The app's globals (certs, keys, addCertBytes, render, …)
// become visible to test modules. Node ≥ 19 (WebCrypto).
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";

const HERE = path.dirname(new URL(import.meta.url).pathname);
export const fixture = (f) => path.join(HERE, "fixtures", f);
export const repoFile = (f) => path.join(HERE, "..", f);

// stable per-id stub so tests can read back e.g. dom.forest.innerHTML
const els = {};
globalThis.document = { getElementById: (id) => els[id] ??= {
  addEventListener(){}, style:{}, textContent:"", value:"", innerHTML:"",
  classList:{ toggle(){}, contains(){ return false }, add(){}, remove(){} },
}};
export const dom = els;

const html = fs.readFileSync(repoFile("index.html"), "utf8");
vm.runInThisContext(html.split("<script>")[1].split("</script>")[0]);

// PEM blocks of a fixture file, as Uint8Arrays (uses the app's own pemBlocks)
export const pemFixture = (f) => pemBlocks(fs.readFileSync(fixture(f), "utf8"));

export function reset() { certs.length = 0; seen.clear(); keys.length = 0; }

let failures = 0;
export function check(ok, msg) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failures++;
}
export function finish() { process.exit(failures ? 1 : 0); }
