// Public CA completion: a real leaf (github.com, checked-in fixture) is
// completed from the repo's roots.pem / intermediates.pem via a fetch stub.
// Skips (exit 0) if the data files are absent — the app must work without them.
import fs from "node:fs";
import { pemFixture, repoFile, check, finish } from "./harness.mjs";

if (!fs.existsSync(repoFile("roots.pem")) || !fs.existsSync(repoFile("intermediates.pem"))) {
  console.log("SKIP  roots.pem / intermediates.pem not present (run `make refresh-cas`)");
  process.exit(0);
}
globalThis.fetch = async (url) => ({ ok: true, text: async () => fs.readFileSync(repoFile(url), "utf8") });

for (const b of pemFixture("github-leaf.pem")) addCertBytes(b, "github-leaf.pem");
const added = await matchPublicCAs();
check(added.length >= 2, `completed chain with ${added.length} public CA certs: ${added.join(" | ")}`);

const f = await buildForest();
const leaf = certs.find(c => c.subject.map.CN === "github.com");
check(f.links.get(leaf.id)?.verify === "ok", "leaf signature verified against fetched intermediate");
check(f.roots.some(c => c.selfIssued), "chain reaches a self-signed root");
check(certs.length < caPool.length / 10, "only matching certs added, not the whole pool");

finish();
