// Fail if any installed npm package has a licence outside the allow list.
// Same policy as scripts/check_licences.py for Python packages.
import { readFileSync } from "node:fs";

const ALLOWED = /\b(MIT|Apache-2\.0|BSD-2-Clause|BSD-3-Clause|ISC|0BSD|BlueOak-1\.0\.0|CC0-1\.0|Unlicense|Python-2\.0|MPL-2\.0|CC-BY-4\.0)\b/;
const COPYLEFT = /\b(A?GPL|LGPL|SSPL|EUPL)/i;

const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url)));
const problems = [];
for (const [path, info] of Object.entries(lock.packages)) {
  if (!path) continue; // the project itself
  let licence = info.license ?? "";
  if (!licence) {
    try {
      const pkg = JSON.parse(readFileSync(new URL(`../${path}/package.json`, import.meta.url)));
      licence = typeof pkg.license === "string" ? pkg.license : (pkg.license?.type ?? "");
    } catch {
      // Optional packages for other platforms are not installed here.
      if (info.optional) continue;
    }
  }
  const anyOf = licence.includes(" OR ");
  if (!ALLOWED.test(licence) || (COPYLEFT.test(licence) && !anyOf)) {
    problems.push(`${path.replace(/^node_modules\//, "")}: ${licence || "no licence"}`);
  }
}
if (problems.length) {
  console.error("Licences needing owner review:\n  " + problems.join("\n  "));
  process.exit(1);
}
console.log(`All ${Object.keys(lock.packages).length - 1} npm licences are on the allow list.`);
