import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const publicRoutes = Object.freeze([
  { file: "index.html", markers: ["AETP Evidence Lab", "aetp-evidence/"] },
  { file: "aetp-evidence/index.html", markers: ["SYNTHETIC DEMO ONLY", "not an empirical result"] },
  { file: "aetp-observatory/index.html", markers: ["SYNTHETIC DEMO ONLY", "Claim withheld"] },
  {
    file: "recovery-verifier/index.html",
    markers: ["SYNTHETIC DEMO ONLY", "logical time", "Real protocol recovery is unverified"],
  },
  {
    file: "quotient-trial/index.html",
    markers: ["QuotientTrial | Comparative Evaluation Lab", "NOT SCIENTIFIC RESULTS"],
  },
]);

export async function checkPublicRoutes(dist) {
  for (const { file, markers } of publicRoutes) {
    let html;
    try {
      html = await readFile(resolve(dist, file), "utf8");
    } catch (cause) {
      throw new Error(`Missing public Studio page: ${file}`, { cause });
    }
    for (const marker of markers) {
      if (!html.includes(marker)) {
        throw new Error(`Missing public Studio marker in ${file}: ${marker}`);
      }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await checkPublicRoutes(resolve("dist"));
  process.stdout.write(`Checked ${publicRoutes.length} public Studio routes.\n`);
}
