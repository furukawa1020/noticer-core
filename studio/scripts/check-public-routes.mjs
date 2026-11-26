import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const publicRoutes = Object.freeze([
  {
    file: "mixed-slot-lab/index.html",
    markers: ["SYNTHETIC DEMO ONLY", "The tape is fixed before the draw"],
  },
  {
    file: "mixed-slot-proof/index.html",
    markers: [
      "SYNTHETIC DEMO ONLY", "Independent upper bound", "Achievable lower bound",
      "mixed-slot-proof/asymmetric.json",
    ],
  },
  {
    file: "mixed-slot-results/index.html",
    markers: ["SYNTHETIC DEMO ONLY", "Tied iterative64", "not empirical rates"],
  },
  { file: "index.html", markers: ["AETP Evidence Lab", "aetp-evidence/"] },
  { file: "aetp-evidence/index.html", markers: ["SYNTHETIC DEMO ONLY", "not an empirical result"] },
  { file: "aetp-observatory/index.html", markers: ["SYNTHETIC DEMO ONLY", "Claim withheld"] },
  {
    file: "recovery-verifier/index.html",
    markers: ["SYNTHETIC DEMO ONLY", "logical time", "Real protocol recovery is unverified"],
  },
  {
    file: "shared-slot-verifier/index.html",
    markers: ["SYNTHETIC DEMO ONLY", "same public prefix", "worst-case success is 1/2"],
  },
  {
    file: "shared-slot-capacity/index.html",
    markers: ["SYNTHETIC DEMO ONLY", "Exact neighborhood", "Insufficient reachable capacity"],
  },
  {
    file: "shared-slot-strategy/index.html",
    markers: ["SYNTHETIC DEMO ONLY", "Checked causal policy", "not a measurement on a live protocol"],
  },
  {
    file: "shared-slot-results/index.html",
    markers: ["SYNTHETIC DEMO ONLY", "Least-worst-slack baseline", "not empirical success rates"],
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
