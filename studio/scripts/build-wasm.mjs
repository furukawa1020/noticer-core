import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const studioRoot = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(studioRoot, "..");
const cargo = process.env.CARGO ?? "cargo";

execFileSync(
  cargo,
  [
    "build",
    "--locked",
    "-p",
    "quotient-forge-studio-wasm",
    "--target",
    "wasm32-unknown-unknown",
    "--release",
  ],
  { cwd: repositoryRoot, stdio: "inherit" },
);

const source = join(
  repositoryRoot,
  "target",
  "wasm32-unknown-unknown",
  "release",
  "quotient_forge_studio_wasm.wasm",
);
const destinationDirectory = join(studioRoot, "public", "wasm");
mkdirSync(destinationDirectory, { recursive: true });
copyFileSync(source, join(destinationDirectory, "quotient_forge_studio_wasm.wasm"));
