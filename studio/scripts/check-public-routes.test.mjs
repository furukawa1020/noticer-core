import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { checkPublicRoutes, publicRoutes } from "./check-public-routes.mjs";

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "noticer-pages-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const { file, markers } of publicRoutes) {
    const destination = join(root, file);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, markers.join("<br>"));
  }
  return root;
}

test("complete route and marker inventory passes", async (t) => {
  await checkPublicRoutes(await fixture(t));
});

test("a deleted route blocks publication", async (t) => {
  const root = await fixture(t);
  await rm(join(root, "aetp-evidence/index.html"));
  await assert.rejects(checkPublicRoutes(root), /Missing public Studio page: aetp-evidence/);
});

test("an evidence label is required in the built page", async (t) => {
  const root = await fixture(t);
  await writeFile(join(root, "aetp-evidence/index.html"), "<h1>Demo</h1>");
  await assert.rejects(checkPublicRoutes(root), /SYNTHETIC DEMO ONLY/);
});
