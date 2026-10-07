import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://furukawa1020.github.io",
  base: "/noticer-core",
  output: "static",
  build: {
    assets: "_studio",
  },
});
