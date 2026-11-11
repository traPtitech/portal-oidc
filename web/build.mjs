import { build } from "esbuild";
await build({
  entryPoints: ["src/login.js"],
  bundle: true,
  minify: true,
  outdir: "../internal/router/v1/loginassets",
  platform: "browser",
  target: "es2022",
  legalComments: "eof",
});
