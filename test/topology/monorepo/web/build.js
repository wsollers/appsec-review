"use strict";

const fs = require("node:fs");
const path = require("node:path");

const root = __dirname;
const packages = path.join(root, "packages");
const out = path.join(root, "dist");

fs.mkdirSync(out, { recursive: true });
const parts = [];
for (const name of fs.readdirSync(packages).sort()) {
  const entry = path.join(packages, name, "index.js");
  if (fs.existsSync(entry)) {
    parts.push(`// ${name}\n${fs.readFileSync(entry, "utf8")}`);
  }
}
fs.writeFileSync(path.join(out, "bundle.js"), parts.join("\n"));
console.log(`bundled ${parts.length} packages`);
