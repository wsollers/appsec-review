const fs = require("fs");
fs.mkdirSync("dist", { recursive: true });
fs.copyFileSync("lib/index.js", "dist/index.js");
