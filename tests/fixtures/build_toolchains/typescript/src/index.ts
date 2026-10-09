const parse = require("minimist");
const values = parse(["--name", "appsec fixture"]);
console.log(values.name);
