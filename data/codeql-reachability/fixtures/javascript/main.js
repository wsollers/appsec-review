// Smoke fixture: "vuln-lib" stands in for an npm dependency with an advisory on parse.
const vuln = require("vuln-lib");

function handle(input) {
  return vuln.parse(input);
}

console.log(handle(process.argv[2]));
