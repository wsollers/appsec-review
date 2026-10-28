import * as cp from "child_process";
import readlineSync from "readline-sync";

function runCommand(cmd) {
  cp.execSync(cmd);
}

export function runFromArgs() {
  runCommand(process.argv[2]);
}

export function runFromEnv() {
  runCommand(process.env.TOOL_CMD);
}

export function askAndRun() {
  const answer = readlineSync.question("command? ");
  console.log(answer);
  runCommand(answer);
}

export function token() {
  return Math.random();
}
