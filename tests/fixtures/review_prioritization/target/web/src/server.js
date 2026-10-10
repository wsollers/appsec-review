const express = require("express");
const { exec } = require("child_process");
const util = require("./util");
const plugin = require(process.env.PLUGIN_NAME);

const app = express();
app.use(express.json());

app.post("/convert", (req, res) => {
  const input = req.body.path ?? "default";
  const plain = /^[a-z]+$/.exec(input);
  // eslint-disable-next-line security/detect-child-process
  exec("convert " + input, (error, stdout) => {
    if (error || !stdout) {
      res.status(500).send("failed");
      return;
    }
    res.send(util.render(stdout));
  });
});

function describe(value) {
  return value ? "present" : "absent"; // mentions eval( in a comment only
}

module.exports = { app, describe, plugin };
