import express from "express";
import { Pool } from "pg";
import * as cp from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as http from "http";
import serialize from "node-serialize";

const ROOT = "/srv/files";

function buildQuery(id) {
  return "SELECT * FROM users WHERE id = " + id;
}

function handleSql(req, res) {
  const pool = new Pool();
  pool.query(buildQuery(req.query.id));
}

function handleExec(req, res) {
  const host = req.query.host;
  if (host === "localhost") {
    cp.exec(host);
  }
  cp.exec("nslookup " + host);
}

function handleFile(req, res) {
  const name = path.basename(req.query.file);
  fs.readFileSync(path.join(ROOT, name));
}

function handleFetch(req, res) {
  const target = req.query.url;
  http.get(target);
}

function handleRestore(req, res) {
  const blob = req.body;
  serialize.unserialize(blob);
}

function handleEcho(req, res) {
  const who = req.query.name;
  res.send("Hello " + who);
}

export function main() {
  const app = express();
  app.get("/sql", handleSql);
  app.get("/exec", handleExec);
  app.get("/file", handleFile);
  app.get("/fetch", handleFetch);
  app.post("/restore", handleRestore);
  app.get("/echo", handleEcho);
  app.listen(8080);
}
