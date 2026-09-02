// Admin/ops routes. Contains command injection + reflected XSS sinks.
const express = require("express");
const { exec, execFile } = require("child_process");
const router = express.Router();

router.get("/ping", (req, res) => {
  // VULNERABLE: OS command injection. host flows into a shell command.
  const host = req.query.host;
  exec("ping -c 1 " + host, (err, stdout) => res.send(stdout));
});

router.get("/greet", (req, res) => {
  // VULNERABLE: reflected XSS. name echoed into HTML unescaped.
  const name = req.query.name;
  res.send(`<h1>Hello ${name}</h1>`);
});

router.get("/ping_safe", (req, res) => {
  // SAFE control: execFile with an args array, no shell, validated input.
  const host = req.query.host || "";
  if (!/^[a-z0-9.]+$/i.test(host)) return res.status(400).send("bad host");
  execFile("ping", ["-c", "1", host], (err, stdout) => res.send(stdout));
});

module.exports = router;
