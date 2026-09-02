// File + network routes. Contains path traversal + SSRF sinks.
const express = require("express");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const router = express.Router();

const UPLOAD_DIR = "/var/app/uploads";

router.get("/download", (req, res) => {
  // VULNERABLE: path traversal. name can be ../../etc/passwd.
  const name = req.query.name;
  res.sendFile(UPLOAD_DIR + "/" + name);
});

router.get("/read", (req, res) => {
  // VULNERABLE: path traversal via fs.readFile on user-controlled path.
  const file = req.query.file;
  fs.readFile(path.join(UPLOAD_DIR, file), "utf8", (err, data) => res.send(data));
});

router.get("/fetch", (req, res) => {
  // VULNERABLE: SSRF. Server fetches an attacker-supplied URL.
  const url = req.query.url;
  axios.get(url).then((r) => res.send(r.data));
});

router.get("/download_safe", (req, res) => {
  // SAFE control: basename strips traversal.
  const name = path.basename(req.query.name || "");
  res.sendFile(path.join(UPLOAD_DIR, name));
});

module.exports = router;
