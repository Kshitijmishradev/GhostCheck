// Auth + user lookup routes. Contains SQL injection sinks.
const express = require("express");
const router = express.Router();
const db = require("../db");

router.get("/users/:id", (req, res) => {
  // VULNERABLE: SQL injection via string concatenation.
  const query = "SELECT id, name FROM users WHERE id = " + req.params.id;
  db.query(query, (err, rows) => res.json(rows));
});

router.post("/login", (req, res) => {
  // VULNERABLE: SQL injection via template literal on request body.
  const { username, password } = req.body;
  const q = `SELECT * FROM users WHERE name = '${username}' AND pass = '${password}'`;
  db.query(q, (err, rows) => res.json({ ok: rows.length > 0 }));
});

router.get("/users_safe/:id", (req, res) => {
  // SAFE control: parameterized query. Scanner must NOT flag this.
  db.query("SELECT id, name FROM users WHERE id = ?", [req.params.id], (err, rows) =>
    res.json(rows)
  );
});

module.exports = router;
