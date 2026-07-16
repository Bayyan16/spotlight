// Clean Node/Express API — the precision negative.
// Same shape as vuln-node-api but uses a parameterized prepared statement.

const express = require("express");
const sqlite3 = require("better-sqlite3");

const app = express();
const db = sqlite3(":memory:");
db.exec("CREATE TABLE accounts (id INTEGER, name TEXT, balance REAL)");
db.exec("INSERT INTO accounts VALUES (1, 'alice', 1000)");

app.get("/accounts/:username", (req, res) => {
  const { username } = req.params;
  // SAFE: parameterized. `username` is a bound param, not interpolated.
  const rows = db
    .prepare("SELECT id, name, balance FROM accounts WHERE name = ?")
    .all(username);
  res.json(rows);
});

app.get("/health", (req, res) => res.json({ ok: true }));

module.exports = app;
