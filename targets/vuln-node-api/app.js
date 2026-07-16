// Vulnerable Node/Express API — seeded target for Spotlight.
// Contains a planted SQL injection at GET /accounts/:username.

const express = require("express");
const sqlite3 = require("better-sqlite3");

const app = express();
app.use(express.json());
const db = sqlite3(":memory:");
db.exec("CREATE TABLE accounts (id INTEGER, name TEXT, balance REAL)");
db.exec("INSERT INTO accounts VALUES (1, 'alice', 1000)");
db.exec("INSERT INTO accounts VALUES (2, 'bob', 500)");

app.get("/accounts/:username", (req, res) => {
  const username = req.params.username;
  // VULN: user-controlled `username` interpolated into SQL string.
  const query = "SELECT id, name, balance FROM accounts WHERE name = '" + username + "'";
  const rows = db.prepare(query).all();
  res.json(rows);
});

app.get("/health", (req, res) => res.json({ ok: true }));

if (require.main === module) {
  app.listen(8080);
}

module.exports = app;
