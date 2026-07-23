// CMDI reproduction fixture (Node). Never run outside Spotlight's sandbox.
// Uses Node stdlib only so tests don't need npm install.
const cp = require("child_process");

function run_command(req, res) {
  const url = new URL(req.url, "http://localhost");
  const command = url.searchParams.get("command") || "";
  // VULN: user-controlled `command` passed through the shell.
  cp.exec(command, (err, stdout) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ stdout: stdout || "" }));
  });
}

function handler(req, res) {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/run" && req.method === "POST") {
    return run_command(req, res);
  }
  res.writeHead(404).end();
}

module.exports = handler;
module.exports.run_command = run_command;
