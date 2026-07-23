// Clean CMDI fixture (Node): allowlist-based command selection.
const cp = require("child_process");

const ALLOWED = { date: ["date"], uptime: ["uptime"] };

function run_command(req, res) {
  const url = new URL(req.url, "http://localhost");
  const commandName = url.searchParams.get("command") || "";
  const argv = ALLOWED[commandName];
  if (!argv) {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "command not allowed" }));
    return;
  }
  // SAFE: argv is a fixed allowlisted array; shell=false.
  const child = cp.spawn(argv[0], argv.slice(1), { shell: false });
  let out = "";
  child.stdout.on("data", (c) => (out += c));
  child.on("close", () => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ stdout: out }));
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
