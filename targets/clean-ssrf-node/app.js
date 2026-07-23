// Clean SSRF fixture (Node): host allowlist prevents fetching arbitrary URLs.
const http = require("http");

const ALLOWED_HOSTS = new Set(["api.example.com", "status.example.com"]);

function fetch_url(req, res) {
  const url = new URL(req.url, "http://localhost");
  const target = url.searchParams.get("url") || "";
  let parsed;
  try { parsed = new URL(target); } catch {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "invalid url" }));
    return;
  }
  if (!ALLOWED_HOSTS.has(parsed.hostname) || parsed.protocol !== "https:") {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "host not allowed" }));
    return;
  }
  // SAFE: host + protocol allowlisted before request.
  http.get(target, (r) => {
    let body = "";
    r.on("data", (c) => (body += c));
    r.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ body }));
    });
  }).on("error", (e) => {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: String(e) }));
  });
}

function handler(req, res) {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/fetch" && req.method === "POST") {
    return fetch_url(req, res);
  }
  res.writeHead(404).end();
}

module.exports = handler;
module.exports.fetch_url = fetch_url;
