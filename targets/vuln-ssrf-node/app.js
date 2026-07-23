// SSRF reproduction fixture (Node). Uses Node stdlib http only.
const http = require("http");

function fetch_url(req, res) {
  const url = new URL(req.url, "http://localhost");
  const target = url.searchParams.get("url") || "";
  // VULN: user-controlled `target` used as request URL without allowlist.
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
