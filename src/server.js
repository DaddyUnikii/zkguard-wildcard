const fs = require("fs");
const http = require("http");
const path = require("path");
const { analyzeTransaction } = require("./analyzer");

const PORT = Number(process.env.PORT || 8788);
const UI_HTML = fs.readFileSync(path.join(__dirname, "ui.html"), "utf8");

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(UI_HTML);
    return;
  }

  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, service: "zkguard-wildcard" }));
    return;
  }

  if (req.method === "POST" && (req.url === "/analyze" || req.url === "/agent")) {
    try {
      const raw = await readBody(req);
      const tx = raw ? JSON.parse(raw) : {};
      const result = await analyzeTransaction(tx);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
    } catch (err) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`zkguard-wildcard listening on 0.0.0.0:${PORT} (/, /analyze, /health)`);
});
