// server.mjs — Extremely Verbal Backend Gateway (no node-fetch needed)
// Uses Node 18+ global fetch. If not present, falls back to node-fetch dynamically.

import express from "express";
import os from "os";

const app = express();
app.use(express.json({ limit: "256kb" }));

// CORS
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// >>> Hard-coded home agent public endpoint (port 80 on your box)
const HOME_AGENT_BASE = "http://98.156.77.218";

function now() { return new Date().toISOString(); }
function log(level, msg, extra = {}) {
  console.log(JSON.stringify({ level, time: now(), host: os.hostname(), msg, ...extra }));
}

// pick fetch: prefer global (Node 18+), else lazy-import node-fetch
async function httpFetch(url, opts) {
  if (typeof globalThis.fetch === "function") {
    return await globalThis.fetch(url, opts);
  }
  const { default: nf } = await import("node-fetch"); // only if absolutely needed
  return await nf(url, opts);
}

app.get("/health", (req, res) => {
  log("info", "backend health");
  res.json({ ok: true, who: "backend", time: now() });
});

function classifyNetErr(err) {
  const m = (err && (err.code || err.type || err.name)) || "ERROR";
  const s = String(err || "");
  const causes = [];
  if (/ECONNREFUSED/.test(s)) causes.push("Home agent not listening / firewall blocked / port forward missing.");
  if (/ETIMEDOUT|timeout|network timeout/i.test(s)) causes.push("No response from home agent (ISP block / firewall / wrong IP).");
  if (/ENETUNREACH|EHOSTUNREACH/.test(s)) causes.push("Route to host unreachable (wrong IP or network down).");
  if (/invalid json response body/i.test(s)) causes.push("Home agent returned non-JSON (proxy or captive portal?).");
  if (causes.length === 0) causes.push("Unknown network failure; check home agent logs.");
  return { code: m, probableCauses: causes };
}

app.post("/api/auth/login-plain", async (req, res) => {
  const body = req.body || {};
  log("info", "frontend -> backend /api/auth/login-plain", { body: { ...body, password: body.password ? "***" : "" } });

  const missing = [];
  for (const k of ["email", "host", "port", "secure", "password"]) {
    if (body[k] === undefined || body[k] === null || body[k] === "") missing.push(k);
  }
  if (missing.length) {
    const diag = {
      ok: false,
      error: "BAD_REQUEST_BODY",
      message: `Missing fields: ${missing.join(", ")}`,
      expectation: "{ email, host, port, secure, password }",
      time: now(),
    };
    log("warn", "bad request body", diag);
    return res.status(400).json(diag);
  }

  const url = `${HOME_AGENT_BASE}/api/auth/login-plain`;
  log("info", "backend -> home-agent begin", {
    url, targetBody: { ...body, password: "***" }, timeoutMs: 6000
  });

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort("timeout"), 6000);

    const r = await httpFetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    }).finally(() => clearTimeout(t));

    const text = await r.text();
    let json;
    try { json = JSON.parse(text); } catch { /* keep text */ }

    log("info", "backend <- home-agent response", {
      status: r.status, bodyParsed: Boolean(json), rawPreview: text.slice(0, 1000)
    });

    res.status(r.status).type(json ? "application/json" : "text/plain").send(json ? JSON.stringify(json) : text);
  } catch (err) {
    const net = classifyNetErr(err);
    const diag = {
      ok: false,
      error: "HOME_AGENT_UNREACHABLE",
      message: String(err),
      homeAgentUrl: `${HOME_AGENT_BASE}/api/auth/login-plain`,
      probableCauses: [
        ...net.probableCauses,
        "Router lacks NAT loopback: testing public IP from LAN can fail — try from LTE.",
        "ISP CGNAT: inbound port forwarding impossible — need public IP or reverse tunnel.",
      ],
      quickChecks: [
        `From phone LTE: open ${HOME_AGENT_BASE}/health — should return JSON { ok: true }`,
        "Router: port forward TCP 80 → 192.168.1.58:80",
        "Windows Firewall: allow inbound TCP 80 for node.exe",
      ],
      time: now(),
    };
    log("error", "backend -> home-agent failed", diag);
    res.status(504).json(diag);
  }
});

app.use((req, res) => {
  res.status(404).json({ ok: false, error: "NOT_FOUND", path: req.path, time: now() });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  log("info", "backend listening", { port: PORT, homeAgent: HOME_AGENT_BASE });
});
