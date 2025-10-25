// Extremely Verbal Backend Gateway — targets your home agent directly
// Hard-coded to your public IP on port 80.

import express from "express";
import fetch from "node-fetch";
import os from "os";

const app = express();
app.use(express.json({ limit: "256kb" }));

// CORS for browser clients
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// >>> CHANGE THIS if your public IP changes <<<
const HOME_AGENT_BASE = "http://98.156.77.218"; // port 80

function now() {
  return new Date().toISOString();
}
function log(level, msg, extra = {}) {
  console.log(JSON.stringify({ level, time: now(), host: os.hostname(), msg, ...extra }));
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
  if (/ETIMEDOUT|Request timed out|network timeout/.test(s)) causes.push("No response from home agent (ISP block / firewall / wrong IP).");
  if (/ENETUNREACH|EHOSTUNREACH/.test(s)) causes.push("Route to host unreachable (wrong IP or network down).");
  if (/FetchError: invalid json response body/.test(s)) causes.push("Home agent returned non-JSON (proxy or captive portal?).");
  if (causes.length === 0) causes.push("Unknown network failure; check home agent logs.");
  return { code: m, probableCauses: causes };
}

// Extremely verbal pass-through to the home agent
app.post("/api/auth/login-plain", async (req, res) => {
  const body = req.body || {};
  log("info", "frontend -> backend /api/auth/login-plain", { body });

  // Sanity check
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

  // Call home agent with aggressive logging & moderate timeout
  const url = `${HOME_AGENT_BASE}/api/auth/login-plain`;
  log("info", "backend -> home-agent begin", { url, targetBody: { ...body, password: !!body.password ? "***" : "(empty)" } });

  try {
    const ctrl = new AbortController();
    const timeoutMs = 6000; // keep under Railway’s 8s idle to avoid 504
    const t = setTimeout(() => ctrl.abort("timeout"), timeoutMs);

    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    }).finally(() => clearTimeout(t));

    const text = await r.text();
    let json;
    try { json = JSON.parse(text); } catch { /* leave json undefined */ }

    log("info", "backend <- home-agent response", {
      status: r.status,
      bodyParsed: Boolean(json),
      raw: text.slice(0, 4000), // preview
    });

    // Pass through status + body so frontend can see exact diagnostics
    res.status(r.status).type(json ? "application/json" : "text/plain").send(json ? JSON.stringify(json) : text);
  } catch (err) {
    const net = classifyNetErr(err);
    const diag = {
      ok: false,
      error: "HOME_AGENT_UNREACHABLE",
      message: String(err),
      homeAgentUrl: url,
      probableCauses: [
        ...net.probableCauses,
        "Router lacks NAT loopback? (If you test from the same LAN using the public IP, use the LAN URL instead.)",
        "ISP CGNAT (inbound port forwarding impossible) — ask for public IP or use a reverse tunnel.",
      ],
      quickChecks: [
        `From your phone's LTE: open ${HOME_AGENT_BASE}/health — must return { ok: true }`,
        "Router: TCP 80 → 192.168.1.58:80",
        "Windows Firewall: allow inbound TCP 80 for node",
      ],
      time: now(),
    };
    log("error", "backend -> home-agent failed", diag);
    res.status(504).json(diag); // 504 so the UI clearly sees a gatewayish timeout path
  }
});

// Fallback route to show where you are
app.use((req, res) => {
  res.status(404).json({ ok: false, error: "NOT_FOUND", path: req.path, time: now() });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  log("info", "backend listening", { port: PORT, homeAgent: HOME_AGENT_BASE });
});
