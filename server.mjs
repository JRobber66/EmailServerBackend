// server.mjs — Extremely Verbal Backend Gateway (targets your home agent on :31001)
// Node 18+ (uses global fetch). No node-fetch import.

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

// >>> HARD-CODED: your public IP + correct agent port
const HOME_AGENT_BASE = "http://98.156.77.218:31001";

function now() { return new Date().toISOString(); }
function log(level, msg, extra = {}) {
  console.log(JSON.stringify({ level, time: now(), host: os.hostname(), msg, ...extra }));
}

async function httpFetch(url, opts) {
  if (typeof globalThis.fetch === "function") return await globalThis.fetch(url, opts);
  const { default: nf } = await import("node-fetch"); // fallback only if needed
  return await nf(url, opts);
}

app.get("/health", (req, res) => {
  log("info", "backend health");
  res.json({ ok: true, who: "backend", time: now(), homeAgentTarget: HOME_AGENT_BASE });
});

function classifyNetErr(err) {
  const s = `${err?.code ?? ""} ${err?.type ?? ""} ${err?.name ?? ""} ${String(err)}`;
  const causes = [];
  if (/ECONNREFUSED/.test(s)) causes.push("Home agent not listening / firewall blocked / port forward missing.");
  if (/ETIMEDOUT|timeout|network timeout/i.test(s)) causes.push("No response from home agent (ISP block / firewall / wrong IP/port).");
  if (/ENETUNREACH|EHOSTUNREACH/.test(s)) causes.push("Route to host unreachable (wrong IP or network down).");
  if (/invalid json response body/i.test(s)) causes.push("Home agent returned non-JSON (proxy or captive portal?).");
  if (!causes.length) causes.push("Unknown network failure; check home agent logs.");
  return { probableCauses: causes, raw: s.trim() };
}

app.post("/api/auth/login-plain", async (req, res) => {
  const body = req.body || {};
  log("info", "frontend -> backend /api/auth/login-plain", {
    body: { ...body, password: body.password ? "***" : "" }
  });

  const missing = [];
  for (const k of ["email", "host", "port", "secure", "password"]) {
    if (body[k] === undefined || body[k] === null || body[k] === "") missing.push(k);
  }
  if (missing.length) {
    const diag = {
      ok: false,
      error: "BAD_REQUEST_BODY",
      message: `Missing fields: ${missing.join(", ")}`,
      need: "{ email, host, port, secure, password }",
      time: now(),
    };
    log("warn", "bad request body", diag);
    return res.status(400).json(diag);
  }

  const url = `${HOME_AGENT_BASE}/api/auth/login-plain`;
  log("info", "backend -> home-agent begin", {
    url,
    willSend: { ...body, password: "***" },
    timeoutMs: 9000
  });

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort("timeout"), 9000);

    const r = await httpFetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    }).finally(() => clearTimeout(t));

    const text = await r.text();
    let json;
    try { json = JSON.parse(text); } catch {}

    log("info", "backend <- home-agent response", {
      status: r.status,
      bodyParsed: Boolean(json),
      rawPreview: text.slice(0, 1000)
    });

    res.status(r.status).type(json ? "application/json" : "text/plain")
       .send(json ? JSON.stringify(json) : text);
  } catch (err) {
    const net = classifyNetErr(err);
    const diag = {
      ok: false,
      error: "HOME_AGENT_UNREACHABLE",
      message: String(err),
      homeAgentUrl: url,
      probableCauses: [
        ...net.probableCauses,
        "Router NAT loopback (hairpin) can break testing from your own LAN using public IP — Railway still reaches externally if port is open.",
        "ISP CGNAT: inbound port forwarding won’t work; need a reverse tunnel or a real public IP."
      ],
      quickChecks: [
        `From phone LTE (not Wi-Fi): open ${HOME_AGENT_BASE}/health — should return JSON { ok: true }`,
        "Router: forward TCP 31001 → 192.168.1.58:31001",
        "Windows Defender Firewall: allow inbound TCP 31001 for node.exe",
        "Home PC: netstat -ano | findstr :31001 shows LISTENING on 0.0.0.0:31001"
      ],
      rawError: net.raw,
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
  log("info", "backend listening", { port: PORT, homeAgentTarget: HOME_AGENT_BASE });
});
