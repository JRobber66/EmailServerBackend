// server.mjs — Ultra-verbose gateway to your home agent
import express from "express";
import os from "os";

const app = express();
app.use(express.json({ limit: "256kb" }));

// ---- CONFIG: your public IP + agent port
const HOME_AGENT_BASE = "http://98.156.77.218:31001"; // <-- change if needed

// ---- logging helpers
const now = () => new Date().toISOString();
const log = (level, msg, extra = {}) =>
  console.log(JSON.stringify({ level, time: now(), host: os.hostname(), msg, ...extra }));

app.use((req, _res, next) => {
  // raw request logger (without body parse for OPTIONS)
  log("info", "INCOMING", {
    method: req.method,
    path: req.path,
    query: req.query,
    headers: {
      host: req.headers.host,
      origin: req.headers.origin,
      "user-agent": req.headers["user-agent"],
      "content-type": req.headers["content-type"],
      referer: req.headers.referer,
      "accept-encoding": req.headers["accept-encoding"],
    },
  });
  next();
});

// CORS
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") {
    log("info", "CORS preflight 204", { path: req.path });
    return res.sendStatus(204);
  }
  next();
});

// Health
app.get("/health", (req, res) => {
  log("info", "backend /health");
  res.json({
    ok: true,
    who: "backend",
    time: now(),
    homeAgentTarget: HOME_AGENT_BASE,
    note: "Use /debug/ping-home to verify Railway -> Home-Agent reachability.",
  });
});

// Diagnostic: fetch home-agent /health and report everything
app.get("/debug/ping-home", async (req, res) => {
  const url = `${HOME_AGENT_BASE}/health`;
  log("info", "debug ping -> home", { url });

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort("timeout"), 6000);
    const r = await fetch(url, { signal: ctrl.signal }).finally(() => clearTimeout(t));
    const text = await r.text();
    log("info", "debug ping <- home", { status: r.status, body: text.slice(0, 2000) });
    res.status(200).json({
      ok: true,
      tried: url,
      status: r.status,
      raw: text,
      time: now(),
    });
  } catch (err) {
    log("error", "debug ping FAILED", { url, error: String(err) });
    res.status(504).json({
      ok: false,
      error: "PING_HOME_FAILED",
      message: String(err),
      tried: url,
      probableCauses: [
        "Port forward missing/incorrect (router must forward TCP 31001 -> 192.168.1.58:31001).",
        "Windows firewall blocking inbound on port 31001.",
        "ISP CGNAT or inbound port blocking.",
        "Home agent not listening on 0.0.0.0.",
      ],
      time: now(),
    });
  }
});

// Diagnostic: send a minimal login JSON to home-agent
app.get("/debug/try-login", async (req, res) => {
  const url = `${HOME_AGENT_BASE}/api/auth/login-plain`;
  // Tiny body just to exercise the pipeline; change email/host if you want.
  const body = {
    email: "debug@example.com",
    host: "127.0.0.1",
    port: 993,
    secure: true,
    password: "test",
  };
  log("info", "debug try-login -> home", { url, body: { ...body, password: "***" } });

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort("timeout"), 9000);
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    }).finally(() => clearTimeout(t));

    const text = await r.text();
    log("info", "debug try-login <- home", { status: r.status, body: text.slice(0, 2000) });
    res.status(200).json({
      ok: true,
      tried: url,
      status: r.status,
      raw: text,
      time: now(),
    });
  } catch (err) {
    log("error", "debug try-login FAILED", { url, error: String(err) });
    res.status(504).json({
      ok: false,
      error: "TRY_LOGIN_FAILED",
      message: String(err),
      tried: url,
      time: now(),
    });
  }
});

// Real endpoint the frontend calls
app.post("/api/auth/login-plain", async (req, res) => {
  const body = req.body || {};
  log("info", "frontend -> backend login-plain", {
    body: { ...body, password: body.password ? "***" : "" },
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
      expected: "{ email, host, port, secure, password }",
      time: now(),
    };
    log("warn", "login-plain validation fail", diag);
    return res.status(400).json(diag);
  }

  const url = `${HOME_AGENT_BASE}/api/auth/login-plain`;
  log("info", "backend -> home-agent login", { url });

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort("timeout"), 9000);
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    }).finally(() => clearTimeout(t));

    const text = await r.text();
    let json; try { json = JSON.parse(text); } catch {}
    log("info", "backend <- home-agent", {
      status: r.status,
      parsed: Boolean(json),
      rawPreview: text.slice(0, 1000),
    });

    res.status(r.status).type(json ? "application/json" : "text/plain")
       .send(json ? JSON.stringify(json) : text);
  } catch (err) {
    log("error", "backend -> home-agent FAILED", { url, error: String(err) });
    res.status(504).json({
      ok: false,
      error: "HOME_AGENT_UNREACHABLE",
      message: String(err),
      tried: url,
      quickChecks: [
        `From *outside your LAN* visit ${HOME_AGENT_BASE}/health — should return JSON.`,
        "Router must forward TCP 31001 -> 192.168.1.58:31001",
        "Windows Firewall inbound allow for node.exe on 31001",
        "Home agent must bind 0.0.0.0:31001 (not 127.0.0.1)",
      ],
      time: now(),
    });
  }
});

// 404
app.use((req, res) => {
  log("warn", "404", { path: req.path });
  res.status(404).json({ ok: false, error: "NOT_FOUND", path: req.path, time: now() });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  log("info", "backend listening", { port: PORT, homeAgentTarget: HOME_AGENT_BASE });
});

// ---- background pinger (every 20s) to prove Railway can/can't reach your PC
setInterval(async () => {
  const url = `${HOME_AGENT_BASE}/health`;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort("timeout"), 6000);
    const r = await fetch(url, { signal: ctrl.signal }).finally(() => clearTimeout(t));
    const text = await r.text();
    log("info", "BG-PING OK", { status: r.status, preview: text.slice(0, 200) });
  } catch (e) {
    log("error", "BG-PING FAIL", { url, error: String(e) });
  }
}, 20000);
