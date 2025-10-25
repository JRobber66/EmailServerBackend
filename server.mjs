import express from "express";
import os from "os";

// ======= HARD-CODE YOUR PC AGENT HERE =======
const HOME_AGENT_HOST = "98.156.77.218";
const HOME_AGENT_PORT = 31001;
const HOME_AGENT_BASE = `http://${HOME_AGENT_HOST}:${HOME_AGENT_PORT}`;

const APP_PORT = process.env.PORT || 8080;
const APP_NAME = "railway-backend";
const POST_TIMEOUT_MS = 8000; // stay under browser/edge default timeouts

// tiny logger
const now = () => new Date().toISOString();
const log = (level, msg, extra = {}) => {
  try {
    console.log(JSON.stringify({ level, time: now(), host: os.hostname(), msg, ...extra }));
  } catch (e) {
    console.log(`[${level}] ${msg} ${String(e)}`);
  }
};

const app = express();
app.use(express.json({ limit: "256kb" }));

// global request logger
app.use((req, res, next) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  log("info", "INCOMING", {
    method: req.method,
    path: req.path,
    ip,
    headers: {
      host: req.headers.host,
      origin: req.headers.origin,
      "user-agent": req.headers["user-agent"],
      "content-type": req.headers["content-type"]
    }
  });
  next();
});

// permissive CORS
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") {
    log("info", "CORS preflight 204");
    return res.sendStatus(204);
  }
  next();
});

// health
app.get("/health", (_req, res) => {
  res.json({ ok: true, who: APP_NAME, time: now() });
});

// verify we can reach your PC /health
app.get("/debug/ping-home", async (_req, res) => {
  const url = `${HOME_AGENT_BASE}/health`;
  log("info", "BG-PING start", { url });
  try {
    const r = await fetch(url, { method: "GET" });
    const text = await r.text();
    log("info", "BG-PING ok", { status: r.status, len: text.length });
    res.status(200).json({ ok: true, status: r.status, body: safeSlice(text) });
  } catch (e) {
    const diag = fetchErrDiag(e);
    log("error", "BG-PING fail", diag);
    res.status(502).json({ ok: false, error: "PING_HOME_FAIL", diag });
  }
});

// MAIN: forward login to your PC agent
app.post("/api/auth/login-plain", async (req, res) => {
  const body = req.body || {};
  const scrub = { ...body, password: body.password ? "***" : "" };

  log("info", "login-plain received", { incomingBody: scrub });

  // validate quickly before forwarding
  const missing = [];
  for (const k of ["email", "host", "port", "secure", "password"]) {
    if (body[k] === undefined || body[k] === null || body[k] === "") missing.push(k);
  }
  if (missing.length) {
    log("warn", "login-plain bad body", { missing });
    return res.status(400).json({
      ok: false,
      error: "BAD_REQUEST_BODY",
      message: `Missing: ${missing.join(", ")}`,
      expected: "{ email, host, port, secure, password }",
      time: now()
    });
  }

  const url = `${HOME_AGENT_BASE}/api/auth/login-plain`;
  const controller = new AbortController();
  const kill = setTimeout(() => controller.abort(), POST_TIMEOUT_MS);

  const forward = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: controller.signal
  };

  log("info", "forwarding to PC", { url, forwardBody: scrub, timeoutMs: POST_TIMEOUT_MS });

  let r;
  try {
    r = await fetch(url, forward);
  } catch (e) {
    clearTimeout(kill);
    const diag = fetchErrDiag(e);
    log("error", "forward fetch failed", diag);
    // return explicit JSON so browser shows something useful
    return res.status(504).json({
      ok: false,
      error: "HOME_AGENT_UNREACHABLE",
      message: "Failed to fetch from PC home-agent",
      target: url,
      diag,
      suggestions: [
        "Confirm your PC agent is running and listening on 0.0.0.0:31001",
        "Verify router port-forward TCP 31001 → 192.168.1.58:31001",
        "Check Windows Firewall allows inbound TCP 31001 for node.exe",
        "Open http://98.156.77.218:31001/health from the Railway shell"
      ],
      time: now()
    });
  }
  clearTimeout(kill);

  const text = await r.text();
  log("info", "forward response", {
    status: r.status,
    len: text.length,
    preview: safeSlice(text)
  });

  // pass through status & body so you see PC-agent’s diagnostics
  res.status(r.status);
  res.set("content-type", r.headers.get("content-type") || "application/json");
  res.send(text);
});

// 404
app.use((req, res) => {
  log("warn", "backend 404", { path: req.path });
  res.status(404).json({ ok: false, error: "NOT_FOUND", path: req.path, time: now() });
});

// start
app.listen(APP_PORT, () => {
  log("info", "backend listening", { port: APP_PORT, homeAgent: HOME_AGENT_BASE });
});

// ==== helpers ====
function safeSlice(s, n = 300) {
  if (typeof s !== "string") return String(s);
  return s.length > n ? s.slice(0, n) + ` …(${s.length} bytes)` : s;
}
function fetchErrDiag(e) {
  // surface AbortError, system codes etc.
  const diag = {
    name: e?.name,
    message: e?.message,
    type: e?.type,
  };
  // node abort error
  if (e?.name === "AbortError") {
    diag.reason = "Request timed out or was aborted";
  }
  // node system error codes (ECONNREFUSED, ETIMEDOUT, EHOSTUNREACH, etc.)
  if (e?.cause) {
    diag.cause = {
      name: e.cause.name,
      code: e.cause.code,
      message: e.cause.message
    };
  }
  return diag;
}
