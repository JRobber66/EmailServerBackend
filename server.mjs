import express from "express";
import os from "os";

const HOME_AGENT_HOST = "98.156.77.218";   // your WAN IP
const HOME_AGENT_PORT = 31001;             // forwarded to your PC
const HOME_AGENT_BASE = `http://${HOME_AGENT_HOST}:${HOME_AGENT_PORT}`;

const APP_PORT = process.env.PORT || 8080;
const APP_NAME = "railway-backend";
const POST_TIMEOUT_MS = 8000;

const now = () => new Date().toISOString();
const log = (level, msg, extra = {}) => {
  try { console.log(JSON.stringify({ level, time: now(), host: os.hostname(), msg, ...extra })); }
  catch { console.log(`[${level}] ${msg}`); }
};

const app = express();

// ----------- VERBOSE CORS (DYNAMIC) -----------
app.use((req, res, next) => {
  const origin  = req.headers.origin || "*";
  const acrm    = req.headers["access-control-request-method"] || "";
  const acrh    = req.headers["access-control-request-headers"] || ""; // comma-separated
  const ua      = req.headers["user-agent"] || "";

  // Log preflight intent
  if (req.method === "OPTIONS") {
    log("info", "CORS preflight IN", { path: req.path, acrm, acrh, origin, ua });
  }

  // Always reflect Origin (* is also fine, but some browsers prefer reflection)
  res.set("Access-Control-Allow-Origin", origin);
  res.set("Vary", "Origin");

  // Allow common methods
  res.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");

  // **CRITICAL**: echo back requested headers exactly so the browser is satisfied
  // If none requested, still allow common ones
  const allowHeaders = acrh ? acrh : "content-type, authorization, x-requested-with";
  res.set("Access-Control-Allow-Headers", allowHeaders);

  // Cache preflight to reduce noise
  res.set("Access-Control-Max-Age", "86400");

  if (req.method === "OPTIONS") {
    log("info", "CORS preflight OUT 204", { allowHeaders, origin });
    return res.sendStatus(204);
  }
  next();
});

// Body parser after CORS (so preflight doesn’t hit it)
app.use(express.json({ limit: "256kb" }));

// Global request logger
app.use((req, _res, next) => {
  log("info", "INCOMING", {
    method: req.method,
    path: req.path,
    origin: req.headers.origin || "",
    ct: req.headers["content-type"] || "",
  });
  next();
});

// Health
app.get("/health", (_req, res) => {
  res.json({ ok: true, who: APP_NAME, time: now() });
});

// Debug ping to your home agent
app.get("/debug/ping-home", async (_req, res) => {
  const url = `${HOME_AGENT_BASE}/health`;
  log("info", "BG-PING start", { url });
  try {
    const r = await fetch(url, { method: "GET" });
    const text = await r.text();
    log("info", "BG-PING ok", { status: r.status, len: text.length });
    res.status(200).json({ ok: true, status: r.status, body: text.slice(0, 400) });
  } catch (e) {
    log("error", "BG-PING fail", diagFromFetch(e, url));
    res.status(502).json({ ok: false, error: "PING_HOME_FAIL", diag: diagFromFetch(e, url) });
  }
});

// MAIN proxy -> home agent
app.post("/api/auth/login-plain", async (req, res) => {
  const body = req.body || {};
  const scrub = { ...body, password: body.password ? "***" : "" };

  log("info", "login-plain received", { body: scrub });

  const missing = [];
  for (const k of ["email", "host", "port", "secure", "password"]) {
    if (body[k] === undefined || body[k] === null || body[k] === "") missing.push(k);
  }
  if (missing.length) {
    log("warn", "login-plain missing fields", { missing });
    return res.status(400).json({
      ok: false, error: "BAD_REQUEST_BODY", missing, time: now()
    });
  }

  const url = `${HOME_AGENT_BASE}/api/auth/login-plain`;
  const controller = new AbortController();
  const kill = setTimeout(() => controller.abort(), POST_TIMEOUT_MS);

  const forwardInit = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: controller.signal
  };

  log("info", "forwarding to home-agent", { url, forwardBody: scrub, timeoutMs: POST_TIMEOUT_MS });

  let r, text;
  try {
    r = await fetch(url, forwardInit);
    text = await r.text();
  } catch (e) {
    clearTimeout(kill);
    const diag = diagFromFetch(e, url);
    log("error", "forward failed", diag);
    return res.status(504).json({
      ok: false, error: "HOME_AGENT_UNREACHABLE", diag, time: now()
    });
  }
  clearTimeout(kill);

  log("info", "forward response", {
    status: r.status, len: (text || "").length, preview: (text || "").slice(0, 400)
  });

  res.status(r.status);
  res.set("content-type", r.headers.get("content-type") || "application/json");
  res.send(text);
});

// 404
app.use((req, res) => {
  log("warn", "NOT_FOUND", { path: req.path });
  res.status(404).json({ ok: false, error: "NOT_FOUND", path: req.path, time: now() });
});

app.listen(APP_PORT, () => {
  log("info", "backend listening", { port: APP_PORT, homeAgent: HOME_AGENT_BASE });
});

function diagFromFetch(e, target) {
  return {
    target,
    name: e?.name,
    message: e?.message,
    type: e?.type,
    cause: e?.cause ? { name: e.cause.name, code: e.cause.code, message: e.cause.message } : undefined
  };
}
