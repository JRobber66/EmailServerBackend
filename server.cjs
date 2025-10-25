/* server.cjs — Railway proxy to your home-agent with diagnostics (CommonJS, no .env) */

const express = require('express');

// ======== CHANGE THIS TO YOUR TUNNEL OR PUBLIC IP ========
// e.g. "https://abc-123.trycloudflare.com"  (HTTPS!)
// or   "http://203.0.113.55:31001"          (public IP + port forward)
const HOME_AGENT_BASE = "https://REPLACE_ME.trycloudflare.com"; // <— CHANGE THIS

// Tuning
const PORT = process.env.PORT ? Number(process.env.PORT) : 8080; // Railway injects PORT
const REQUEST_TIMEOUT_MS = 30000;   // generous timeout for slow home networks
const CONNECT_RETRIES = 2;          // a couple retries on transient errors
const ALLOW_ORIGIN = "*";           // CORS — lock down to your frontend origin if you want

// ------------- tiny logger
function log(level, obj) {
  try {
    const line = JSON.stringify({ level, time: new Date().toISOString(), ...obj });
    (level === 'error' ? process.stderr : process.stdout).write(line + '\n');
  } catch {}
}

// ------------- Express
const app = express();

// CORS + preflight
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// JSON body
app.use(express.json({ limit: '256kb', strict: true }));

// health
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'email-backend', time: new Date().toISOString() });
});

// -------- helpers
function redactBodyForLog(b) {
  if (!b || typeof b !== 'object') return b;
  const copy = { ...b };
  if ('password' in copy) copy.password = '(* redacted *)';
  if ('pass' in copy) copy.pass = '(* redacted *)';
  return copy;
}

async function fetchWithTimeout(url, opts, timeoutMs) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}

async function forwardToAgent(path, method, body) {
  const url = `${HOME_AGENT_BASE}${path}`;
  const headers = { 'content-type': 'application/json' };
  const payload = body ? JSON.stringify(body) : undefined;

  let lastErr;
  for (let attempt = 0; attempt <= CONNECT_RETRIES; attempt++) {
    try {
      log('info', { msg: 'forwarding', method, url, attempt, body: redactBodyForLog(body) });
      const res = await fetchWithTimeout(url, { method, headers, body: payload }, REQUEST_TIMEOUT_MS);

      const text = await res.text();
      // Pass-through semantics
      return {
        ok: true,
        status: res.status,
        text,
        headers: Object.fromEntries(res.headers.entries())
      };
    } catch (err) {
      lastErr = err;
      const abort = err && (err.name === 'AbortError' || err.code === 'ABORT_ERR');
      log('error', { msg: 'forwarding error', method, url, attempt, abort, error: String(err) });
      await new Promise(r => setTimeout(r, 250));
    }
  }

  return {
    ok: false,
    status: 504,
    text: JSON.stringify({
      ok: false,
      error: 'gateway_timeout',
      detail: 'Backend could not reach home-agent',
      agentBase: HOME_AGENT_BASE
    })
  };
}

// ------------- DIAGNOSTICS (super helpful)

// What does the backend think the agent base is?
app.get('/diag', (_req, res) => {
  res.json({
    ok: true,
    message: 'Backend is alive',
    agentBase: HOME_AGENT_BASE,
    now: new Date().toISOString()
  });
});

// Can Railway reach your home-agent /health?
app.get('/diag/agent-health', async (_req, res) => {
  try {
    const u = `${HOME_AGENT_BASE}/health`;
    const r = await fetchWithTimeout(u, {}, 7000);
    const t = await r.text();
    res.status(r.status).type(r.headers.get('content-type') || 'text/plain')
       .send(t);
  } catch (e) {
    res.status(502).json({ ok: false, error: 'agent_unreachable', detail: String(e), agentBase: HOME_AGENT_BASE });
  }
});

// echo proxy (useful for quick post tests)
app.post('/diag/echo', async (req, res) => {
  res.json({ ok: true, body: req.body, time: new Date().toISOString() });
});

// ------------- PROXIED API

// login-plain
app.post('/api/auth/login-plain', async (req, res) => {
  const { email, host, port, secure, password } = req.body || {};
  log('info', { msg: 'login-plain inbound', email, host, port, secure, havePassword: !!password });

  if (!email || typeof email !== 'string' || !password) {
    return res.status(400).json({ ok: false, error: 'bad_request', detail: 'email and password required' });
    }
  // Forward
  const out = await forwardToAgent('/api/auth/login-plain', 'POST', { email, host, port, secure, password });

  res.status(out.status);
  // Try JSON, fallback to text
  try { res.json(JSON.parse(out.text)); }
  catch { res.type('text/plain').send(out.text ?? ''); }
});

// list
app.post('/api/imap/list', async (req, res) => {
  const out = await forwardToAgent('/api/imap/list', 'POST', req.body || {});
  res.status(out.status);
  try { res.json(JSON.parse(out.text)); }
  catch { res.type('text/plain').send(out.text ?? ''); }
});

// get
app.post('/api/imap/get', async (req, res) => {
  const out = await forwardToAgent('/api/imap/get', 'POST', req.body || {});
  res.status(out.status);
  try { res.json(JSON.parse(out.text)); }
  catch { res.type('text/plain').send(out.text ?? ''); }
});

// open (stream-ish; pass through as text)
app.post('/api/imap/open', async (req, res) => {
  const out = await forwardToAgent('/api/imap/open', 'POST', req.body || {});
  res.status(out.status).type('text/plain').send(out.text ?? '');
});

// 404
app.use((_req, res) => res.status(404).json({ ok: false, error: 'not_found' }));

// start
app.listen(PORT, () => {
  log('info', {
    msg: 'backend listening',
    port: PORT,
    agentBase: HOME_AGENT_BASE,
    timeoutMs: REQUEST_TIMEOUT_MS,
    retries: CONNECT_RETRIES
  });
});
