/* server.cjs — CommonJS, no .env, hard-coded config */

const express = require('express');

// ===== HARD-CODE YOUR HOME-AGENT PUBLIC URL HERE =====
// Use your Cloudflare Tunnel URL (recommended), e.g.:
//   https://your-subdomain.trycloudflare.com
// OR your public IP + forwarded port, e.g.:
//   http://203.0.113.55:31001
const HOME_AGENT_BASE = "https://REPLACE_ME.trycloudflare.com";  // <-- CHANGE THIS

// Networking & behavior knobs
const PORT = process.env.PORT ? Number(process.env.PORT) : 8080; // Railway will set PORT
const REQUEST_TIMEOUT_MS = 25000;    // generous timeout for your home-agent roundtrip
const CONNECT_RETRIES = 2;           // retry a couple times on network-ish failures
const ALLOW_ORIGIN = "*";            // adjust if you want to lock down CORS

// ---- tiny logger
function log(level, obj) {
  try {
    const line = JSON.stringify({ level, time: new Date().toISOString(), ...obj });
    // Use stdout for info, stderr for error
    if (level === 'error') process.stderr.write(line + '\n');
    else process.stdout.write(line + '\n');
  } catch {
    // never throw from logger
  }
}

// ---- Express app
const app = express();

// basic CORS (and preflight)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// parse JSON (limit keeps us safe)
app.use(express.json({ limit: '256kb' }));

// health
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'email-backend', time: new Date().toISOString() });
});

// ---- helpers
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
    const res = await fetch(url, { ...opts, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(id);
  }
}

// generic forwarder to home-agent
async function forwardToAgent(path, method, body) {
  const url = `${HOME_AGENT_BASE}${path}`;
  const headers = { 'content-type': 'application/json' };

  const payload = body ? JSON.stringify(body) : undefined;

  let lastErr;
  for (let attempt = 0; attempt <= CONNECT_RETRIES; attempt++) {
    try {
      log('info', { msg: 'forwarding', url, method, attempt, body: redactBodyForLog(body) });

      const res = await fetchWithTimeout(
        url,
        { method, headers, body: payload },
        REQUEST_TIMEOUT_MS
      );

      const text = await res.text();
      // Pass through status & body
      return { status: res.status, body: text, headers: Object.fromEntries(res.headers.entries()) };

    } catch (err) {
      lastErr = err;
      const isAbort = err && (err.name === 'AbortError' || err.code === 'ABORT_ERR');
      log('error', { msg: 'forwarding error', url, attempt, error: String(err), abort: !!isAbort });
      // quick backoff between retries (non-blocking)
      await new Promise(r => setTimeout(r, 300));
    }
  }
  // If all attempts failed to connect or timed out:
  return { status: 504, body: JSON.stringify({ ok: false, error: 'gateway_timeout', detail: String(lastErr) }) };
}

// ---- routes that your frontend calls

// 1) login with plain password -> forwards to home-agent
app.post('/api/auth/login-plain', async (req, res) => {
  const { email, host, port, secure, password } = req.body || {};
  log('info', { msg: 'login-plain inbound', email, host, port, secure, havePassword: !!password });

  // minimal validation
  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'bad_request', detail: 'email and password required' });
  }

  // forward to your home-agent
  const out = await forwardToAgent('/api/auth/login-plain', 'POST', { email, host, port, secure, password });

  // normalize headers and return
  res.status(out.status);
  // keep it simple: always respond as JSON if agent returned JSON, otherwise raw text
  try {
    const maybeJson = JSON.parse(out.body);
    res.json(maybeJson);
  } catch {
    res.type('text/plain').send(out.body ?? '');
  }
});

// 2) optionally forward other agent endpoints as needed:

// list mailbox (example passthrough)
app.post('/api/imap/list', async (req, res) => {
  const out = await forwardToAgent('/api/imap/list', 'POST', req.body || {});
  res.status(out.status);
  try {
    res.json(JSON.parse(out.body));
  } catch {
    res.type('text/plain').send(out.body ?? '');
  }
});

// get a message (example passthrough)
app.post('/api/imap/get', async (req, res) => {
  const out = await forwardToAgent('/api/imap/get', 'POST', req.body || {});
  res.status(out.status);
  try {
    res.json(JSON.parse(out.body));
  } catch {
    res.type('text/plain').send(out.body ?? '');
  }
});

// keep-alive / open stream (example passthrough)
app.post('/api/imap/open', async (req, res) => {
  const out = await forwardToAgent('/api/imap/open', 'POST', req.body || {});
  res.status(out.status);
  // open may be NDJSON or text; just pass-through
  res.type('text/plain').send(out.body ?? '');
});

// fallback 404
app.use((_req, res) => {
  res.status(404).json({ ok: false, error: 'not_found' });
});

// start server
app.listen(PORT, () => {
  log('info', { msg: 'backend listening', port: PORT, agentBase: HOME_AGENT_BASE, timeoutMs: REQUEST_TIMEOUT_MS, retries: CONNECT_RETRIES });
});
