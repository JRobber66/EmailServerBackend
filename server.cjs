const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { ImapFlow } = require("imapflow");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const net = require("net");
const tls = require("tls");

// ===== Direct Configuration (no env vars) =====
const CONFIG = {
  HMAIL_HOST: "mail.refnull.net",   // your home hMailServer hostname (98.156.77.218)
  IMAP_PORT: 993,
  IMAP_SECURE: true,                // IMAPS on 993
  SMTP_PORT: 587,
  SMTP_SECURE: false,               // STARTTLS on 587
  ALLOW_SELF_SIGNED: false,         // set true only if hMail uses self-signed certs
  SESSION_TTL_MIN: 30               // minutes; token lifetime
};

// CORS allow-list — add every frontend origin you’ll use
const ALLOWED_ORIGINS = [
  "https://refnul.net", // user/org GitHub Pages
  // Add custom domains here if you host the frontend elsewhere:
  // "https://refnull.net",
  // "https://mail.refnull.net"
];

// ===== In-memory session store =====
const sessions = new Map(); // token -> { username, password, createdAt }
setInterval(() => {
  const now = Date.now();
  for (const [token, s] of sessions) {
    if (now - s.createdAt > CONFIG.SESSION_TTL_MIN * 60_000) sessions.delete(token);
  }
}, 60_000);

// ===== Helpers =====
function newToken() { return crypto.randomUUID(); }
function getAuth(req) {
  const m = (req.headers.authorization || "").match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}
function requireSession(req, res, next) {
  const token = getAuth(req);
  if (!token || !sessions.has(token)) return res.status(401).json({ error: "Unauthorized" });
  req.session = sessions.get(token);
  next();
}

async function withImap({ username, password, fn }) {
  const client = new ImapFlow({
    host: CONFIG.HMAIL_HOST,
    port: CONFIG.IMAP_PORT,
    secure: CONFIG.IMAP_SECURE,
    logger: false,
    tls: CONFIG.ALLOW_SELF_SIGNED ? { rejectUnauthorized: false } : undefined,
    auth: { user: username, pass: password }
  });
  try {
    await client.connect();
    return await fn(client);
  } finally {
    try { await client.logout(); } catch {}
  }
}

function smtpTransport({ username, password }) {
  return nodemailer.createTransport({
    host: CONFIG.HMAIL_HOST,
    port: CONFIG.SMTP_PORT,
    secure: CONFIG.SMTP_SECURE,
    tls: CONFIG.ALLOW_SELF_SIGNED ? { rejectUnauthorized: false } : undefined,
    auth: { user: username, pass: password }
  });
}

function tcpCheck(host, port, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const started = Date.now();
    const sock = net.connect({ host, port });
    let done = false;

    const finish = (ok, info) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch {}
      resolve({ ok, ms: ok ? Date.now() - started : null, error: ok ? null : info || "connect_failed" });
    };

    const to = setTimeout(() => finish(false, "timeout"), timeoutMs);
    sock.once("connect", () => { clearTimeout(to); finish(true); });
    sock.once("error", (e) => { clearTimeout(to); finish(false, e && e.message); });
  });
}

function tlsCheck(host, port, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const started = Date.now();
    const sock = tls.connect({ host, port, rejectUnauthorized: false }); // diagnose reachability/handshake only
    let done = false;
    const finish = (ok, info) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch {}
      resolve({ ok, ms: ok ? Date.now() - started : null, error: ok ? null : info || "tls_failed" });
    };
    const to = setTimeout(() => finish(false, "timeout"), timeoutMs);
    sock.once("secureConnect", () => { clearTimeout(to); finish(true); });
    sock.once("error", (e) => { clearTimeout(to); finish(false, e && e.message); });
  });
}

// ===== Express App =====
const app = express();

// --- CORS FIRST (so preflight never gets blocked by parsers) ---
const corsOptions = {
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error(`CORS blocked: ${origin}`));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 600
};
app.use((req, res, next) => { res.setHeader("Vary", "Origin"); next(); });
app.use(cors(corsOptions));
app.options("*", cors(corsOptions)); // handle preflight early

// --- Security, parsers, rate limit ---
app.use(helmet());
app.use(express.json({ limit: "200kb" }));
app.use(rateLimit({ windowMs: 60_000, max: 90, standardHeaders: true, legacyHeaders: false }));

// --- Health & probe ---
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, host: CONFIG.HMAIL_HOST, time: new Date().toISOString() });
});

app.get("/api/probe", async (_req, res) => {
  const host = CONFIG.HMAIL_HOST;
  const out = { host, ts: new Date().toISOString(), results: {} };
  out.results.imap_993_tcp = await tcpCheck(host, CONFIG.IMAP_PORT);
  // try TLS handshake on 993 (IMAPS)
  out.results.imap_993_tls = await tlsCheck(host, CONFIG.IMAP_PORT);
  out.results.smtp_587_tcp = await tcpCheck(host, CONFIG.SMTP_PORT);
  res.json(out);
});

// --- Auth: login / logout ---
app.post("/api/login", async (req, res) => {
  let { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  if (!username.includes("@")) username = `${username}@refnull.net`; // convenience

  try {
    await withImap({
      username, password,
      fn: async (client) => { await client.mailboxOpen("INBOX", { readOnly: true }); }
    });
    const token = newToken();
    sessions.set(token, { username, password, createdAt: Date.now() });
    res.json({ token, ttlMinutes: CONFIG.SESSION_TTL_MIN });
  } catch (err) {
    res.status(401).json({ error: "Invalid credentials or IMAP unavailable", detail: err?.message });
  }
});

app.post("/api/logout", requireSession, (req, res) => {
  const token = getAuth(req);
  sessions.delete(token);
  res.json({ ok: true });
});

// --- Messages: list / read ---
app.get("/api/messages", requireSession, async (req, res) => {
  const mailbox = req.query.mailbox || "INBOX";
  const limit = Math.min(Number(req.query.limit || 25), 100);
  try {
    const messages = await withImap({
      username: req.session.username,
      password: req.session.password,
      fn: async (client) => {
        await client.mailboxOpen(mailbox, { readOnly: true });
        const total = client.mailbox.exists || 0;
        const seqStart = Math.max(total - limit + 1, 1);
        const list = [];
        for await (const msg of client.fetch(`${seqStart}:*`, { envelope: true, uid: true, internalDate: true, size: true, flags: true })) {
            list.push({
              uid: msg.uid,
              date: msg.internalDate,
              subject: msg.envelope?.subject || "",
              from: (msg.envelope?.from || []).map(a => a.address).join(", "),
              to: (msg.envelope?.to || []).map(a => a.address).join(", "),
              size: msg.size || 0,
              flags: Array.from(msg.flags || [])
            });
        }
        return list.reverse();
      }
    });
    res.json({ mailbox, messages });
  } catch (err) {
    res.status(500).json({ error: "Failed to list messages", detail: err?.message });
  }
});

app.get("/api/messages/:uid", requireSession, async (req, res) => {
  const uid = Number(req.params.uid);
  if (!uid) return res.status(400).json({ error: "invalid uid" });

  try {
    const text = await withImap({
      username: req.session.username,
      password: req.session.password,
      fn: async (client) => {
        await client.mailboxOpen("INBOX", { readOnly: true });
        const stream = await client.download(uid, null, { uid: true });
        return await streamToString(stream);
      }
    });
    res.json({ uid, text });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch message", detail: err?.message });
  }
});

function streamToString(stream) {
  return new Promise((resolve, reject) => {
    let data = "";
    stream.on("data", (c) => (data += c.toString("utf8")));
    stream.on("end", () => resolve(data));
    stream.on("error", reject);
  });
}

// --- Send ---
app.post("/api/send", requireSession, async (req, res) => {
  const { to, subject, text, html } = req.body || {};
  if (!to || (!text && !html)) return res.status(400).json({ error: "to and (text or html) required" });

  try {
    const t = smtpTransport(req.session);
    const info = await t.sendMail({
      from: req.session.username,
      to,
      subject: subject || "",
      text: text || undefined,
      html: html || undefined
    });
    res.json({ ok: true, messageId: info.messageId });
  } catch (err) {
    res.status(500).json({ error: "send failed", detail: err?.message });
  }
});

// ===== Start =====
const PORT = process.env.PORT || 8080; // Railway supplies PORT
app.listen(PORT, () => {
  console.log(`refnull mail API running on port ${PORT}`);
});
