const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { ImapFlow } = require("imapflow");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

// ===== Direct Configuration =====
const CONFIG = {
  HMAIL_HOST: "mail.refnull.net",      // your home mail server
  IMAP_PORT: 993,
  IMAP_SECURE: true,
  SMTP_PORT: 587,
  SMTP_SECURE: false,                  // false means STARTTLS
  ALLOW_SELF_SIGNED: false,            // set true if self-signed cert
  ALLOWED_ORIGIN: "https://jrobber66.github.io",
  SESSION_TTL_MIN: 30                  // minutes
};

// ===== In-memory session store =====
const sessions = new Map(); // token -> { username, password, createdAt }
setInterval(() => {
  const now = Date.now();
  for (const [token, sess] of sessions) {
    if (now - sess.createdAt > CONFIG.SESSION_TTL_MIN * 60_000) {
      sessions.delete(token);
    }
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

// ===== Express App =====
const app = express();
app.use(helmet());
app.use(express.json({ limit: "200kb" }));
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || origin === CONFIG.ALLOWED_ORIGIN) cb(null, true);
    else cb(new Error("CORS blocked"));
  }
}));
app.use(rateLimit({
  windowMs: 60_000,
  max: 90,
  standardHeaders: true
}));

// ===== Routes =====
app.get("/api/health", (_req, res) => res.json({ ok: true, host: CONFIG.HMAIL_HOST }));

// --- Login ---
app.post("/api/login", async (req, res) => {
  let { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  if (!username.includes("@")) username += "@refnull.net"; // auto-append domain
  try {
    await withImap({
      username, password,
      fn: async (client) => { await client.mailboxOpen("INBOX", { readOnly: true }); }
    });
    const token = newToken();
    sessions.set(token, { username, password, createdAt: Date.now() });
    res.json({ token, ttlMinutes: CONFIG.SESSION_TTL_MIN });
  } catch (err) {
    res.status(401).json({ error: "Invalid credentials", detail: err.message });
  }
});

// --- List messages ---
app.get("/api/messages", requireSession, async (req, res) => {
  const mailbox = req.query.mailbox || "INBOX";
  const limit = Math.min(Number(req.query.limit || 25), 100);
  try {
    const result = await withImap({
      username: req.session.username,
      password: req.session.password,
      fn: async (client) => {
        await client.mailboxOpen(mailbox, { readOnly: true });
        const total = client.mailbox.exists || 0;
        const seqStart = Math.max(total - limit + 1, 1);
        const list = [];
        for await (const msg of client.fetch(`${seqStart}:*`, { envelope: true, uid: true, internalDate: true })) {
          list.push({
            uid: msg.uid,
            date: msg.internalDate,
            subject: msg.envelope.subject,
            from: (msg.envelope.from || []).map(a => a.address).join(", ")
          });
        }
        return list.reverse();
      }
    });
    res.json({ mailbox, messages: result });
  } catch (err) {
    res.status(500).json({ error: "Failed to list messages", detail: err.message });
  }
});

// --- Read message ---
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
    res.status(500).json({ error: "Failed to fetch", detail: err.message });
  }
});
function streamToString(stream) {
  return new Promise((resolve, reject) => {
    let data = "";
    stream.on("data", (c) => data += c.toString("utf8"));
    stream.on("end", () => resolve(data));
    stream.on("error", reject);
  });
}

// --- Send ---
app.post("/api/send", requireSession, async (req, res) => {
  const { to, subject, text } = req.body || {};
  if (!to || !text) return res.status(400).json({ error: "to and text required" });
  try {
    const t = smtpTransport(req.session);
    const info = await t.sendMail({
      from: req.session.username,
      to, subject, text
    });
    res.json({ ok: true, messageId: info.messageId });
  } catch (err) {
    res.status(500).json({ error: "send failed", detail: err.message });
  }
});

// --- Logout ---
app.post("/api/logout", requireSession, (req, res) => {
  const token = getAuth(req);
  sessions.delete(token);
  res.json({ ok: true });
});

// ===== Start =====
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`refnull mail API running on port ${PORT}`);
});
