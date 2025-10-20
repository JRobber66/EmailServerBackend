// server.cjs (CommonJS, Node 18+/20+)
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const cron = require("node-cron");
const { z } = require("zod");

// ------------ Config / Env ------------
const PORT = process.env.PORT || 3000;
const SERVICE_KEY = process.env.SERVICE_KEY;           // required
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;   // optional (for CORS)
const AGENT_URL = process.env.AGENT_URL;               // required
const AGENT_KEY = process.env.AGENT_KEY || "";         // optional extra header
const AGENT_PSK_B64 = process.env.AGENT_PSK_B64;       // required (32 bytes base64)
const MAIL_DOMAIN = process.env.MAIL_DOMAIN || "local";

if (!SERVICE_KEY || !AGENT_URL || !AGENT_PSK_B64) {
  console.error("Missing env: SERVICE_KEY, AGENT_URL, and AGENT_PSK_B64 are required.");
  process.exit(1);
}
const AGENT_PSK = Buffer.from(AGENT_PSK_B64, "base64");
if (AGENT_PSK.length !== 32) {
  console.error("AGENT_PSK_B64 must decode to exactly 32 bytes.");
  process.exit(1);
}

// ------------ App setup ------------
const app = express();
app.set("trust proxy", 1);
app.use(helmet({ crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: "512kb" }));

// CORS (restrict to your GitHub Pages origin if set)
app.use(
  cors({
    origin: FRONTEND_ORIGIN ? [FRONTEND_ORIGIN] : true,
    credentials: false
  })
);

// Rate limit
app.use(
  "/api",
  rateLimit({
    windowMs: 60_000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false
  })
);

// Basic service key gate
function requireServiceKey(req, res, next) {
  const key = req.headers["x-service-key"];
  if (!key || key !== SERVICE_KEY) return res.status(401).json({ error: "unauthorized" });
  next();
}

// ------------ DB (SQLite) ------------
let db;
(async () => {
  db = await open({ filename: "./data.db", driver: sqlite3.Database });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS temp_accounts (
      id INTEGER PRIMARY KEY,
      mailbox TEXT UNIQUE,
      password TEXT,
      purpose TEXT,
      created_at INTEGER,
      expires_at INTEGER
    );
  `);
})().catch((e) => {
  console.error("DB init error", e);
  process.exit(1);
});

// ------------ Crypto helpers (AES-256-GCM) ------------
function encryptJSON(obj) {
  const iv = crypto.randomBytes(12); // GCM nonce
  const cipher = crypto.createCipheriv("aes-256-gcm", AGENT_PSK, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: ciphertext.toString("base64")
  };
}

// (Agent will decrypt with the same PSK. Define JSON envelope:)
async function callAgent(op, payload) {
  const envelope = encryptJSON({ op, payload, ts: Date.now() });
  const r = await fetch(`${AGENT_URL}/agent`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(AGENT_KEY ? { "x-agent-key": AGENT_KEY } : {})
    },
    body: JSON.stringify(envelope)
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`Agent ${r.status}: ${text}`);
  }
  return r.json();
}

// ------------ Schemas ------------
const sendSchema = z.object({
  from: z.string().email(),
  to: z.string().email(),
  subject: z.string().max(512).optional().default(""),
  text: z.string().max(20000).optional(),
  html: z.string().max(20000).optional()
}).refine((d) => d.text || d.html, { message: "text or html required" });

const inboxSchema = z.object({
  mailbox: z.string().email(),
  limit: z.coerce.number().int().min(1).max(100).optional().default(25)
});

const createTempSchema = z.object({
  ttl_seconds: z.coerce.number().int().min(60).max(86400).optional().default(3600),
  purpose: z.string().max(64).optional().default("otp")
});

const deleteSchema = z.object({
  mailbox: z.string().email()
});

// ------------ Routes ------------
app.get("/health", (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// Send mail
app.post("/api/send", requireServiceKey, async (req, res) => {
  try {
    const data = sendSchema.parse(req.body);
    const result = await callAgent("send", data);
    res.json({ ok: true, result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// List inbox headers (agent should IMAP/POP and return headers)
app.get("/api/inbox", requireServiceKey, async (req, res) => {
  try {
    const data = inboxSchema.parse({ mailbox: req.query.mailbox, limit: req.query.limit });
    const result = await callAgent("listInbox", data);
    res.json(result);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Get full message by id
app.get("/api/message/:id", requireServiceKey, async (req, res) => {
  try {
    const mailbox = z.string().email().parse(req.query.mailbox);
    const id = z.string().min(1).max(256).parse(req.params.id);
    const result = await callAgent("getMessage", { mailbox, id });
    res.json(result);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Create temp mailbox (random local-part) and store expiry
app.post("/api/create-temp", requireServiceKey, async (req, res) => {
  try {
    const { ttl_seconds, purpose } = createTempSchema.parse(req.body || {});
    const local = "t" + crypto.randomBytes(4).toString("hex");
    const password = crypto.randomBytes(12).toString("base64url");
    const mailbox = `${local}@${MAIL_DOMAIN}`;

    // Ask agent to create the mailbox
    await callAgent("createAccount", { mailbox, password });

    const now = Math.floor(Date.now() / 1000);
    const expires = now + ttl_seconds;
    await db.run(
      "INSERT INTO temp_accounts (mailbox, password, purpose, created_at, expires_at) VALUES (?,?,?,?,?)",
      mailbox, password, purpose, now, expires
    );

    res.json({ mailbox, password, expires_at: expires });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Delete an account now
app.post("/api/delete-account", requireServiceKey, async (req, res) => {
  try {
    const { mailbox } = deleteSchema.parse(req.body || {});
    await callAgent("deleteAccount", { mailbox });
    await db.run("DELETE FROM temp_accounts WHERE mailbox = ?", mailbox);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Admin view of temp accounts
app.get("/api/admin/temp-accounts", requireServiceKey, async (_req, res) => {
  const rows = await db.all("SELECT * FROM temp_accounts ORDER BY expires_at DESC");
  res.json(rows);
});

// Cleanup job (every 5 minutes): delete expired accounts via agent
cron.schedule("*/5 * * * *", async () => {
  try {
    const now = Math.floor(Date.now() / 1000);
    const expired = await db.all("SELECT mailbox FROM temp_accounts WHERE expires_at <= ?", now);
    for (const { mailbox } of expired) {
      try {
        await callAgent("deleteAccount", { mailbox });
      } catch (e) {
        // If agent fails, leave the row (will retry next cycle)
        console.error("cleanup deleteAccount error:", mailbox, e.message);
        continue;
      }
      await db.run("DELETE FROM temp_accounts WHERE mailbox = ?", mailbox);
      console.log("Deleted expired", mailbox);
    }
  } catch (e) {
    console.error("cleanup job error:", e.message);
  }
});

// 404
app.use((_req, res) => res.status(404).json({ error: "not found" }));

// Start
app.listen(PORT, () => {
  console.log(`API listening on :${PORT}`);
});
