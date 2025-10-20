// server.cjs — boot-safe (no native loads), AES-256-GCM to agent, inbox/message w/ password

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const cron = require("node-cron");
const { z } = require("zod");

// ---------- ENV ----------
const PORT = process.env.PORT || 3000;
const SERVICE_KEY = process.env.SERVICE_KEY || "";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "";
const AGENT_URL = process.env.AGENT_URL || "";
const AGENT_KEY = process.env.AGENT_KEY || "";
const AGENT_PSK_B64 = process.env.AGENT_PSK_B64 || "";
const MAIL_DOMAIN = process.env.MAIL_DOMAIN || "local";

// Boot log (safe; no secrets)
console.log("[BOOT] PORT=%s, FRONTEND_ORIGIN=%s, MAIL_DOMAIN=%s", PORT, FRONTEND_ORIGIN || "(any)", MAIL_DOMAIN);
console.log("[BOOT] SERVICE_KEY set? %s", SERVICE_KEY ? "yes" : "NO");
console.log("[BOOT] AGENT_URL=%s", AGENT_URL || "(missing)");
console.log("[BOOT] AGENT_KEY set? %s", AGENT_KEY ? "yes" : "no");
console.log("[BOOT] AGENT_PSK_B64 set? %s", AGENT_PSK_B64 ? "yes" : "NO");

// Validate PSK (but don’t crash boot)
let AGENT_PSK = null;
try {
  const buf = Buffer.from(AGENT_PSK_B64 || "", "base64");
  if (buf.length === 32) AGENT_PSK = buf;
  else if (AGENT_PSK_B64) console.error("[BOOT] AGENT_PSK_B64 decodes to %d bytes (need 32).", buf.length);
} catch (e) {
  console.error("[BOOT] AGENT_PSK_B64 invalid base64: %s", e.message);
}

// ---------- APP ----------
const app = express();
app.set("trust proxy", 1);
app.use(helmet({ crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: "512kb" }));
app.use(
  cors({ origin: FRONTEND_ORIGIN ? [FRONTEND_ORIGIN] : true, credentials: false })
);
app.use(
  "/api",
  rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false })
);

function requireServiceKey(req, res, next) {
  const key = req.headers["x-service-key"];
  if (!key || key !== SERVICE_KEY) return res.status(401).json({ error: "unauthorized" });
  next();
}

// ---------- LAZY DB (no native require on boot) ----------
let db = null;
let dbReady = false;
async function ensureDB() {
  if (dbReady) return db;
  try {
    // Lazy import to avoid native load at boot
    const { open } = require("sqlite");
    const sqlite3 = require("sqlite3");
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
    dbReady = true;
    console.log("[DB] ready");
  } catch (e) {
    console.error("[DB] init error; continuing without persistence:", e.message);
    db = null; dbReady = true; // mark as tried; run without DB
  }
  return db;
}

// ---------- CRYPTO ----------
function encryptJSON(obj) {
  if (!AGENT_PSK) throw new Error("server not fully configured (AGENT_PSK)");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", AGENT_PSK, iv);
  const pt = Buffer.from(JSON.stringify(obj), "utf8");
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString("base64"), tag: tag.toString("base64"), data: ct.toString("base64") };
}

async function callAgent(op, payload) {
  if (!AGENT_URL) throw new Error("server not fully configured (AGENT_URL)");
  const envelope = encryptJSON({ op, payload, ts: Date.now() });
  const r = await fetch(`${AGENT_URL}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(AGENT_KEY ? { "x-agent-key": AGENT_KEY } : {}) },
    body: JSON.stringify(envelope),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`Agent ${r.status}: ${text || "no body"}`);
  }
  return r.json();
}

// ---------- SCHEMAS ----------
const sendSchema = z.object({
  from: z.string().email(),
  to: z.string().email(),
  subject: z.string().max(512).optional().default(""),
  text: z.string().max(20000).optional(),
  html: z.string().max(20000).optional(),
}).refine(d => d.text || d.html, { message: "text or html required" });

const createTempSchema = z.object({
  ttl_seconds: z.coerce.number().int().min(60).max(86400).optional().default(3600),
  purpose: z.string().max(64).optional().default("otp"),
});

const delSchema = z.object({ mailbox: z.string().email() });

const inboxWithPassSchema = z.object({
  mailbox: z.string().email(),
  password: z.string().min(1),
  limit: z.coerce.number().int().min(1).max(100).optional().default(25),
});

const getMsgSchema = z.object({
  mailbox: z.string().email(),
  password: z.string().min(1),
  id: z.union([z.string(), z.number()]).transform(String),
});

// ---------- ROUTES ----------
app.get("/health", (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.post("/api/send", requireServiceKey, async (req, res) => {
  try {
    const data = sendSchema.parse(req.body || {});
    const result = await callAgent("send", data);
    res.json({ ok: true, result });
  } catch (e) {
    console.error("[/api/send] %s", e.message);
    res.status(400).json({ error: e.message });
  }
});

app.post("/api/create-temp", requireServiceKey, async (req, res) => {
  try {
    const { ttl_seconds, purpose } = createTempSchema.parse(req.body || {});
    const local = "t" + crypto.randomBytes(4).toString("hex");
    const password = crypto.randomBytes(12).toString("base64url");
    const mailbox = `${local}@${MAIL_DOMAIN}`;

    await callAgent("createAccount", { mailbox, password });

    const now = Math.floor(Date.now() / 1000);
    const expires = now + ttl_seconds;

    const _db = await ensureDB();
    if (_db) {
      await _db.run(
        "INSERT INTO temp_accounts (mailbox,password,purpose,created_at,expires_at) VALUES (?,?,?,?,?)",
        mailbox, password, purpose, now, expires
      );
    }
    res.json({ mailbox, password, expires_at: expires });
  } catch (e) {
    console.error("[/api/create-temp] %s", e.message);
    res.status(400).json({ error: e.message });
  }
});

app.post("/api/delete-account", requireServiceKey, async (req, res) => {
  try {
    const { mailbox } = delSchema.parse(req.body || {});
    await callAgent("deleteAccount", { mailbox });

    const _db = await ensureDB();
    if (_db) await _db.run("DELETE FROM temp_accounts WHERE mailbox = ?", mailbox);

    res.json({ ok: true });
  } catch (e) {
    console.error("[/api/delete-account] %s", e.message);
    res.status(400).json({ error: e.message });
  }
});

app.post("/api/inbox", requireServiceKey, async (req, res) => {
  try {
    const data = inboxWithPassSchema.parse(req.body || {});
    const result = await callAgent("listInbox", data);
    res.json(result);
  } catch (e) {
    console.error("[/api/inbox] %s", e.message);
    res.status(400).json({ error: e.message });
  }
});

app.post("/api/message", requireServiceKey, async (req, res) => {
  try {
    const data = getMsgSchema.parse(req.body || {});
    const result = await callAgent("getMessage", data);
    res.json(result);
  } catch (e) {
    console.error("[/api/message] %s", e.message);
    res.status(400).json({ error: e.message });
  }
});

app.get("/api/inbox", requireServiceKey, (_req, res) =>
  res.status(400).json({ error: "use POST /api/inbox with { mailbox, password, limit }" })
);

app.get("/api/admin/temp-accounts", requireServiceKey, async (_req, res) => {
  const _db = await ensureDB();
  if (!_db) return res.json([]);
  const rows = await _db.all("SELECT * FROM temp_accounts ORDER BY expires_at DESC");
  res.json(rows);
});

cron.schedule("*/5 * * * *", async () => {
  try {
    const _db = await ensureDB();
    if (!_db) return;
    const now = Math.floor(Date.now() / 1000);
    const expired = await _db.all("SELECT mailbox FROM temp_accounts WHERE expires_at <= ?", now);
    for (const { mailbox } of expired) {
      try {
        await callAgent("deleteAccount", { mailbox });
        await _db.run("DELETE FROM temp_accounts WHERE mailbox = ?", mailbox);
        console.log("[CLEANUP] deleted", mailbox);
      } catch (e) {
        console.error("[CLEANUP] %s -> %s", mailbox, e.message);
      }
    }
  } catch (e) {
    console.error("[CLEANUP] job error:", e.message);
  }
});

app.use((_req, res) => res.status(404).json({ error: "not found" }));

app.listen(PORT, () => console.log(`API listening on :${PORT}`));
