import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import axios from "axios";

/**
 * HARD-CODED home-agent address (your public IP). No .env.
 * Railway (public) must reach your home-agent via your WAN IP.
 */
const HOME_AGENT_BASE = "http://98.156.77.218:31001"; // <-- public IP + port forward

// Optional: if you ever want to test locally, flip this to the LAN IP:
// const HOME_AGENT_BASE = "http://192.168.1.58:31001";

const app = express();

// Permissive CORS for your frontend
app.use(cors({ origin: "*", methods: ["GET", "POST", "OPTIONS"], allowedHeaders: ["Content-Type"] }));

// Body parser
app.use(bodyParser.json({ limit: "1mb" }));

// Basic health
app.get("/diag", (req, res) => {
  res.json({
    ok: true,
    env: "railway",
    homeAgentBase: HOME_AGENT_BASE,
    time: new Date().toISOString(),
  });
});

// Proxy health -> home-agent
app.get("/diag/agent-health", async (req, res) => {
  try {
    const r = await axios.get(`${HOME_AGENT_BASE}/health`, { timeout: 3000 });
    res.status(200).json({ ok: true, agent: r.data });
  } catch (err) {
    res.status(502).json({
      ok: false,
      where: "agent-health",
      error: err?.message || String(err),
    });
  }
});

// ----- API your frontend calls -----

// Login with plain password -> forwards to home-agent
app.post("/api/auth/login-plain", async (req, res) => {
  // Expecting: { email, host, port, secure, password }
  const payload = req.body || {};
  const started = Date.now();

  try {
    const r = await axios.post(`${HOME_AGENT_BASE}/api/auth/login-plain`, payload, {
      timeout: 6000,               // keep well under Railway’s 8s idle limit
      headers: { "Content-Type": "application/json" },
      validateStatus: () => true,  // pass through agent status
    });

    res.status(r.status || 200).json(r.data);
  } catch (err) {
    res.status(502).json({
      ok: false,
      where: "backend->home-agent",
      route: "/api/auth/login-plain",
      ms: Date.now() - started,
      error: err?.message || String(err),
    });
  }
});

// 404 fallthrough
app.use((req, res) => {
  res.status(404).json({ ok: false, error: "Not found" });
});

// Start server
const PORT = process.env.PORT || 8080; // Railway provides PORT
app.listen(PORT, () => {
  console.log(JSON.stringify({
    level: 30,
    msg: "backend listening",
    port: PORT,
    homeAgentBase: HOME_AGENT_BASE
  }));
});
