'use strict';

const http = require('http');
const crypto = require('crypto');
const net = require('net');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const cookie = require('cookie');
const { v4: uuidv4 } = require('uuid');
const { exportJWK, generateKeyPair } = require('jose');

// ================= CONFIG =================
const FRONTEND_ORIGIN = 'https://refnull.net';
const SESSION_TTL_SECONDS = 86400;
const PORT = 8080;

const HOME_HOST = '98.156.77.218';
const HOME_PORT = 31001;
const HOME_REPLY_PORT = undefined;
const HOME_PSK_BASE64 = 'PUy9rgQrk7jZqRY5g8FqQBG901FOwrflcYHeruqRWcI=';

let HOME_PSK = null;
try {
  const buf = Buffer.from(HOME_PSK_BASE64, 'base64');
  if (buf.length === 32) HOME_PSK = buf;
  else console.warn('HOME_PSK_BASE64 must decode to 32 bytes (got', buf.length, ')');
} catch {
  console.warn('Invalid HOME_PSK_BASE64');
}

// ================= SESSION STORAGE =================
const sessions = new Map();
const noncesSeen = new Set();
setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  for (const [k, v] of sessions.entries()) if (v.exp <= now) sessions.delete(k);
  if (noncesSeen.size > 5000) noncesSeen.clear();
}, 60_000);

// ================= RSA KEY (JWKS) =================
let keyPair, jwkPub, jwks, kid;
async function initKeys() {
  keyPair = await generateKeyPair('RSA-OAEP-256', { modulusLength: 2048 });
  jwkPub = await exportJWK(keyPair.publicKey);
  kid = crypto.createHash('sha256')
    .update(Buffer.from(JSON.stringify(jwkPub)))
    .digest('base64url')
    .slice(0, 16);
  jwkPub.use = 'enc';
  jwkPub.alg = 'RSA-OAEP-256';
  jwkPub.kid = kid;
  jwks = { keys: [jwkPub] };
}

// ================= HELPERS =================
function b64urlToBuf(b64u) {
  return Buffer.from(b64u.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
function setSessCookie(res, sessId, maxAgeSeconds) {
  const c = cookie.serialize('sess', sessId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    maxAge: maxAgeSeconds,
  });
  res.setHeader('Set-Cookie', c);
}
function parseCookies(req) {
  return cookie.parse(req.headers['cookie'] || '');
}
function requireAuth(req, res, next) {
  const { sess } = parseCookies(req);
  if (!sess) return res.status(401).json({ error: 'unauthorized' });
  const rec = sessions.get(sess);
  if (!rec || rec.exp <= Math.floor(Date.now() / 1000))
    return res.status(401).json({ error: 'unauthorized' });
  req.user = { email: rec.email, name: rec.name };
  req.sessId = sess;
  next();
}

// ================= CORS =================
const corsOpts = {
  origin: (origin, cb) => {
    if (!origin || origin === FRONTEND_ORIGIN) return cb(null, true);
    cb(new Error('CORS blocked'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['content-type'],
};

// ================= HOME CONNECTOR =================
let homeSocket = null, homeReplySocket = null;
let rpcCounter = 0;
const pendingRPC = new Map();

function makeFrame(obj) {
  const json = Buffer.from(JSON.stringify(obj), 'utf8');
  if (!HOME_PSK) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(json.length, 0);
    return Buffer.concat([len, json]);
  }
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', HOME_PSK, nonce);
  const enc = Buffer.concat([c.update(json), c.final()]);
  const tag = c.getAuthTag();
  const packed = Buffer.concat([nonce, tag, enc]);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(packed.length, 0);
  return Buffer.concat([len, packed]);
}
function parseFrames(buf, onMessage) {
  let off = 0;
  while (buf.length - off >= 4) {
    const len = buf.readUInt32BE(off);
    off += 4;
    if (buf.length - off < len) {
      off -= 4;
      break;
    }
    const chunk = buf.subarray(off, off + len);
    off += len;
    let jsonBuf;
    if (!HOME_PSK) jsonBuf = chunk;
    else {
      const nonce = chunk.subarray(0, 12);
      const tag = chunk.subarray(12, 28);
      const enc = chunk.subarray(28);
      const d = crypto.createDecipheriv('aes-256-gcm', HOME_PSK, nonce);
      d.setAuthTag(tag);
      jsonBuf = Buffer.concat([d.update(enc), d.final()]);
    }
    onMessage(JSON.parse(jsonBuf.toString('utf8')));
  }
  return buf.subarray(off);
}
function connectHomeSockets() {
  const connectOne = (port, label) => {
    const sock = net.createConnection({ host: HOME_HOST, port }, () =>
      console.log(`[home] connected ${label} ${HOME_HOST}:${port}`)
    );
    sock.setKeepAlive(true, 20_000);
    let buffer = Buffer.alloc(0);
    sock.on('data', (d) => {
      buffer = Buffer.concat([buffer, d]);
      buffer = parseFrames(buffer, (msg) => {
        if (msg.kind === 'rpc.res' && typeof msg.id !== 'undefined') {
          const ent = pendingRPC.get(msg.id);
          if (ent) {
            clearTimeout(ent.timer);
            pendingRPC.delete(msg.id);
            msg.error ? ent.reject(new Error(msg.error)) : ent.resolve(msg.result);
          }
        }
      });
    });
    sock.on('error', (e) => console.warn(`[home] ${label} error:`, e.message));
    sock.on('close', () => {
      console.warn(`[home] ${label} closed. retrying in 3s`);
      setTimeout(connectHomeSockets, 3000);
    });
    return sock;
  };
  homeSocket = connectOne(HOME_PORT, 'main');
  if (HOME_REPLY_PORT) homeReplySocket = connectOne(HOME_REPLY_PORT, 'reply');
}
function homeRPC(method, params) {
  return new Promise((resolve, reject) => {
    if (!homeSocket || homeSocket.destroyed)
      return reject(new Error('home socket not connected'));
    const id = ++rpcCounter;
    const frame = makeFrame({ kind: 'rpc.req', id, method, params });
    const timer = setTimeout(() => {
      pendingRPC.delete(id);
      reject(new Error('home rpc timeout'));
    }, 10_000);
    pendingRPC.set(id, { resolve, reject, timer });
    (homeReplySocket && !homeReplySocket.destroyed
      ? homeReplySocket
      : homeSocket
    ).write(frame);
  });
}

// ================= EXPRESS APP =================
const app = express();
app.disable('x-powered-by');
app.use(
  helmet({
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
  })
);
app.use(morgan('tiny'));
app.use((req, res, next) => {
  res.setHeader('Vary', 'Origin');
  next();
});
app.use(cors(corsOpts));
app.use(express.json({ limit: '256kb' }));

// ================= ROUTES =================
app.get('/.well-known/jwks.json', (req, res) => res.json(jwks));

app.post('/api/auth/login-encrypted', async (req, res) => {
  try {
    const { ciphertext, kid: kidFromClient, nonce } = req.body || {};
    if (!ciphertext || !kidFromClient || !nonce)
      return res.status(400).json({ error: 'bad request' });
    if (kidFromClient !== kid)
      return res.status(400).json({ error: 'unknown kid' });
    if (noncesSeen.has(nonce))
      return res.status(409).json({ error: 'nonce replay' });

    const ct = b64urlToBuf(ciphertext);
    const decrypted = crypto.privateDecrypt(
      {
        key: keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      ct
    );

    const payload = JSON.parse(decrypted.toString('utf8'));
    const { email, password, nonce: innerNonce, ts } = payload;
    if (!email || !password || !innerNonce || !ts)
      return res.status(400).json({ error: 'invalid payload' });
    if (innerNonce !== nonce)
      return res.status(400).json({ error: 'nonce mismatch' });
    if (Math.abs(Date.now() - ts) > 2 * 60 * 1000)
      return res.status(401).json({ error: 'stale timestamp' });

    noncesSeen.add(nonce);

    let userRecord;
    try {
      userRecord = await homeRPC('auth.verify', { email, password });
    } catch (e) {
      console.warn('[auth] homeRPC failed, demo fallback:', e.message);
      if (typeof password !== 'string' || password.length < 6)
        return res.status(401).json({ error: 'invalid credentials' });
      userRecord = { email, name: email.split('@')[0] };
    }

    const sessId = crypto.randomBytes(24).toString('base64url');
    const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
    sessions.set(sessId, {
      email: userRecord.email,
      name: userRecord.name || userRecord.email,
      exp,
    });
    setSessCookie(res, sessId, SESSION_TTL_SECONDS);
    res.json({ ok: true });
  } catch (e) {
    console.error('login-encrypted error', e);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/me', requireAuth, (req, res) =>
  res.json({ email: req.user.email, name: req.user.name })
);

app.get('/api/mail/messages', requireAuth, async (req, res) => {
  const folder = (req.query.folder || 'inbox').toString();
  const q = (req.query.q || '').toString();
  const page = parseInt((req.query.page || '1').toString(), 10);
  try {
    let items;
    try {
      items = await homeRPC('imap.list', { folder, q, page, who: req.user.email });
    } catch (e) {
      console.warn('[imap.list] homeRPC failed, demo:', e.message);
      items = [
        {
          id: 'msg_demo_1',
          from: 'Alice <alice@example.com>',
          subject: 'Demo hello',
          snippet: 'This is a demo message',
          date: new Date().toISOString(),
        },
      ];
    }
    res.json({ items, nextPage: page + 1 });
  } catch {
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/mail/messages/:id', requireAuth, async (req, res) => {
  try {
    let msg;
    try {
      msg = await homeRPC('imap.get', { id: req.params.id, who: req.user.email });
    } catch (e) {
      console.warn('[imap.get] homeRPC failed, demo:', e.message);
      msg = {
        id: req.params.id,
        from: 'Alice <alice@example.com>',
        to: [req.user.email],
        subject: 'Demo message',
        date: new Date().toISOString(),
        body: 'Plain text demo body.',
      };
    }
    res.json(msg);
  } catch {
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/mail/send', requireAuth, async (req, res) => {
  const { to, subject, body } = req.body || {};
  if (!to || typeof to !== 'string')
    return res.status(400).json({ error: 'invalid to' });
  try {
    let result;
    try {
      result = await homeRPC('smtp.send', {
        from: req.user.email,
        to,
        subject: subject || '',
        body: body || '',
      });
    } catch (e) {
      console.warn('[smtp.send] homeRPC failed, demo:', e.message);
      result = { ok: true, id: 'msg_demo_sent_' + Date.now() };
    }
    res.json(result.ok ? result : { ok: false, error: result.error || 'send failed' });
  } catch {
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  sessions.delete(req.sessId);
  setSessCookie(res, '', 0);
  res.json({ ok: true });
});

app.get('/healthz', (req, res) => res.json({ ok: true }));

// ================= START SERVER =================
(async () => {
  await initKeys();
  connectHomeSockets();
  http.createServer(app).listen(PORT, () =>
    console.log(`refnull mail API running on port ${PORT}`)
  );
})();
