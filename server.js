/**
 * Emberline — Matchmaking Server
 * ─────────────────────────────
 * Install:  npm install ws express
 * Run:      node server.js
 *
 * Privacy & legal:
 *   - No IP addresses are logged or stored in permanent files
 *   - No message content is ever stored (E2EE relay only)
 *   - Reports are written to reports.log (reason + timestamp only)
 *   - Abuse events written to abuse.log (reason + timestamp only, for Fail2Ban)
 *   - Privacy policy served at /privacy
 */

'use strict';

const express = require('express');
const http    = require('http');
const WS      = require('ws');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');
const { execSync } = require('child_process');

const PORT = process.env.PORT || 3000;

const app    = express();
const server = http.createServer(app);

// ─────────────────────────────────────────────────────────────────────────────
// Constants — all tuneable limits in one place
// ─────────────────────────────────────────────────────────────────────────────

const MAX_CONNS_PER_IP        = 20;   // concurrent WS connections per IP
const MAX_WS_CONNECTS_PER_MIN = 20;  // new WS connections per IP per minute
                                      // (20 allows rapid Next → clicks without hitting the limit)
const MAX_HTTP_API_RPM        = 60;  // /challenge, /count, /report per IP per minute
const MAX_HTTP_STATIC_RPM     = 300; // static assets per IP per minute

const MAX_REPORTS_PER_IP      = 10;  // abuse reports per IP per hour
const MAX_CHALLENGES_PER_IP   = 60;  // challenge tokens per IP per hour
                                      // (60 allows Next → + fallback timer without throttling)
const MAX_KEYWORD_POOLS       = 11;   // keyword pools a single client can join (10 + __random__)
const CHALLENGE_TTL_MS        = 60_000;
const POW_DIFFICULTY          = 4;
const HEARTBEAT_INTERVAL_MS   = 60_000;  // 60s — halves ping overhead vs 30s while still
                                           // detecting zombie connections within a minute
const FLAGGED_IP_TTL_MS       = 24 * 60 * 60 * 1000;

// Hard memory ceilings — protect against flood even if rate limits are bypassed
const MAX_WAITING_POOL_KEYS   = 10_000;
const MAX_CHALLENGES_STORED   = 5_000;
const MAX_ROOMS               = 20_000;

const HONEYPOT_KEYWORD = '__honeypot__';
const MAX_RECENT_PARTNERS     = 20;   // per-connection cooldown to avoid re-matching the same pair

// Allowed WebSocket origins — set to your production domain(s).
// null/undefined origin (non-browser clients) is allowed so CLI tools still work.
const ALLOWED_WS_ORIGINS = new Set([
  `http://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`,
  'https://emberline.ch',
  'https://www.emberline.ch',
]);

// Base64 character class for NaCl public key validation (44 chars for 32-byte key)
const BASE64_RE = /^[A-Za-z0-9+/=]{1,64}$/;

// ─────────────────────────────────────────────────────────────────────────────
// In-memory state  (never written to disk)
// ─────────────────────────────────────────────────────────────────────────────

const waitingPool = new Map();  // keyword → Set<ws>
const rooms       = new Map();  // roomId  → { a: ws, b: ws }
const challenges  = new Map();  // token   → { prefix, expiresAt, ip }

// Per-IP rate tracking — values are ephemeral, never persisted
const ipConnections  = new Map();  // ip → count (concurrent)
const wsConnectRate  = new Map();  // ip → { count, resetAt }
const httpApiRate    = new Map();  // ip → { count, resetAt }
const httpStaticRate = new Map();  // ip → { count, resetAt }
const reportThrottle = new Map();  // ip → { count, resetAt }
const challengeRate  = new Map();  // ip → { count, resetAt }
const flaggedIPs     = new Map();  // ip → flaggedAt timestamp

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function getIP(req) {
  const fwd = req.headers['x-forwarded-for'];
  return (fwd ? fwd.split(',')[0] : req.socket?.remoteAddress || 'unknown').trim();
}

function send(ws, obj) {
  if (ws.readyState === WS.OPEN) ws.send(JSON.stringify(obj));
}

function randomId() {
  return crypto.randomBytes(8).toString('hex'); // 64-bit cryptographically random room ID
}

// Abuse log — for Fail2Ban pattern matching only. No content, no identity.
const ABUSE_LOG = path.join(__dirname, 'abuse.log');
function logAbuse(reason, ip) {
  const line = `${new Date().toISOString()} [${reason}] ip=${ip}\n`;
  fs.appendFile(ABUSE_LOG, line, err => {
    if (err) console.error('[abuse-log] write failed:', err.message);
  });
}

// Sliding-window rate limiter. Returns true if the IP is over the limit.
function rateExceeded(map, ip, maxPerWindow, windowMs) {
  const now = Date.now();
  const rec = map.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + windowMs; }
  rec.count++;
  map.set(ip, rec);
  return rec.count > maxPerWindow;
}

function isIPFlagged(ip) {
  const ts = flaggedIPs.get(ip);
  if (!ts) return false;
  if (Date.now() - ts > FLAGGED_IP_TTL_MS) { flaggedIPs.delete(ip); return false; }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Periodic sweep — evict expired entries, keep all maps bounded
// ─────────────────────────────────────────────────────────────────────────────

setInterval(() => {
  const now    = Date.now();
  const cutoff = now - FLAGGED_IP_TTL_MS;
  for (const [k, v] of flaggedIPs)     { if (v < cutoff)        flaggedIPs.delete(k); }
  for (const [k, v] of wsConnectRate)  { if (now > v.resetAt)   wsConnectRate.delete(k); }
  for (const [k, v] of httpApiRate)    { if (now > v.resetAt)   httpApiRate.delete(k); }
  for (const [k, v] of httpStaticRate) { if (now > v.resetAt)   httpStaticRate.delete(k); }
  for (const [k, v] of reportThrottle) { if (now > v.resetAt)   reportThrottle.delete(k); }
  for (const [k, v] of challengeRate)  { if (now > v.resetAt)   challengeRate.delete(k); }
}, 60 * 60 * 1000); // hourly

// Challenge tokens expire after 60s but the hourly sweep let stale entries
// accumulate (~36k at 10 challenges/sec). This dedicated timer keeps the map
// tight without waiting for the hourly pass or relying on per-request sweeps.
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of challenges) { if (now > v.expiresAt) challenges.delete(k); }
}, 60_000); // every 60s — matches CHALLENGE_TTL_MS

// ─────────────────────────────────────────────────────────────────────────────
// HTTP middleware — security headers + split-budget rate limiting
// All middleware must be declared AFTER the helpers above.
// ─────────────────────────────────────────────────────────────────────────────

app.disable('x-powered-by');

// Built once — these headers never change per request.
const CSP_HEADER =
  "default-src 'none'; " +
  "script-src 'self'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "font-src 'self'; " +
  "img-src 'self'; " +
  "connect-src 'self' ws: wss:; " +
  "manifest-src 'self'; " +
  "worker-src 'self'; " +
  "frame-ancestors 'none'";

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', CSP_HEADER);
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// Static assets get a generous separate budget so font/JS loads don't eat
// into the API budget used for /challenge and /count.
const STATIC_EXT = new Set(['.js', '.css', '.woff2', '.woff', '.ttf', '.ico', '.png', '.svg', '.json']);

app.use((req, res, next) => {
  const ip       = getIP(req);
  const isStatic = STATIC_EXT.has(path.extname(req.path).toLowerCase());
  if (isStatic) {
    if (rateExceeded(httpStaticRate, ip, MAX_HTTP_STATIC_RPM, 60_000)) {
      return res.status(429).json({ error: 'too many requests' });
    }
  } else {
    if (rateExceeded(httpApiRate, ip, MAX_HTTP_API_RPM, 60_000)) {
      logAbuse('http_flood', ip);
      return res.status(429).json({ error: 'too many requests' });
    }
  }
  next();
});

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket server
// ─────────────────────────────────────────────────────────────────────────────

const wss = new WS.Server({
  server,
  maxPayload: 4096, // 4 KB hard ceiling at library level
  verifyClient: ({ origin, req }) => {
    // Non-browser clients (curl, etc.) send no origin — allow them through
    // so health checks and CLI tools work. Browsers always send an origin.
    if (!origin) return true;
    if (ALLOWED_WS_ORIGINS.has(origin)) return true;
    const ip = getIP(req);
    logAbuse('ws_origin', ip);
    return false;
  }
});

wss.on('connection', (ws, req) => {
  const ip  = getIP(req);
  const now = Date.now();

  // ── Rate: new connections per minute ─────────────────────────────────────
  if (rateExceeded(wsConnectRate, ip, MAX_WS_CONNECTS_PER_MIN, 60_000)) {
    logAbuse('ws_rate', ip);
    ws.close(1008, 'Too many connections');
    return;
  }

  // ── Cap: concurrent connections per IP ───────────────────────────────────
  const currentConns = ipConnections.get(ip) || 0;
  if (currentConns >= MAX_CONNS_PER_IP) {
    logAbuse('conn_cap', ip);
    ws.close(4429, 'Too many connections from your IP');
    return;
  }

  // ── Honeypot: flagged IPs ─────────────────────────────────────────────────
  if (isIPFlagged(ip)) {
    logAbuse('flagged_ip', ip);
    ws.close(1008, 'Blocked');
    return;
  }

  ipConnections.set(ip, currentConns + 1);

  ws.isAlive         = true;
  ws._ip             = ip;
  ws.keywords        = null;
  ws.roomId          = null;
  ws.lastMsg         = 0;
  ws._leaving        = false;
  ws._connectedAt    = now;
  ws._verified       = false;
  ws._recentPartners = new Set();  // avoid re-matching the same pair on Next →
  ws._joinedPoolAt   = 0;          // set when entering the waiting pool

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', raw => {
    if (raw.length > 4096) return; // belt-and-suspenders after maxPayload
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;

    switch (msg.type) {

      case 'join': {

        // ── Proof-of-work verification ───────────────────────────────────
        // PoW is the primary bot defence. A timing check is redundant —
        // any client that solved SHA-256 with difficulty 4 has already
        // spent ~50-200ms of real CPU time proving it is not a trivial bot.
        if (!ws._verified) {
          const { token, nonce } = msg;
          const challenge = token && challenges.get(token);
          if (!challenge || Date.now() > challenge.expiresAt) {
            send(ws, { type: 'error', code: 'challenge_expired' });
            return;
          }
          // Reject if the challenge was issued to a different IP
          if (challenge.ip !== ws._ip) {
            logAbuse('pow_ip_mismatch', ws._ip);
            ws.close(1008, 'Invalid challenge');
            return;
          }
          const hashBuf = crypto.createHash('sha256')
            .update(challenge.prefix + String(nonce))
            .digest();
          const fullBytes = POW_DIFFICULTY >> 1;
          const halfByte  = POW_DIFFICULTY & 1;
          let powOk = true;
          for (let i = 0; i < fullBytes; i++) {
            if (hashBuf[i] !== 0) { powOk = false; break; }
          }
          if (powOk && halfByte && (hashBuf[fullBytes] >> 4) !== 0) powOk = false;
          if (!powOk) {
            logAbuse('pow_fail', ws._ip);
            ws.close(1008, 'Invalid challenge');
            return;
          }
          challenges.delete(token);
          ws._verified = true;
        }

        // ── Sanitise keywords ────────────────────────────────────────────
        const keywords = (Array.isArray(msg.keywords) ? msg.keywords : [])
          .map(k => (typeof k === 'string' ? k : '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20))
          .filter(Boolean)
          .slice(0, MAX_KEYWORD_POOLS);

        if (keywords.length === 0) return;

        // ── Honeypot keyword ─────────────────────────────────────────────
        if (keywords.includes(HONEYPOT_KEYWORD)) {
          logAbuse('honeypot', ws._ip);
          flaggedIPs.set(ws._ip, Date.now());
          ws.close(1008, 'Blocked');
          return;
        }

        // ── Memory ceiling ───────────────────────────────────────────────
        if (waitingPool.size >= MAX_WAITING_POOL_KEYS || rooms.size >= MAX_ROOMS) {
          send(ws, { type: 'error', code: 'server_busy' });
          return;
        }

        // ── Clean up any previous pool membership (critical for Next →) ──
        // Without this, the ws stays in the old pool from the previous
        // session and either matches with itself or blocks future matches.
        if (ws.keywords) {
          ws.keywords.forEach(kw => {
            const p = waitingPool.get(kw);
            if (p) { p.delete(ws); if (p.size === 0) waitingPool.delete(kw); }
          });
          ws.keywords = null;
        }

        ws.pubKey = (typeof msg.pubKey === 'string' && BASE64_RE.test(msg.pubKey))
          ? msg.pubKey.slice(0, 64)
          : null;

        // Reset _leaving so handleLeave works correctly on this reused connection.
        // nextConversation() sends leave then join on the same socket — handleLeave
        // sets _leaving=true and decrements ipConnections. We restore both here.
        if (ws._leaving) {
          ws._leaving = false;
          const n = ipConnections.get(ws._ip) || 0;
          ipConnections.set(ws._ip, n + 1);
        }

        // ── Matching algorithm ───────────────────────────────────────────
        // Scan ALL keyword pools and score every candidate by how many
        // keywords they share with this client. Among the highest-overlap
        // candidates, pick the one who has been waiting the longest.
        // Recent partners (from Next →) are excluded to avoid re-matching.

        const candidateScores = new Map(); // other_ws → { count, keywords[] }

        for (const keyword of keywords) {
          const pool = waitingPool.get(keyword);
          if (!pool) continue;

          // Prune disconnected entries on the fly
          for (const other of pool) {
            if (other.readyState !== WS.OPEN) pool.delete(other);
          }

          for (const other of pool) {
            if (other === ws) continue;
            if (ws._recentPartners.has(other)) continue;
            let score = candidateScores.get(other);
            if (!score) { score = { count: 0, keywords: [] }; candidateScores.set(other, score); }
            score.count++;
            score.keywords.push(keyword);
          }
        }

        let matched = false;

        if (candidateScores.size > 0) {
          // Find the maximum overlap count
          let maxCount = 0;
          for (const [, score] of candidateScores) {
            if (score.count > maxCount) maxCount = score.count;
          }

          // Among max-overlap candidates, pick the one waiting longest (fairness)
          let partner     = null;
          let partnerInfo = null;
          let oldestJoin  = Infinity;

          for (const [candidate, score] of candidateScores) {
            if (score.count !== maxCount) continue;
            const joinTime = candidate._joinedPoolAt || 0;
            if (joinTime < oldestJoin) {
              oldestJoin  = joinTime;
              partner     = candidate;
              partnerInfo = score;
            }
          }

          if (partner) {
            // Remove partner from ALL its pools atomically before notifying
            if (partner.keywords) {
              partner.keywords.forEach(kw => {
                const p = waitingPool.get(kw);
                if (p) { p.delete(partner); if (p.size === 0) waitingPool.delete(kw); }
              });
              partner.keywords = null;
            }

            const roomId = randomId();
            rooms.set(roomId, { a: partner, b: ws });
            partner.roomId = roomId;
            ws.roomId      = roomId;
            ws.keywords    = null;

            // Record each other as recent partners so Next → doesn't re-match them
            ws._recentPartners.add(partner);
            partner._recentPartners.add(ws);
            // Cap the sets to avoid unbounded growth over many Next → cycles
            if (ws._recentPartners.size > MAX_RECENT_PARTNERS) {
              const first = ws._recentPartners.values().next().value;
              ws._recentPartners.delete(first);
            }
            if (partner._recentPartners.size > MAX_RECENT_PARTNERS) {
              const first = partner._recentPartners.values().next().value;
              partner._recentPartners.delete(first);
            }

            // Send all matched keywords (filter out __random__ for display)
            const matchedKeywords = partnerInfo.keywords.filter(k => k !== '__random__');

            send(partner, { type: 'matched', matchedKeywords, partnerPubKey: ws.pubKey });
            send(ws,      { type: 'matched', matchedKeywords, partnerPubKey: partner.pubKey });

            console.log(`[match] overlap=${partnerInfo.count} room=${roomId} rooms=${rooms.size}`);
            matched = true;
          }
        }

        if (!matched) {
          ws.keywords      = keywords;
          ws._joinedPoolAt = Date.now();
          keywords.forEach(kw => {
            const pool = waitingPool.get(kw) || new Set();
            pool.add(ws);
            waitingPool.set(kw, pool);
          });
          send(ws, { type: 'waiting', keywords });
          console.log(`[wait] pool_keys=${waitingPool.size}`);
        }
        break;
      }

      case 'message': {
        if (!ws.roomId) return;
        const now = Date.now();
        if (now - ws.lastMsg < 300) return; // 300ms per-client send rate limit
        ws.lastMsg = now;
        const room = rooms.get(ws.roomId);
        if (!room) return;
        const other = room.a === ws ? room.b : room.a;
        // Only relay E2EE frames — plaintext relay intentionally absent
        if (typeof msg.ciphertext === 'string' && typeof msg.nonce === 'string') {
          const ct = msg.ciphertext.slice(0, 800);
          const nn = msg.nonce.slice(0, 50);
          if (ct && nn) send(other, { type: 'message', ciphertext: ct, nonce: nn });
        }
        break;
      }

      case 'typing': {
        if (!ws.roomId) return;
        const room = rooms.get(ws.roomId);
        if (!room) return;
        const other = room.a === ws ? room.b : room.a;
        send(other, { type: 'typing' });
        break;
      }

      case 'leave': {
        handleLeave(ws);
        break;
      }

      // Unknown types are silently ignored
    }
  });

  ws.on('close', () => handleLeave(ws));
  ws.on('error', () => handleLeave(ws));
});

// ─────────────────────────────────────────────────────────────────────────────
// Cleanup on leave / close / error
// ─────────────────────────────────────────────────────────────────────────────

function handleLeave(ws) {
  if (ws._leaving) return;
  ws._leaving = true;

  // Decrement concurrent connection count
  if (ws._ip) {
    const n = (ipConnections.get(ws._ip) || 1) - 1;
    if (n <= 0) ipConnections.delete(ws._ip);
    else        ipConnections.set(ws._ip, n);
  }

  // Remove from any waiting pool
  if (ws.keywords) {
    ws.keywords.forEach(kw => {
      const pool = waitingPool.get(kw);
      if (pool) { pool.delete(ws); if (pool.size === 0) waitingPool.delete(kw); }
    });
    ws.keywords = null;
  }

  // Notify partner and clean room
  if (ws.roomId) {
    const room = rooms.get(ws.roomId);
    if (room) {
      const other = room.a === ws ? room.b : room.a;
      send(other, { type: 'partner_left' });
    }
    rooms.delete(ws.roomId);
    ws.roomId = null;
    console.log(`[leave] room cleaned  rooms=${rooms.size}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Heartbeat — terminate zombie connections every 60s
// ─────────────────────────────────────────────────────────────────────────────

const heartbeat = setInterval(() => {
  let zombies = 0;
  wss.clients.forEach(ws => {
    if (!ws.isAlive) { zombies++; handleLeave(ws); ws.terminate(); return; }
    ws.isAlive = false;
    ws.ping();
  });
  if (zombies > 0) console.log(`[heartbeat] terminated ${zombies} zombie(s)`);
}, HEARTBEAT_INTERVAL_MS);

wss.on('close', () => clearInterval(heartbeat));

// ─────────────────────────────────────────────────────────────────────────────
// REST: /challenge
// ─────────────────────────────────────────────────────────────────────────────

app.get('/challenge', (req, res) => {
  const ip = getIP(req);
  if (rateExceeded(challengeRate, ip, MAX_CHALLENGES_PER_IP, 3_600_000)) {
    return res.status(429).json({ error: 'too many requests' });
  }

  // Ceiling check only — expired tokens are swept by the dedicated 60s interval
  if (challenges.size >= MAX_CHALLENGES_STORED) {
    return res.status(503).json({ error: 'server busy, try again shortly' });
  }

  const token     = crypto.randomBytes(16).toString('hex');
  const prefix    = crypto.randomBytes(8).toString('hex');
  const expiresAt = Date.now() + CHALLENGE_TTL_MS;
  challenges.set(token, { prefix, expiresAt, ip });

  res.json({ token, prefix, difficulty: POW_DIFFICULTY });
});

// ─────────────────────────────────────────────────────────────────────────────
// REST: /count
// ─────────────────────────────────────────────────────────────────────────────

app.get('/count', (req, res) => {
  res.json({ count: wss.clients.size });
});

// ─────────────────────────────────────────────────────────────────────────────
// REST: /report
// ─────────────────────────────────────────────────────────────────────────────

app.use(express.json({ limit: '1kb' }));

const VALID_REASONS = new Set(['csam', 'harassment', 'illegal', 'spam']);

app.post('/report', (req, res) => {
  const ip = getIP(req);
  if (rateExceeded(reportThrottle, ip, MAX_REPORTS_PER_IP, 3_600_000)) {
    return res.status(429).json({ error: 'too many reports, please try again later' });
  }

  const { reason, details } = req.body || {};
  if (!reason || !VALID_REASONS.has(reason)) {
    return res.status(400).json({ error: 'invalid reason' });
  }

  const cleanDetails = typeof details === 'string'
    ? details.replace(/[<>]/g, '').trim().slice(0, 500)
    : '';

  const entry = JSON.stringify({
    ts:      new Date().toISOString(),
    reason:  reason.slice(0, 20),
    details: cleanDetails
    // deliberately: no IP, no room ID, no user identity
  }) + '\n';

  fs.appendFile(path.join(__dirname, 'reports.log'), entry, err => {
    if (err) console.error('[report] failed to write log:', err.message);
  });

  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// REST: /privacy
// ─────────────────────────────────────────────────────────────────────────────

// Effective dates — update manually when the corresponding policy changes.
// Hardcoding avoids the bug where `new Date()` made the "effective date"
// slide forward every time someone loaded the page.
const POLICY_EFFECTIVE_DATE = '17 April 2026';
const TERMS_EFFECTIVE_DATE  = '17 April 2026';

app.get('/privacy', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privacy Policy — Emberline</title>
<link href="/fonts/fonts.css" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', sans-serif; background: #1c1713; color: #e8ddd0; max-width: 680px; margin: 0 auto; padding: 3rem 1.5rem; line-height: 1.7; }
  h1 { font-family: 'Unbounded', sans-serif; font-size: 2rem; margin-bottom: 0.4rem; }
  h2 { font-family: 'Unbounded', sans-serif; font-size: 1.2rem; margin: 2rem 0 0.5rem; }
  p { color: #a89070; margin-bottom: 1rem; } a { color: #c87941; }
  .date { font-size: 0.85rem; color: #5a4e44; margin-bottom: 2rem; }
  hr { border: none; border-top: 1px solid #2e2620; margin: 2rem 0; }
</style>
</head>
<body>
<h1>Privacy Policy</h1>
<p class="date">Effective date: ${POLICY_EFFECTIVE_DATE} &nbsp;·&nbsp; Jurisdiction: Switzerland</p>
<p>Emberline is an anonymous, ephemeral chat platform. This policy describes what data we collect, what we do not collect, and your rights under Swiss law (nFADP).</p>
<h2>What we do not collect</h2>
<p>We do not collect names, email addresses, phone numbers, or any other identifying information. We do not require registration. We do not store chat messages — messages are relayed in real time using end-to-end encryption and are never written to disk. We have no ability to retrieve or reconstruct past conversations.</p>
<h2>What we do collect</h2>
<p>When a user submits an abuse report, we record the report timestamp and reason category only. No message content, IP address, or user identity is included. This information is retained for a maximum of 90 days.</p>
<h2>IP addresses</h2>
<p>We do not log IP addresses in association with chat content, reports, keywords, or any durable user record. An IP-based abuse defense runs at the connection layer: when a client trips a rate limit, fails a proof-of-work check, or hits a honeypot, an entry is written to an abuse log containing only a timestamp, the triggered rule, and the source IP. This log feeds a ban system that temporarily blocks repeat offenders and is rotated after 90 days. It is never cross-referenced against reports, conversations, or keywords — and cannot be, because none of those are stored. This is the minimum defense a fully anonymous service requires to remain functional.</p>
<h2>End-to-end encryption</h2>
<p>All messages are encrypted on your device using the NaCl box construction (Curve25519 + XSalsa20 + Poly1305). Only the two participants can decrypt messages. The server relays encrypted data it cannot read.</p>
<h2>Keywords</h2>
<p>Keywords are held temporarily in server memory during matching and discarded immediately after a match is made or the session ends.</p>
<h2>Cookies, tracking, and storage</h2>
<p>We use no cookies, no analytics, no tracking pixels, and no third-party services. We do not use localStorage, sessionStorage, or any other form of persistent client-side storage. All fonts and cryptography libraries are self-hosted — no external requests are made by your browser.</p>
<h2>Illegal content</h2>
<p>Use of Emberline to share, solicit, or facilitate illegal content — including CSAM, harassment, or content illegal under Swiss law — is strictly prohibited. We cooperate with Swiss law enforcement under the Swiss Criminal Code.</p>
<h2>Your rights under nFADP</h2>
<p>You have the right to request access to any personal data we hold about you and to request its deletion. Because we store no user identities, no messages, and no session history, there is typically nothing to disclose or delete. The one category of data that could constitute personal data under nFADP is the IP entries in the abuse log described above; these can be removed on request if you provide the IP and an approximate time window. Contact: <a href="mailto:contactall@emberline.ch">contactall@emberline.ch</a>.</p>
<h2>Changes</h2>
<p>We may update this policy as the platform evolves. The effective date above reflects the most recent revision.</p>
<hr><p style="font-size:0.85rem;"><a href="/">← Back to Emberline</a></p>
</body></html>`);
});

// ─────────────────────────────────────────────────────────────────────────────
// REST: /terms
// ─────────────────────────────────────────────────────────────────────────────

app.get('/terms', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terms of Service — Emberline</title>
<link href="/fonts/fonts.css" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', sans-serif; background: #1c1713; color: #e8ddd0; max-width: 680px; margin: 0 auto; padding: 3rem 1.5rem; line-height: 1.7; }
  h1 { font-family: 'Unbounded', sans-serif; font-size: 2rem; margin-bottom: 0.4rem; }
  h2 { font-family: 'Unbounded', sans-serif; font-size: 1.2rem; margin: 2rem 0 0.5rem; color: #e8ddd0; }
  p { color: #a89070; margin-bottom: 1rem; } ul { color: #a89070; padding-left: 1.5rem; margin-bottom: 1rem; }
  li { margin-bottom: 0.4rem; } a { color: #c87941; }
  .date { font-size: 0.85rem; color: #5a4e44; margin-bottom: 2rem; }
  .notice { border-left: 2px solid #c87941; padding-left: 1rem; margin: 1.5rem 0; }
  .notice p { color: #c4a882; }
  hr { border: none; border-top: 1px solid #2e2620; margin: 2rem 0; }
</style>
</head>
<body>
<h1>Terms of Service</h1>
<p class="date">Effective date: ${TERMS_EFFECTIVE_DATE} &nbsp;·&nbsp; Jurisdiction: Switzerland &nbsp;·&nbsp; Governing law: Swiss Code of Obligations (OR)</p>
<div class="notice"><p>By using Emberline, you agree to these terms. If you do not agree, please do not use the platform.</p></div>
<h2>1. What Emberline is</h2>
<p>Emberline is an anonymous, ephemeral chat service connecting strangers on shared keywords. No accounts required. No messages stored. Conversations are end-to-end encrypted.</p>
<h2>2. Eligibility</h2>
<p>You must be at least 18 years old to use Emberline. By using the platform you confirm this.</p>
<h2>3. Prohibited conduct</h2>
<p>You agree not to transmit, solicit, share, or facilitate:</p>
<ul>
  <li>Child sexual abuse material (CSAM) or any content sexualising minors</li>
  <li>Threats of violence, harassment, stalking, or intimidation</li>
  <li>Content illegal under Swiss law or your country of residence</li>
  <li>Coordinated manipulation, deception, or fraud</li>
  <li>Automated access (bots, scrapers, scripts)</li>
  <li>Attempts to circumvent security or encryption mechanisms</li>
</ul>
<h2>4. CSAM — zero tolerance</h2>
<p>Any user who transmits, solicits, or facilitates CSAM will be reported to KOBIK immediately. Report directly at <a href="https://www.kobik.ch" target="_blank" rel="noopener noreferrer">www.kobik.ch</a>.</p>
<h2>5. Anonymity and its limits</h2>
<p>Emberline is designed to be anonymous. We require no accounts, store no messages, and retain no user identifiers. An IP-based abuse defense log is maintained for bot prevention only — see the Privacy Policy for full details. Anonymity at the technical layer does not exempt users from legal responsibility under Swiss law.</p>
<h2>6. No warranty</h2>
<p>Emberline is provided as-is without warranty of any kind. Use is at your own risk.</p>
<h2>7. Governing law</h2>
<p>These terms are governed exclusively by Swiss law. Disputes are subject to the exclusive jurisdiction of Swiss courts.</p>
<h2>8. Contact</h2>
<p>Legal notices and law enforcement requests: <a href="mailto:contactall@emberline.ch">contactall@emberline.ch</a>.</p>
<hr>
<p style="font-size:0.85rem;color:#5a4e44;"><a href="/privacy">Privacy policy</a> &nbsp;·&nbsp; <a href="/">Back to Emberline</a></p>
</body></html>`);
});

// ─────────────────────────────────────────────────────────────────────────────
// Build version — commit hash footer
// ─────────────────────────────────────────────────────────────────────────────
// Resolves which source version is currently running so the client can show
// a commit hash footer linked to the GitHub tree. Three fallbacks:
//   1. BUILD_VERSION file written by the pre-deploy script (production path)
//   2. git rev-parse HEAD if a .git directory exists (local dev path)
//   3. the literal string "dev" (self-hosted zip downloads, CI sandboxes)
// In the "dev" case the footer renders without the hash — there is no
// specific commit to verify against, so showing "build dev" would be noise.

const BUILD_VERSION = (() => {
  const buildFile = path.join(__dirname, 'BUILD_VERSION');
  try {
    const v = fs.readFileSync(buildFile, 'utf8').trim();
    if (v && /^[0-9a-f]{7,40}$/.test(v)) return v;
  } catch {} // file missing — try git

  try {
    const v = execSync('git rev-parse HEAD', {
      cwd: __dirname,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2000,
    }).toString().trim();
    if (/^[0-9a-f]{40}$/.test(v)) return v;
  } catch {} // not a git repo, or git not installed

  return 'dev';
})();

const BUILD_VERSION_SHORT = BUILD_VERSION === 'dev' ? 'dev' : BUILD_VERSION.slice(0, 7);

// Footer HTML fragment: either a linked short-hash or empty (hidden with its separator).
// Kept as a pre-rendered fragment so index.html stays clean — one placeholder, one replace.
const GITHUB_REPO_URL    = 'https://github.com/ProjectEmberline/emberline';
const BUILD_FOOTER_FRAGMENT = BUILD_VERSION === 'dev'
  ? ''
  : `<a href="${GITHUB_REPO_URL}/tree/${BUILD_VERSION}" target="_blank" rel="noopener noreferrer">build ${BUILD_VERSION_SHORT}</a> &nbsp;·&nbsp; `;

// Index template — inject placeholder at startup.
// This route MUST come before express.static so the static handler doesn't
// serve the raw template with unreplaced placeholders.
const INDEX_SOURCE = (() => {
  try {
    return fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8')
      .replace(/__BUILD_FOOTER__/g, BUILD_FOOTER_FRAGMENT);
  } catch (err) {
    console.error('[index] failed to read index.html template:', err.message);
    return '<!doctype html><title>Emberline</title><p>Server misconfigured.</p>';
  }
})();

app.get('/', (req, res) => {
  res.type('text/html; charset=utf-8');
  res.send(INDEX_SOURCE);
});
app.get('/index.html', (req, res) => {
  res.type('text/html; charset=utf-8');
  res.send(INDEX_SOURCE);
});

// ─────────────────────────────────────────────────────────────────────────────
// REST: /sw.js  —  content-hashed cache versioning
// ─────────────────────────────────────────────────────────────────────────────
// The service worker needs a CACHE_NAME that changes when — and only when —
// cached files actually change. Hard-coding a version string means a future
// contributor forgets to bump it and users get stale assets silently.
//
// Instead: enumerate shell files at startup, compute a short SHA-256 prefix
// over their contents, and inject both the hash and the shell list into
// sw.js at request time. Adding a new font file needs zero code edits.
//
// This route MUST be declared before `express.static` — otherwise the
// static handler serves the raw template (with unreplaced placeholders)
// and the service worker breaks.

const SHELL_STATIC = [
  '/',
  '/app.js',
  '/manifest.json',
  '/fonts/fonts.css',
  '/vendor/nacl-fast.min.js',
  '/vendor/nacl-util.min.js',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
];

function buildShellList() {
  const files = [...SHELL_STATIC];
  // Enumerate woff2 files dynamically — Google Fonts generates hashed names
  try {
    const fontsDir = path.join(__dirname, 'fonts');
    for (const f of fs.readdirSync(fontsDir)) {
      if (f.endsWith('.woff2')) files.push('/fonts/' + f);
    }
  } catch {} // fonts/ may not exist in fresh dev environments

  // Filter to files that exist on disk, so cache.addAll() doesn't fail install
  return files.filter(url => {
    const rel = url === '/' ? 'index.html' : url.replace(/^\//, '');
    try { fs.accessSync(path.join(__dirname, rel)); return true; }
    catch { return false; }
  });
}

const SHELL_LIST = buildShellList();

const CACHE_VERSION = (() => {
  const h = crypto.createHash('sha256');
  for (const url of SHELL_LIST) {
    const rel = url === '/' ? 'index.html' : url.replace(/^\//, '');
    try { h.update(fs.readFileSync(path.join(__dirname, rel))); } catch {}
  }
  return h.digest('hex').slice(0, 8);
})();

const SW_SOURCE = (() => {
  try {
    return fs.readFileSync(path.join(__dirname, 'sw.js'), 'utf8')
      .replace('__CACHE_VERSION__', CACHE_VERSION)
      .replace('__SHELL_LIST__', JSON.stringify(SHELL_LIST));
  } catch (err) {
    console.error('[sw] failed to read sw.js template:', err.message);
    return '// sw.js template missing';
  }
})();

app.get('/sw.js', (req, res) => {
  res.type('application/javascript');
  // Always revalidate — this is how new cache versions reach clients
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.send(SW_SOURCE);
});

// ─────────────────────────────────────────────────────────────────────────────
// Static files
// ─────────────────────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.js'))   res.setHeader('Content-Type', 'application/javascript');
    if (filePath.endsWith('.css'))  res.setHeader('Content-Type', 'text/css');
    if (filePath.endsWith('.html')) res.setHeader('Content-Type', 'text/html');
  }
}));

// ─────────────────────────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`Emberline listening on http://localhost:${PORT}`);
  console.log(`Reports → ${path.join(__dirname, 'reports.log')}`);
  console.log(`Abuse   → ${path.join(__dirname, 'abuse.log')}`);
  console.log(`SW      → cache=${CACHE_VERSION} files=${SHELL_LIST.length}`);
  console.log(`BUILD   → ${BUILD_VERSION_SHORT}${BUILD_VERSION === 'dev' ? '' : ` (${BUILD_VERSION})`}`);
});
