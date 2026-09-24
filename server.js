/**
 * Emberline — Matchmaking Server
 * ─────────────────────────────
 * Install:  npm install ws express
 * Run:      node server.js
 *
 * Privacy & legal:
 *   - IP addresses are written only to abuse.log (timestamp + rule + IP), never
 *     alongside chats, keywords or reports
 *   - No message content is ever stored (E2EE relay only)
 *   - Reports are written to reports.log (reason + timestamp + optional details)
 *   - Privacy policy served at /privacy
 *
 * Environment:
 *   PORT         listen port (default 3000)
 *   LOG_DIR      directory for abuse.log / reports.log (default: project root).
 *                Must never be inside PUBLIC_DIR.
 *   TRUST_PROXY  number of reverse proxies in front of this process
 *                (default 1). Used to pick the real client IP out of
 *                X-Forwarded-For. Set to 0 if clients connect directly.
 *   BAN_ALLOWLIST  comma-separated IPs that are never auto-banned
 *   MAX_CONNS_PER_IP  concurrent WebSocket connections per IP (default 20)
 *   BOT_TOKEN    shared secret for the operator's AI chat bots (bots/ember-bot.js).
 *                Unset = AI chat disabled. Never commit it.
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

// Only this directory is ever served over HTTP. Everything else in the project
// root (server source, node_modules, .git, logs, BUILD_VERSION) stays private.
const PUBLIC_DIR = path.join(__dirname, 'public');

// Logs are written outside PUBLIC_DIR so they can never be fetched by URL.
const LOG_DIR = path.resolve(process.env.LOG_DIR || __dirname);
if (LOG_DIR === PUBLIC_DIR || LOG_DIR.startsWith(PUBLIC_DIR + path.sep)) {
  console.error('[config] LOG_DIR must not be inside the public directory');
  process.exit(1);
}

// Number of trusted reverse-proxy hops. Each proxy appends the address it
// received the request from to X-Forwarded-For, so the real client IP is the
// entry TRUST_PROXY positions from the right (counting the socket address).
// Anything further left was supplied by the client and cannot be trusted.
const TRUST_PROXY = envInt('TRUST_PROXY', 1);

// Non-negative integer from the environment, or the default if unset/invalid.
function envInt(name, fallback) {
  const n = parseInt(process.env[name] ?? '', 10);
  return Number.isInteger(n) && n >= 0 ? n : fallback;
}

const app    = express();
const server = http.createServer(app);

// ─────────────────────────────────────────────────────────────────────────────
// Constants — all tuneable limits in one place
// ─────────────────────────────────────────────────────────────────────────────

const MAX_CONNS_PER_IP        = envInt('MAX_CONNS_PER_IP', 20); // concurrent WS connections per IP
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

// Automatic bans. Every abuse event (the same events written to abuse.log)
// is a strike against the client IP. Too many strikes in the window, or a
// single honeypot hit, bans the IP in memory: HTTP gets 403, WebSocket
// upgrades are refused. This works regardless of network topology — unlike a
// firewall on the app host, which only sees the tunnel/proxy address.
// Hitting a rate limit is something a busy shared IP (school, office, VPN
// exit) does in normal use, so it counts as at most one strike per IP per
// minute and can never reach STRIKE_LIMIT on its own.
const STRIKE_LIMIT            = 20;              // abuse events per window…
const STRIKE_WINDOW_MS        = 10 * 60 * 1000;  // …within 10 minutes
const BAN_DURATION_MS         = 24 * 60 * 60 * 1000;
const BAN_ALLOWLIST           = new Set(
  (process.env.BAN_ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean)
);

// Hard memory ceilings — protect against flood even if rate limits are bypassed
const MAX_WAITING_POOL_KEYS   = 10_000;
const MAX_CHALLENGES_STORED   = 5_000;
const MAX_ROOMS               = 20_000;

// Chat message relay. Token bucket per connection: bursts of MSG_BURST are
// fine (network jitter can bunch frames together), sustained rate is one
// message per MSG_REFILL_MS.
const MSG_BURST               = 5;
const MSG_REFILL_MS           = 300;

// Every frame a person's socket sends, of any type. A real client stays far
// below this (paced messages + a typing ping every 2s); going over it closes
// the socket and counts as a strike.
const FRAME_BURST             = 30;
const FRAME_REFILL_MS         = 100;
// Joins (incl. join_ai). Each one can match with someone, so this caps how fast
// a client can cycle through the people waiting. A proof-of-work is only needed
// once per socket, so it can't do that job. Over the limit the client is asked
// to retry later (no strike).
const JOIN_BURST              = 5;
const JOIN_REFILL_MS          = 3_000;
const MAX_JOINS_PER_IP_PER_MIN = 120;  // across all sockets of one IP
// Must match maxlength on #chat-input. A JS string of N UTF-16 units encodes
// to at most 3N UTF-8 bytes; NaCl box adds a 16-byte tag; base64 is 4/3.
const MAX_MESSAGE_CHARS       = 300;
const MAX_CIPHERTEXT_B64      = Math.ceil((MAX_MESSAGE_CHARS * 3 + 16) / 3) * 4; // 1224
const CIPHERTEXT_RE           = /^[A-Za-z0-9+/]+={0,2}$/;
const NONCE_RE                = /^[A-Za-z0-9+/]{32}$/; // 24-byte NaCl nonce

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

// NaCl box public key: exactly 32 bytes → 43 base64 chars + one '=' pad
const PUBKEY_RE = /^[A-Za-z0-9+/]{43}=$/;

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
const joinRate       = new Map();  // ip → { count, resetAt }
const lastRateStrike = new Map();  // ip → timestamp of the last rate-limit strike
// Operator-run AI chat bots (see bots/). Humans are only ever matched with a
// bot after explicitly opting in, and the match is always labeled as AI.
const botSockets     = new Set();  // every authenticated bot connection
const idleBots       = new Set();  // bots ready for a new conversation

const abuseStrikes   = new Map();  // ip → { count, resetAt }
const bannedIPs      = new Map();  // ip → bannedUntil timestamp

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function getIP(req) {
  const fwd   = req.headers['x-forwarded-for'];
  const chain = (typeof fwd === 'string' ? fwd.split(',') : [])
    .map(s => s.trim())
    .filter(Boolean);
  chain.push(req.socket?.remoteAddress || 'unknown');
  // Walk back TRUST_PROXY hops from the socket; clamp to the leftmost entry.
  return chain[Math.max(0, chain.length - 1 - TRUST_PROXY)];
}

function send(ws, obj) {
  if (ws.readyState === WS.OPEN) ws.send(JSON.stringify(obj));
}

function randomId() {
  return crypto.randomBytes(8).toString('hex'); // 64-bit cryptographically random room ID
}

// Abuse log — timestamp, rule and client IP only. No content, keywords or reports.
const ABUSE_LOG   = path.join(LOG_DIR, 'abuse.log');
const REPORTS_LOG = path.join(LOG_DIR, 'reports.log');
function writeAbuseLine(reason, ip) {
  const line = `${new Date().toISOString()} [${reason}] ip=${ip}\n`;
  fs.appendFile(ABUSE_LOG, line, err => {
    if (err) console.error('[abuse-log] write failed:', err.message);
  });
}

// Records an abuse event and counts it as a strike towards an automatic ban.
function logAbuse(reason, ip) {
  writeAbuseLine(reason, ip);
  if (rateExceeded(abuseStrikes, ip, STRIKE_LIMIT, STRIKE_WINDOW_MS)) banIP(ip);
}

// A rate limit was hit: logged and counted at most once per IP per minute
// (see STRIKE_LIMIT), so shared IPs aren't banned for being busy.
function logRateHit(reason, ip) {
  const now = Date.now();
  if (now - (lastRateStrike.get(ip) || 0) < 60_000) return;
  lastRateStrike.set(ip, now);
  logAbuse(reason, ip);
}

function banIP(ip) {
  if (BAN_ALLOWLIST.has(ip) || isBanned(ip)) return;
  bannedIPs.set(ip, Date.now() + BAN_DURATION_MS);
  abuseStrikes.delete(ip);
  writeAbuseLine('banned', ip);
  console.log(`[ban] banned=${bannedIPs.size}`);
}

// Bots authenticate with "Authorization: Bearer <BOT_TOKEN>" on the upgrade.
// Browsers can't set that header, so a page can never pose as a bot.
const BOT_TOKEN_HASH = process.env.BOT_TOKEN
  ? crypto.createHash('sha256').update(process.env.BOT_TOKEN).digest()
  : null;

function isBotRequest(req) {
  if (!BOT_TOKEN_HASH) return false;
  const auth = req.headers['authorization'];
  if (typeof auth !== 'string' || !auth.startsWith('Bearer ')) return false;
  const given = crypto.createHash('sha256').update(auth.slice(7)).digest();
  return crypto.timingSafeEqual(given, BOT_TOKEN_HASH);
}

function isBanned(ip) {
  const until = bannedIPs.get(ip);
  if (!until) return false;
  if (Date.now() > until) { bannedIPs.delete(ip); return false; }
  return true;
}

// Fixed-window rate limiter. Returns true if the IP is over the limit.
function rateExceeded(map, ip, maxPerWindow, windowMs) {
  const now = Date.now();
  const rec = map.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + windowMs; }
  rec.count++;
  map.set(ip, rec);
  return rec.count > maxPerWindow;
}

// Token bucket stored on the socket: up to `burst` tokens, one more every
// `refillMs`. Takes a token and returns 0, or returns the ms until one is free.
function takeToken(ws, key, burst, refillMs) {
  const now = Date.now();
  const b = ws[key] ??= { tokens: burst, at: now };
  b.tokens = Math.min(burst, b.tokens + (now - b.at) / refillMs);
  b.at = now;
  if (b.tokens >= 1) { b.tokens -= 1; return 0; }
  return Math.ceil((1 - b.tokens) * refillMs);
}

// How long a person must wait before their next join (0 = go ahead).
function joinWait(ws) {
  const wait = takeToken(ws, '_joinBucket', JOIN_BURST, JOIN_REFILL_MS);
  if (wait) return wait;
  if (rateExceeded(joinRate, ws._ip, MAX_JOINS_PER_IP_PER_MIN, 60_000)) {
    return Math.max(1000, joinRate.get(ws._ip).resetAt - Date.now());
  }
  return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Periodic sweep — evict expired entries, keep all maps bounded
// ─────────────────────────────────────────────────────────────────────────────

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of bannedIPs)      { if (now > v)           bannedIPs.delete(k); }
  for (const [k, v] of abuseStrikes)   { if (now > v.resetAt)   abuseStrikes.delete(k); }
  for (const [k, v] of wsConnectRate)  { if (now > v.resetAt)   wsConnectRate.delete(k); }
  for (const [k, v] of httpApiRate)    { if (now > v.resetAt)   httpApiRate.delete(k); }
  for (const [k, v] of httpStaticRate) { if (now > v.resetAt)   httpStaticRate.delete(k); }
  for (const [k, v] of reportThrottle) { if (now > v.resetAt)   reportThrottle.delete(k); }
  for (const [k, v] of challengeRate)  { if (now > v.resetAt)   challengeRate.delete(k); }
  for (const [k, v] of joinRate)       { if (now > v.resetAt)   joinRate.delete(k); }
  for (const [k, v] of lastRateStrike) { if (now - v > 60_000)  lastRateStrike.delete(k); }
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
app.set('query parser', false); // no route reads req.query — keep qs off the request path

// No 'unsafe-inline' for styles: pages have no style="" attributes, and each
// inline <style> block is allowed by its SHA-256 hash, registered via
// allowStyleBlocks() when the page is built at startup.
const STYLE_HASHES = new Set();

function allowStyleBlocks(html) {
  for (const m of html.matchAll(/<style>([\s\S]*?)<\/style>/g)) {
    // Browsers hash the parsed text, and HTML parsing turns CRLF into LF.
    const text = m[1].replace(/\r\n?/g, '\n');
    STYLE_HASHES.add(`'sha256-${crypto.createHash('sha256').update(text, 'utf8').digest('base64')}'`);
  }
  return html;
}

// WebSocket endpoints: the allowed page origins with ws(s) schemes. Listed
// explicitly because older Safari versions don't let 'self' cover ws/wss.
const WS_CONNECT_SRC = [...ALLOWED_WS_ORIGINS]
  .map(o => o.replace(/^http/, 'ws'))
  .join(' ');

let CSP_HEADER = null; // built on first request, after all pages registered hashes
function cspHeader() {
  return CSP_HEADER ??= [
    "default-src 'none'",
    "script-src 'self'",
    `style-src 'self' ${[...STYLE_HASHES].join(' ')}`,
    "font-src 'self'",
    "img-src 'self'",
    `connect-src 'self' ${WS_CONNECT_SRC}`,
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ');
}

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', cspHeader());
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  // Browsers ignore HSTS over plain HTTP, so this is harmless in local dev.
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});

// Banned IPs are refused before any other work, without logging each request
// again — the ban itself is logged once.
app.use((req, res, next) => {
  if (isBanned(getIP(req))) return res.status(403).end();
  next();
});

// Static assets get a generous separate budget so font/JS loads don't eat
// into the API budget used for /challenge. So does /count: every waiting
// client polls it, so on a shared IP it adds up with ordinary use.
const STATIC_EXT = new Set(['.js', '.css', '.woff2', '.woff', '.ttf', '.ico', '.png', '.svg', '.json']);

app.use((req, res, next) => {
  const ip       = getIP(req);
  const isStatic = STATIC_EXT.has(path.extname(req.path).toLowerCase()) || req.path === '/count';
  if (isStatic) {
    if (rateExceeded(httpStaticRate, ip, MAX_HTTP_STATIC_RPM, 60_000)) {
      return res.status(429).json({ error: 'too many requests' });
    }
  } else {
    if (rateExceeded(httpApiRate, ip, MAX_HTTP_API_RPM, 60_000)) {
      logRateHit('http_flood', ip);
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
    if (isBotRequest(req)) { req._isBot = true; return true; }
    if (isBanned(getIP(req))) return false;
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
  const ip    = getIP(req);
  const now   = Date.now();
  const isBot = req._isBot === true;

  // Before any early return: a socket that errors with no 'error' listener
  // (e.g. an oversized frame on a refused connection) crashes the process.
  ws.on('error', () => handleClose(ws));

  if (!isBot) {
    // ── Rate: new connections per minute ───────────────────────────────────
    if (rateExceeded(wsConnectRate, ip, MAX_WS_CONNECTS_PER_MIN, 60_000)) {
      logRateHit('ws_rate', ip);
      ws.close(1008, 'Too many connections');
      return;
    }

    // ── Cap: concurrent connections per IP ─────────────────────────────────
    const currentConns = ipConnections.get(ip) || 0;
    if (currentConns >= MAX_CONNS_PER_IP) {
      logRateHit('conn_cap', ip);
      ws.close(4429, 'Too many connections from your IP');
      return;
    }

    ipConnections.set(ip, currentConns + 1);
  } else {
    botSockets.add(ws);
    console.log(`[bot] connected bots=${botSockets.size}`);
  }

  ws.isAlive         = true;
  ws._isBot          = isBot;
  ws._ip             = isBot ? null : ip; // bots don't hold a per-IP slot
  ws.keywords        = null;
  ws.roomId          = null;
  ws._closed         = false;
  ws._connectedAt    = now;
  ws._verified       = false;
  ws._recentPartners = new Set();  // avoid re-matching the same pair on Next →
  ws._joinedPoolAt   = 0;          // set when entering the waiting pool

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', raw => {
    if (ws.readyState !== WS.OPEN) return; // closing — ignore what's still in flight
    if (!ws._isBot && takeToken(ws, '_frameBucket', FRAME_BURST, FRAME_REFILL_MS)) {
      logAbuse('ws_flood', ws._ip);
      ws.close(1008, 'Too many messages');
      return;
    }
    if (raw.length > 4096) return; // belt-and-suspenders after maxPayload
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;

    // Bots may only announce readiness, chat and leave; humans can't do bot things.
    if (ws._isBot  && (msg.type === 'join' || msg.type === 'join_ai')) return;
    if (!ws._isBot && msg.type === 'bot_ready') return;

    switch (msg.type) {

      case 'bot_ready': {
        // A bot offers itself for one new conversation, with a fresh key.
        if (ws.roomId) return;
        if (typeof msg.pubKey !== 'string' || !PUBKEY_RE.test(msg.pubKey)) {
          send(ws, { type: 'error', code: 'invalid_key' });
          return;
        }
        ws.pubKey = msg.pubKey;
        idleBots.add(ws);
        break;
      }

      case 'join_ai': {
        // A waiting human explicitly chose to chat with an AI instead.
        if (!ws._verified || ws.roomId) return;
        if (typeof msg.pubKey !== 'string' || !PUBKEY_RE.test(msg.pubKey)) {
          send(ws, { type: 'error', code: 'invalid_key' });
          return;
        }
        const aiWait = joinWait(ws);
        if (aiWait) {
          send(ws, { type: 'error', code: 'slow_down', retryMs: aiWait });
          return;
        }
        let bot = null;
        for (const b of idleBots) { if (b.readyState === WS.OPEN) { bot = b; break; } }
        if (!bot || rooms.size >= MAX_ROOMS) {
          send(ws, { type: 'error', code: 'ai_unavailable' });
          return;
        }

        // The bot gets the human's keywords as a conversation topic
        const topics = (ws.keywords || []).filter(k => k !== '__random__');
        leaveSession(ws); // out of the keyword pools
        ws.pubKey = msg.pubKey;

        idleBots.delete(bot);
        const roomId = randomId();
        rooms.set(roomId, { a: bot, b: ws, ai: true });
        bot.roomId = roomId;
        ws.roomId  = roomId;

        send(ws,  { type: 'matched', ai: true, matchedKeywords: [], partnerPubKey: bot.pubKey });
        send(bot, { type: 'matched', ai: true, keywords: topics, partnerPubKey: ws.pubKey });
        console.log(`[match] ai room=${roomId} rooms=${rooms.size}`);
        break;
      }

      case 'join': {

        // Already in a conversation — the client must send 'leave' first.
        // Without this, a late join (e.g. the random-pool fallback racing a
        // match) would put one socket into two rooms.
        if (ws.roomId) return;

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
          banIP(ws._ip);
          ws.close(1008, 'Blocked');
          return;
        }

        // ── Memory ceiling ───────────────────────────────────────────────
        if (waitingPool.size >= MAX_WAITING_POOL_KEYS || rooms.size >= MAX_ROOMS) {
          send(ws, { type: 'error', code: 'server_busy' });
          return;
        }

        // ── Pacing: after PoW, so a retry needs no fresh token ───────────
        const wait = joinWait(ws);
        if (wait) {
          send(ws, { type: 'error', code: 'slow_down', retryMs: wait });
          return;
        }

        // ── Clean up any previous pool membership (critical for Next →) ──
        // Without this, the ws stays in the old pool from the previous
        // session and either matches with itself or blocks future matches.
        // A re-join while still waiting (random-pool fallback) keeps the
        // original wait time, so the client doesn't lose its place in line.
        const waitingSince = ws.keywords ? ws._joinedPoolAt : 0;
        if (ws.keywords) {
          ws.keywords.forEach(kw => {
            const p = waitingPool.get(kw);
            if (p) { p.delete(ws); if (p.size === 0) waitingPool.delete(kw); }
          });
          ws.keywords = null;
        }

        // A malformed key would make the partner's key derivation throw
        if (typeof msg.pubKey !== 'string' || !PUBKEY_RE.test(msg.pubKey)) {
          send(ws, { type: 'error', code: 'invalid_key' });
          return;
        }
        ws.pubKey = msg.pubKey;

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
          ws._joinedPoolAt = waitingSince || Date.now();
          keywords.forEach(kw => {
            const pool = waitingPool.get(kw) || new Set();
            pool.add(ws);
            waitingPool.set(kw, pool);
          });
          send(ws, { type: 'waiting', keywords });
        }
        break;
      }

      case 'message': {
        if (!ws.roomId) return;
        const room = rooms.get(ws.roomId);
        if (!room) return;
        const other = room.a === ws ? room.b : room.a;

        // Only relay E2EE frames — plaintext relay intentionally absent.
        // Oversized or malformed frames are rejected, never truncated: a
        // truncated ciphertext just fails authentication on the other side.
        const { ciphertext, nonce } = msg;
        if (typeof ciphertext !== 'string' || typeof nonce !== 'string' ||
            ciphertext.length > MAX_CIPHERTEXT_B64 ||
            !CIPHERTEXT_RE.test(ciphertext) || !NONCE_RE.test(nonce)) {
          send(ws, { type: 'error', code: 'message_rejected' });
          return;
        }

        if (takeToken(ws, '_msgBucket', MSG_BURST, MSG_REFILL_MS)) {
          send(ws, { type: 'error', code: 'rate_limited' });
          return;
        }

        send(other, { type: 'message', ciphertext, nonce });
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
        leaveSession(ws);
        break;
      }

      // Unknown types are silently ignored
    }
  });

  ws.on('close', () => handleClose(ws));
});

// ─────────────────────────────────────────────────────────────────────────────
// Cleanup on leave / close / error
// ─────────────────────────────────────────────────────────────────────────────
// A 'leave' message ends the current session (pool membership or room) but
// keeps the socket open for Next →. Only an actual socket close releases the
// per-IP connection slot, so an open socket always counts against the cap.

function handleClose(ws) {
  if (ws._closed) return;
  ws._closed = true;

  if (ws._isBot) {
    botSockets.delete(ws);
    idleBots.delete(ws);
    console.log(`[bot] disconnected bots=${botSockets.size}`);
  }

  if (ws._ip) {
    const n = (ipConnections.get(ws._ip) || 1) - 1;
    if (n <= 0) ipConnections.delete(ws._ip);
    else        ipConnections.set(ws._ip, n);
  }

  leaveSession(ws);
  // Otherwise every closed socket keeps its past partners alive, and they
  // keep theirs: memory would grow with every conversation since startup.
  ws._recentPartners?.clear();
}

function leaveSession(ws) {
  // A bot that leaves is no longer available until it sends bot_ready again
  idleBots.delete(ws);

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
      other.roomId = null; // room is gone for both sides; lets the partner rejoin
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
    if (!ws.isAlive) { zombies++; handleClose(ws); ws.terminate(); return; }
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
  // Bots are not people — they never count towards the "embers" shown.
  res.json({ count: wss.clients.size - botSockets.size, ai: idleBots.size > 0 });
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

  fs.appendFile(REPORTS_LOG, entry, err => {
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
const POLICY_EFFECTIVE_DATE = '24 September 2026';
const TERMS_EFFECTIVE_DATE  = '24 September 2026';

const PRIVACY_HTML = allowStyleBlocks(`<!DOCTYPE html>
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
  .small { font-size: 0.85rem; }
</style>
</head>
<body>
<h1>Privacy Policy</h1>
<p class="date">Effective date: ${POLICY_EFFECTIVE_DATE} &nbsp;·&nbsp; Jurisdiction: Switzerland</p>
<p>Emberline is an anonymous, ephemeral chat platform. This policy describes what data we collect, what we do not collect, and your rights under Swiss law (nFADP).</p>
<h2>What we do not collect</h2>
<p>We do not collect names, email addresses, phone numbers, or any other identifying information. We do not require registration. We do not store chat messages — messages are relayed in real time using end-to-end encryption and are never written to disk. We have no ability to retrieve or reconstruct past conversations.</p>
<h2>What we do collect</h2>
<p>When a user submits an abuse report, we record the report timestamp, the reason category, and — only if the reporter chooses to write them — up to 500 characters of free-text details. No chat messages are attached, and no IP address or user identity is recorded with the report. Please do not include personal information in the details. Reports are retained for a maximum of 90 days.</p>
<h2>IP addresses</h2>
<p>We do not log IP addresses in association with chat content, reports, keywords, or any durable user record. An IP-based abuse defense runs at the connection layer: when a client trips a rate limit, fails a proof-of-work check, or hits a honeypot, an entry is written to an abuse log containing only a timestamp, the triggered rule, and the source IP. This log feeds a ban system that temporarily blocks repeat offenders and is rotated after 90 days. It is never cross-referenced against reports, conversations, or keywords — and cannot be, because none of those are stored. This is the minimum defense a fully anonymous service requires to remain functional.</p>
<h2>End-to-end encryption</h2>
<p>All messages are encrypted on your device using the NaCl box construction (Curve25519 + XSalsa20 + Poly1305). Only the two participants can decrypt messages. The server relays encrypted data it cannot read. In an optional AI chat, the AI is the other participant (see below).</p>
<h2>Optional AI chat</h2>
<p>If no one matches your keywords right away, the waiting screen may offer to let you chat with an AI instead. This only happens if you click that button, and an AI chat is labeled as such for its entire duration. The AI is a language model running on hardware operated by Emberline. It is the other participant in the conversation, so to reply it decrypts your messages and receives the keywords you entered. AI conversations are held in memory only while the chat lasts; they are not stored, logged, or used to train models. The AI can be wrong or say strange things — do not rely on it for advice, and do not share personal information with it.</p>
<h2>Keywords</h2>
<p>Keywords are held temporarily in server memory during matching and discarded immediately after a match is made or the session ends. If you choose an AI chat, your keywords are passed to the AI as conversation topics and discarded when the chat ends.</p>
<h2>Cookies, tracking, and storage</h2>
<p>We use no cookies, no analytics, no tracking pixels, and no third-party services. We do not use localStorage, sessionStorage, or any other form of persistent client-side storage. All fonts and cryptography libraries are self-hosted — no external requests are made by your browser.</p>
<h2>Illegal content</h2>
<p>Use of Emberline to share, solicit, or facilitate illegal content — including CSAM, harassment, or content illegal under Swiss law — is strictly prohibited. We cooperate with Swiss law enforcement under the Swiss Criminal Code.</p>
<h2>Your rights under nFADP</h2>
<p>You have the right to request access to any personal data we hold about you and to request its deletion. Because we store no user identities, no messages, and no session history, there is typically nothing to disclose or delete. The one category of data that could constitute personal data under nFADP is the IP entries in the abuse log described above; these can be removed on request if you provide the IP and an approximate time window. Contact: <a href="mailto:contactall@emberline.ch">contactall@emberline.ch</a>.</p>
<h2>Changes</h2>
<p>We may update this policy as the platform evolves. The effective date above reflects the most recent revision.</p>
<hr><p class="small"><a href="/">← Back to Emberline</a></p>
</body></html>`);

app.get('/privacy', (req, res) => res.send(PRIVACY_HTML));

// ─────────────────────────────────────────────────────────────────────────────
// REST: /terms
// ─────────────────────────────────────────────────────────────────────────────

const TERMS_HTML = allowStyleBlocks(`<!DOCTYPE html>
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
  .small { font-size: 0.85rem; color: #5a4e44; }
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
  <li>Automated access (bots, scrapers, scripts), other than Emberline's own clearly labeled AI chat</li>
  <li>Attempts to circumvent security or encryption mechanisms</li>
</ul>
<h2>4. CSAM — zero tolerance</h2>
<p>Any user who transmits, solicits, or facilitates CSAM will be reported to KOBIK immediately. Report directly at <a href="https://www.kobik.ch" target="_blank" rel="noopener noreferrer">www.kobik.ch</a>.</p>
<h2>5. Optional AI chat</h2>
<p>Emberline may offer an optional chat with an AI model operated by Emberline when no human match is available. It only starts at your request and is labeled as AI for its entire duration. AI replies are generated automatically, can be inaccurate or inappropriate, and are not advice of any kind. These terms apply to AI chats as well. The AI ends a chat if a user indicates they are under 18.</p>
<h2>6. Anonymity and its limits</h2>
<p>Emberline is designed to be anonymous. We require no accounts, store no messages, and retain no user identifiers. An IP-based abuse defense log is maintained for bot prevention only — see the Privacy Policy for full details. Anonymity at the technical layer does not exempt users from legal responsibility under Swiss law.</p>
<h2>7. No warranty</h2>
<p>Emberline is provided as-is without warranty of any kind. Use is at your own risk.</p>
<h2>8. Governing law</h2>
<p>These terms are governed exclusively by Swiss law. Disputes are subject to the exclusive jurisdiction of Swiss courts.</p>
<h2>9. Contact</h2>
<p>Legal notices and law enforcement requests: <a href="mailto:contactall@emberline.ch">contactall@emberline.ch</a>.</p>
<hr>
<p class="small"><a href="/privacy">Privacy policy</a> &nbsp;·&nbsp; <a href="/">Back to Emberline</a></p>
</body></html>`);

app.get('/terms', (req, res) => res.send(TERMS_HTML));

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
    return allowStyleBlocks(fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8')
      .replace(/__BUILD_FOOTER__/g, BUILD_FOOTER_FRAGMENT));
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
// Static files — PUBLIC_DIR only. Dotfiles are denied explicitly.
// ─────────────────────────────────────────────────────────────────────────────

app.use(express.static(PUBLIC_DIR, {
  dotfiles: 'deny',
  index: false, // '/' is served by the templated route above
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
  console.log(`Public  → ${PUBLIC_DIR}`);
  console.log(`Reports → ${REPORTS_LOG}`);
  console.log(`Abuse   → ${ABUSE_LOG}`);
  console.log(`Proxy   → trusting ${TRUST_PROXY} hop(s) of X-Forwarded-For`);
  console.log(`BUILD   → ${BUILD_VERSION_SHORT}${BUILD_VERSION === 'dev' ? '' : ` (${BUILD_VERSION})`}`);
});
