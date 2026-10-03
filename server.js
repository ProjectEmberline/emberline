/**
 * Emberline — Profiles Server
 * ─────────────────────────────
 * Install:  npm install ws express
 * Run:      node server.js
 *
 * Privacy & legal:
 *   - IP addresses are written only to abuse.log (timestamp + rule + IP), never
 *     alongside chats, profiles or reports
 *   - Profiles, requests and chats live in memory only, while their owner is online
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
 *   MAX_PROFILES_PER_IP  concurrent profiles per IP (default 5)
 *   BOT_TOKEN    shared secret for the operator's AI chat bots (bots/ember-bot.js).
 *                Unset = AI chat disabled. Never commit it.
 *   Tests shorten these (ms): REQUEST_TTL_MS, IDLE_WARNING_MS, IDLE_LOGOFF_MS,
 *                RECONNECT_GRACE_MS, COUNTS_TICK_MS
 *
 * Name and word filters (plain text, one entry per line, # for comments), read
 * from LOG_DIR and reloaded when they change:
 *   reserved-names.txt  names containing an entry are refused (default list below)
 *   blocked-words.txt   refused in names and interests (empty by default)
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
const MAX_HTTP_API_RPM        = 60;  // /challenge and the policy pages, per IP per minute
const MAX_HTTP_STATIC_RPM     = 300; // static assets per IP per minute

const MAX_REPORTS_PER_IP      = 10;  // abuse reports per IP per hour
const MAX_CHALLENGES_PER_IP   = 60;  // challenge tokens per IP per hour
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
const MAX_CHALLENGES_STORED   = 5_000;
const MAX_PROFILES            = 20_000;
const MAX_REQUESTS            = 100_000;
const MAX_CHATS               = 100_000;

// Profiles (see PROFILES.md). All in memory, all per person.
const MAX_PROFILES_PER_IP     = envInt('MAX_PROFILES_PER_IP', 5);  // concurrent
const MAX_INTERESTS           = 10;
const GENDERS = new Set(['', 'woman', 'man', 'trans woman (MtF)', 'trans man (FtM)', 'non-binary', 'genderfluid']);
const MAX_OUTGOING_REQUESTS   = 20;   // open requests a profile has sent
const MAX_INCOMING_REQUESTS   = 30;   // open requests a profile can receive
const MAX_ACTIVE_CHATS        = 20;
const MAX_QUEUED_PER_CHAT     = 50;   // messages waiting for someone who is reconnecting
const REQUEST_TTL_MS          = envInt('REQUEST_TTL_MS', 10 * 60_000);
const REQUEST_BURST           = 5;        // 5 requests…
const REQUEST_REFILL_MS       = 12_000;   // …a minute
const MAX_REQUEST_CHARS       = 200;
const MAX_REQUEST_CT_B64      = Math.ceil((MAX_REQUEST_CHARS * 3 + 16) / 3) * 4; // 824
const SEARCH_RESULTS          = 20;       // random sample of the matches
const SEARCH_BURST            = 10;
const SEARCH_REFILL_MS        = 3_000;
const IDLE_WARNING_MS         = envInt('IDLE_WARNING_MS', 28 * 60_000);
const IDLE_LOGOFF_MS          = envInt('IDLE_LOGOFF_MS', 30 * 60_000);
const RECONNECT_GRACE_MS      = envInt('RECONNECT_GRACE_MS', 5 * 60_000);
const COUNTS_TICK_MS          = Math.max(100, envInt('COUNTS_TICK_MS', 5_000));
const TOP_INTERESTS           = 50;   // "popular now" on Discover
const MAX_WATCHED_INTERESTS   = 40;
const MAX_ALL_INTERESTS       = 200;

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
// Creating a profile and starting an AI chat. A proof-of-work is only needed
// once per socket, so this caps how fast one socket can churn through
// profiles or bots. Over the limit the client is asked to retry later (no strike).
const JOIN_BURST              = 5;
const JOIN_REFILL_MS          = 3_000;
const MAX_JOINS_PER_IP_PER_MIN = 120;  // across all sockets of one IP
// Must match maxlength on the chat input. A JS string of N UTF-16 units encodes
// to at most 3N UTF-8 bytes; NaCl box adds a 16-byte tag; base64 is 4/3.
const MAX_MESSAGE_CHARS       = 300;
const MAX_CIPHERTEXT_B64      = Math.ceil((MAX_MESSAGE_CHARS * 3 + 16) / 3) * 4; // 1224
const CIPHERTEXT_RE           = /^[A-Za-z0-9+/]+={0,2}$/;
const NONCE_RE                = /^[A-Za-z0-9+/]{32}$/; // 24-byte NaCl nonce

const HONEYPOT_KEYWORD = '__honeypot__';
const VALID_REASONS    = new Set(['csam', 'harassment', 'illegal', 'spam']); // report categories

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

const challenges    = new Map();  // token → { prefix, expiresAt, ip }
const profiles      = new Map();  // id → profile (see createProfile)
const byName        = new Map();  // lowercased name → id
const byToken       = new Map();  // resume token → id
const byInterest    = new Map();  // interest → Set<id>; also the source of the counts
const profilesPerIp = new Map();  // ip → concurrent profiles
const requests      = new Map();  // id → { from, to, ciphertext, nonce, expiresAt, declined }
const chats         = new Map();  // id → { a, b, ai, bot, open: Set<profile id> }

// Per-IP rate tracking — values are ephemeral, never persisted
const ipConnections  = new Map();  // ip → count (concurrent)
const wsConnectRate  = new Map();  // ip → { count, resetAt }
const httpApiRate    = new Map();  // ip → { count, resetAt }
const httpStaticRate = new Map();  // ip → { count, resetAt }
const reportThrottle = new Map();  // ip → { count, resetAt }
const challengeRate  = new Map();  // ip → { count, resetAt }
const joinRate       = new Map();  // ip → { count, resetAt }
const lastRateStrike = new Map();  // ip → timestamp of the last rate-limit strike
// Operator-run AI chat bots (see bots/). A person only ever chats with a bot
// after choosing to, and the chat is always labeled as AI.
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

// How long a person must wait before their next profile or AI chat (0 = go ahead).
function joinWait(ws) {
  const wait = takeToken(ws, '_joinBucket', JOIN_BURST, JOIN_REFILL_MS);
  if (wait) return wait;
  if (rateExceeded(joinRate, ws._ip, MAX_JOINS_PER_IP_PER_MIN, 60_000)) {
    return Math.max(1000, joinRate.get(ws._ip).resetAt - Date.now());
  }
  return 0;
}

// Name and word filters, editable without a release (see header)
const DEFAULT_RESERVED_NAMES = ['admin', 'emberline', 'moderator', 'support', 'system', 'official'];
const FILTER_FILES = {
  reserved: path.join(LOG_DIR, 'reserved-names.txt'),
  blocked:  path.join(LOG_DIR, 'blocked-words.txt'),
};
let reservedNames = DEFAULT_RESERVED_NAMES;
let blockedWords  = [];
function readList(file, fallback) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n')
      .map(l => l.replace(/#.*/, '').trim().normalize('NFC').toLowerCase()).filter(Boolean);
  } catch { return fallback; } // no file: defaults
}
function loadFilters() {
  reservedNames = readList(FILTER_FILES.reserved, DEFAULT_RESERVED_NAMES);
  blockedWords  = readList(FILTER_FILES.blocked, []);
}
loadFilters();
// Polling rather than fs.watch: the files are bind-mounted into the container
for (const f of Object.values(FILTER_FILES)) fs.watchFile(f, { interval: 10_000, persistent: false }, loadFilters);

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
// Profiles: in-memory directory, requests and chats
// ─────────────────────────────────────────────────────────────────────────────
// A profile exists only while its owner is online. It is bound to one socket;
// after an unclean disconnect it waits RECONNECT_GRACE_MS for a `resume` with
// its secret token, then it is deleted. Nothing here is ever written to disk.

const newId  = () => crypto.randomBytes(16).toString('base64url');
const ID_RE  = /^[A-Za-z0-9_-]{22}$/;
const NAME_RE = /^[A-Za-z0-9_.-]{3,20}$/;

// Letters of any language, digits and "-"; lowercase, NFC, 2–24 chars.
function cleanInterest(raw) {
  if (typeof raw !== 'string') return '';
  return raw.normalize('NFC').toLowerCase()
    .replace(/[^\p{L}\p{N}-]/gu, '').replace(/^-+|-+$/g, '').slice(0, 24);
}

function bucket(n) {
  if (n >= 50) return '50+';
  if (n >= 25) return '25+';
  if (n >= 10) return '10+';
  if (n >= 5)  return '5–9';
  if (n >= 1)  return '1–4';
  return '0';
}

const containsAny = (text, words) => { const t = text.toLowerCase(); return words.some(w => t.includes(w)); };

// Public part of a profile: what other people see
const summary = p => ({ id: p.id, name: p.name, gender: p.gender, interests: p.interests, pubKey: p.pubKey, accepting: p.accepting });
const toProfile = (p, obj) => { if (p?.ws) send(p.ws, obj); };
const blockedBetween = (a, b) => a.blocked.has(b.id) || b.blocked.has(a.id);
const openIncoming = p => { let n = 0; for (const rid of p.inbound) if (!requests.get(rid)?.declined) n++; return n; };

function isActiveChat(c) { return c.ai ? !!c.bot : c.open.size === 2; }
function activeChats(p) { let n = 0; for (const cid of p.chats) { const c = chats.get(cid); if (c && isActiveChat(c)) n++; } return n; }
function partnerId(c, pid) { return c.a === pid ? c.b : c.a; }
function chatBetween(a, b) {
  for (const cid of a.chats) { const c = chats.get(cid); if (c && !c.ai && partnerId(c, a.id) === b.id && c.open.size === 2) return c; }
  return null;
}
function pendingBetween(a, b) {
  for (const rid of a.outgoing) { const r = requests.get(rid); if (r && r.to === b.id) return r; }
  // One a declined doesn't count: a can still ask b
  for (const rid of b.outgoing) { const r = requests.get(rid); if (r && r.to === a.id && !r.declined) return r; }
  return null;
}

function createProfile(ws, { name, gender, interests, pubKey }) {
  const p = {
    id: newId(), name, gender, interests, pubKey,
    ws: null, ip: ws._ip, resumeToken: newId() + newId(),
    accepting: true, lastActiveAt: Date.now(), idleWarned: false,
    outgoing: new Set(), inbound: new Set(), chats: new Set(),
    blocked: new Set(), blockedBy: new Set(), noAnswer: new Set(), noAnswerBy: new Set(),
    graceTimer: null, watch: { on: false, interests: [], last: '' },
    queue: new Map(),   // chatId → encrypted messages waiting while this profile reconnects
  };
  profiles.set(p.id, p);
  byName.set(name.toLowerCase(), p.id);
  byToken.set(p.resumeToken, p.id);
  for (const t of interests) {
    const s = byInterest.get(t) || new Set();
    s.add(p.id); byInterest.set(t, s);
  }
  profilesPerIp.set(p.ip, (profilesPerIp.get(p.ip) || 0) + 1);
  attach(p, ws);
  return p;
}

function attach(p, ws) {
  clearTimeout(p.graceTimer);
  p.graceTimer = null;
  p.ws = ws;
  ws._profile = p.id;
  p.lastActiveAt = Date.now();
  p.idleWarned = false;
}

// What a (re)connected client needs to bring its view in line with the server
function stateSnapshot(p) {
  const incoming = [], outgoing = [], chatList = [];
  for (const rid of p.inbound) {
    const r = requests.get(rid);
    if (!r || r.declined) continue;
    incoming.push({ requestId: r.id, from: summary(profiles.get(r.from)), ciphertext: r.ciphertext, nonce: r.nonce, expiresIn: r.expiresAt - Date.now() });
  }
  for (const rid of p.outgoing) {
    const r = requests.get(rid);
    if (r) outgoing.push({ requestId: r.id, to: r.to, expiresIn: r.expiresAt - Date.now() });
  }
  for (const cid of p.chats) {
    const c = chats.get(cid);
    if (!c) continue;
    if (c.ai) { chatList.push({ chatId: c.id, ai: true, open: !!c.bot }); continue; }
    const other = profiles.get(partnerId(c, p.id));
    chatList.push({ chatId: c.id, partnerId: partnerId(c, p.id), open: c.open.size === 2, away: !!other && !other.ws });
  }
  return { type: 'state', accepting: p.accepting, incoming, outgoing, chats: chatList };
}

// ── Requests ─────────────────────────────────────────────────────────────────

function dropRequest(r, why) {
  clearTimeout(r.timer);
  requests.delete(r.id);
  const from = profiles.get(r.from), to = profiles.get(r.to);
  from?.outgoing.delete(r.id);
  to?.inbound.delete(r.id);
  // The recipient hears nothing about a request it already declined
  if ((why === 'withdrawn' || why === 'from_gone') && !r.declined) toProfile(to, { type: 'request_gone', requestId: r.id });
  if (why === 'to_gone') toProfile(from, { type: 'request_gone', requestId: r.id });
}

// No answer within REQUEST_TTL_MS. A decline ends up here too, at the same
// time and with the same frame, so the sender can't tell the two apart.
function expireRequest(r) {
  if (!requests.has(r.id)) return;
  const from = profiles.get(r.from), to = profiles.get(r.to);
  if (from && to) { from.noAnswer.add(to.id); to.noAnswerBy.add(from.id); }
  toProfile(from, { type: 'request_expired', requestId: r.id });
  dropRequest(r, 'expired');
  if (!r.declined) toProfile(to, { type: 'request_gone', requestId: r.id });
}

// ── Chats ────────────────────────────────────────────────────────────────────

// Profile p closes its side of chat c. The partner keeps a read-only copy
// until they close it too; the chat is forgotten once nobody has it open.
function leaveChat(c, p, reason) {
  c.open.delete(p.id);
  p.chats.delete(c.id);
  p.queue.delete(c.id);
  if (c.ai) {
    if (c.bot) { send(c.bot, { type: 'partner_left' }); c.bot._aiChat = null; c.bot = null; }
    chats.delete(c.id);
    return;
  }
  const other = profiles.get(partnerId(c, p.id));
  other?.queue.delete(c.id);   // nobody will read them any more
  if (other && c.open.has(other.id)) toProfile(other, { type: 'chat_ended', chatId: c.id, reason });
  if (c.open.size === 0) chats.delete(c.id);
}

// The bot ended the conversation (or disconnected); the human keeps their copy.
function botLeft(bot) {
  const c = bot._aiChat && chats.get(bot._aiChat);
  bot._aiChat = null;
  if (!c) return;
  c.bot = null;
  toProfile(profiles.get(c.a), { type: 'chat_ended', chatId: c.id, reason: 'ended' });
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

function deleteProfile(p, reason) {
  if (!profiles.has(p.id)) return;
  clearTimeout(p.graceTimer);
  for (const rid of [...p.outgoing]) { const r = requests.get(rid); if (r) dropRequest(r, 'from_gone'); }
  for (const rid of [...p.inbound])  { const r = requests.get(rid); if (r) dropRequest(r, 'to_gone'); }
  for (const cid of [...p.chats])    { const c = chats.get(cid); if (c) leaveChat(c, p, 'logged_off'); }
  for (const id of p.blocked)    profiles.get(id)?.blockedBy.delete(p.id);
  for (const id of p.blockedBy)  profiles.get(id)?.blocked.delete(p.id);
  for (const id of p.noAnswer)   profiles.get(id)?.noAnswerBy.delete(p.id);
  for (const id of p.noAnswerBy) profiles.get(id)?.noAnswer.delete(p.id);
  byName.delete(p.name.toLowerCase());
  byToken.delete(p.resumeToken);
  for (const t of p.interests) {
    const s = byInterest.get(t);
    if (s) { s.delete(p.id); if (s.size === 0) byInterest.delete(t); }
  }
  const n = (profilesPerIp.get(p.ip) || 1) - 1;
  if (n <= 0) profilesPerIp.delete(p.ip); else profilesPerIp.set(p.ip, n);
  profiles.delete(p.id);
  if (p.ws) { send(p.ws, { type: 'logged_off', reason }); p.ws._profile = null; p.ws = null; }
}

// The socket dropped without a log off: keep the profile for the grace period
function startGrace(p) {
  p.ws = null;
  if (RECONNECT_GRACE_MS === 0) return deleteProfile(p, 'timeout');
  for (const cid of p.chats) {
    const c = chats.get(cid);
    if (c && !c.ai && c.open.size === 2) toProfile(profiles.get(partnerId(c, p.id)), { type: 'partner_reconnecting', chatId: c.id });
  }
  p.graceTimer = setTimeout(() => deleteProfile(p, 'timeout'), RECONNECT_GRACE_MS);
}

// Idle: warn at IDLE_WARNING_MS, log off at IDLE_LOGOFF_MS without user action
const IDLE_CHECK_MS = Math.max(250, Math.min(15_000, Math.floor(IDLE_WARNING_MS / 4)));
setInterval(() => {
  const now = Date.now();
  for (const p of profiles.values()) {
    if (!p.ws) continue;
    const idle = now - p.lastActiveAt;
    if (idle >= IDLE_LOGOFF_MS) deleteProfile(p, 'idle');
    else if (idle >= IDLE_WARNING_MS && !p.idleWarned) {
      p.idleWarned = true;
      toProfile(p, { type: 'idle_warning', secondsLeft: Math.ceil((IDLE_LOGOFF_MS - idle) / 1000) });
    }
  }
}, IDLE_CHECK_MS).unref();

// ── Live interest counts: rounded buckets, pushed only when they change ──────

function topInterests(n) {
  return [...byInterest].sort((a, b) => b[1].size - a[1].size || (a[0] < b[0] ? -1 : 1)).slice(0, n);
}
function sendCounts(p, top, force) {
  const want = new Set([...p.interests, ...p.watch.interests, ...top]);
  // Other people only: on your own interests you aren't counted, so the chip
  // agrees with the search results ("0" when nobody else is there)
  const mine = new Set(p.interests);
  const buckets = {};
  for (const t of want) buckets[t] = bucket((byInterest.get(t)?.size || 0) - (mine.has(t) ? 1 : 0));
  const key = JSON.stringify([top, buckets]);
  if (!force && key === p.watch.last) return;
  p.watch.last = key;
  toProfile(p, { type: 'counts', buckets, top });
}
setInterval(() => {
  const top = topInterests(TOP_INTERESTS).map(([t]) => t);
  for (const p of profiles.values()) if (p.ws && p.watch.on) sendCounts(p, top, false);
}, COUNTS_TICK_MS).unref();

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

  ws.isAlive      = true;
  ws._isBot       = isBot;
  ws._ip          = isBot ? null : ip; // bots don't hold a per-IP slot
  ws._closed      = false;
  ws._connectedAt = now;
  ws._verified    = false;
  ws._profile     = null;   // profile id, humans
  ws._aiChat      = null;   // chat id, bots

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

    if (ws._isBot) handleBotFrame(ws, msg);
    else           handleHumanFrame(ws, msg);
  });

  ws.on('close', code => handleClose(ws, code));
});

// Bots keep the protocol they had before profiles: bot_ready, then 'matched',
// 'message', 'typing', 'leave' / 'partner_left' for one conversation at a time.
function handleBotFrame(bot, msg) {
  switch (msg.type) {
    case 'bot_ready': {
      // A bot offers itself for one new conversation, with a fresh key.
      if (bot._aiChat) return;
      if (typeof msg.pubKey !== 'string' || !PUBKEY_RE.test(msg.pubKey)) {
        send(bot, { type: 'error', code: 'invalid_key' });
        return;
      }
      bot.pubKey = msg.pubKey;
      idleBots.add(bot);
      break;
    }
    case 'message': {
      const c = bot._aiChat && chats.get(bot._aiChat);
      if (!c || !validCiphertext(msg, MAX_CIPHERTEXT_B64)) return;
      toProfile(profiles.get(c.a), { type: 'chat_message', chatId: c.id, ciphertext: msg.ciphertext, nonce: msg.nonce });
      break;
    }
    case 'typing': {
      const c = bot._aiChat && chats.get(bot._aiChat);
      if (c) toProfile(profiles.get(c.a), { type: 'chat_typing', chatId: c.id });
      break;
    }
    case 'leave':
      idleBots.delete(bot);
      botLeft(bot);
      break;
  }
}

function validCiphertext({ ciphertext, nonce }, max) {
  return typeof ciphertext === 'string' && typeof nonce === 'string' &&
    ciphertext.length <= max && CIPHERTEXT_RE.test(ciphertext) && NONCE_RE.test(nonce);
}

function verifyPow(ws, { token, nonce }) {
  const challenge = typeof token === 'string' && challenges.get(token);
  if (!challenge || Date.now() > challenge.expiresAt) {
    send(ws, { type: 'error', code: 'challenge_expired', re: 'profile_create' });
    return false;
  }
  // Reject if the challenge was issued to a different IP
  if (challenge.ip !== ws._ip) {
    logAbuse('pow_ip_mismatch', ws._ip);
    ws.close(1008, 'Invalid challenge');
    return false;
  }
  const hashBuf = crypto.createHash('sha256').update(challenge.prefix + String(nonce)).digest();
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
    return false;
  }
  challenges.delete(token);
  ws._verified = true;
  return true;
}

// Frames that don't count as the person doing something (for the idle timer).
// So is a search the page repeats by itself to keep its results current (auto).
const PASSIVE_FRAMES = new Set(['chat_typing', 'counts_watch']);
const isPassive = msg => PASSIVE_FRAMES.has(msg.type) || (msg.type === 'search' && msg.auto === true);

function handleHumanFrame(ws, msg) {
  // `re` names the frame an error answers, so the client never has to guess
  const err = (code, extra) => send(ws, { type: 'error', code, re: msg.type, ...extra });

  // ── Before a profile exists ────────────────────────────────────────────────
  if (msg.type === 'profile_create') {
    if (ws._profile) return;
    if (!ws._verified && !verifyPow(ws, msg)) return;

    // A hidden form field only bots fill in; the client sends it as an interest
    const rawInterests = Array.isArray(msg.interests) ? msg.interests.slice(0, 20) : [];
    if (rawInterests.includes(HONEYPOT_KEYWORD)) {
      logAbuse('honeypot', ws._ip);
      banIP(ws._ip);
      ws.close(1008, 'Blocked');
      return;
    }
    const name = typeof msg.name === 'string' ? msg.name.trim() : '';
    if (!NAME_RE.test(name)) return err('name_invalid');
    if (containsAny(name, reservedNames) || containsAny(name, blockedWords)) return err('name_reserved');
    if (byName.has(name.toLowerCase())) return err('name_taken');
    const gender = typeof msg.gender === 'string' ? msg.gender : '';
    if (!GENDERS.has(gender)) return err('gender_invalid');
    const interests = [...new Set(rawInterests.map(cleanInterest).filter(t => t.length >= 2))];
    if (interests.length === 0 || interests.length > MAX_INTERESTS || interests.some(t => containsAny(t, blockedWords))) {
      return err('interests_invalid');
    }
    if (typeof msg.pubKey !== 'string' || !PUBKEY_RE.test(msg.pubKey)) return err('invalid_key');
    if ((profilesPerIp.get(ws._ip) || 0) >= MAX_PROFILES_PER_IP) return err('too_many_profiles');
    if (profiles.size >= MAX_PROFILES) return err('server_busy');
    // Paced after validation, so fixing a typo in the form costs nothing
    const wait = joinWait(ws);
    if (wait) return err('slow_down', { retryMs: wait });

    const p = createProfile(ws, { name, gender, interests, pubKey: msg.pubKey });
    send(ws, { type: 'profile_ok', ...summary(p), resumeToken: p.resumeToken });
    return;
  }

  if (msg.type === 'resume') {
    if (ws._profile) return;
    const p = typeof msg.resumeToken === 'string' && profiles.get(byToken.get(msg.resumeToken));
    if (!p) return err('resume_failed');
    // Newest tab wins: the old socket is told and closed
    if (p.ws && p.ws !== ws) {
      send(p.ws, { type: 'replaced' });
      p.ws._profile = null;
      p.ws.close(4001, 'Continued in another tab');
    }
    const wasAway = !p.ws;
    byToken.delete(p.resumeToken);
    p.resumeToken = newId() + newId();
    byToken.set(p.resumeToken, p.id);
    if (p.ip !== ws._ip) {
      const n = (profilesPerIp.get(p.ip) || 1) - 1;
      if (n <= 0) profilesPerIp.delete(p.ip); else profilesPerIp.set(p.ip, n);
      p.ip = ws._ip;
      profilesPerIp.set(p.ip, (profilesPerIp.get(p.ip) || 0) + 1);
    }
    ws._verified = true;
    attach(p, ws);
    p.watch.last = '';
    send(ws, { type: 'profile_ok', ...summary(p), resumeToken: p.resumeToken });
    send(ws, stateSnapshot(p));
    // Messages that arrived while this profile was away, in order
    for (const [chatId, waiting] of p.queue) {
      if (!chats.get(chatId)?.open.has(p.id)) continue;
      for (const m of waiting) send(ws, { type: 'chat_message', chatId, ciphertext: m.ciphertext, nonce: m.nonce });
    }
    p.queue.clear();
    if (wasAway) {
      for (const cid of p.chats) {
        const c = chats.get(cid);
        if (c && !c.ai && c.open.size === 2) toProfile(profiles.get(partnerId(c, p.id)), { type: 'partner_back', chatId: c.id });
      }
    }
    return;
  }

  const me = ws._profile && profiles.get(ws._profile);
  if (!me || me.ws !== ws) return;
  if (!isPassive(msg)) { me.lastActiveAt = Date.now(); me.idleWarned = false; }

  switch (msg.type) {

    case 'still_here': break; // the activity update above is all it does

    case 'counts_watch': {
      me.watch.on = msg.on !== false;
      me.watch.interests = (Array.isArray(msg.interests) ? msg.interests : [])
        .slice(0, MAX_WATCHED_INTERESTS).map(cleanInterest).filter(t => t.length >= 2);
      if (me.watch.on) sendCounts(me, topInterests(TOP_INTERESTS).map(([t]) => t), true);
      break;
    }

    case 'interests_all': {
      if (takeToken(ws, '_searchBucket', SEARCH_BURST, SEARCH_REFILL_MS)) return err('rate_limited');
      send(ws, { type: 'interests_all', list: topInterests(MAX_ALL_INTERESTS).map(([t, s]) => [t, bucket(s.size)]) });
      break;
    }

    case 'search': {
      const interest = cleanInterest(msg.interest);
      if (interest.length < 2) return;
      const wait = takeToken(ws, '_searchBucket', SEARCH_BURST, SEARCH_REFILL_MS);
      if (wait) return err('rate_limited', { retryMs: wait });
      const ids = [...(byInterest.get(interest) || [])].filter(id => {
        if (id === me.id) return false;
        const o = profiles.get(id);
        return o && !blockedBetween(me, o);
      });
      // Random sample, so the first people in a list aren't the ones everyone asks
      for (let i = 0; i < Math.min(SEARCH_RESULTS, ids.length); i++) {
        const j = i + crypto.randomInt(ids.length - i);
        [ids[i], ids[j]] = [ids[j], ids[i]];
      }
      const people = ids.slice(0, SEARCH_RESULTS).map(id => {
        const o = profiles.get(id);
        return { ...summary(o), askedBefore: me.noAnswer.has(id) };
      });
      send(ws, { type: 'results', interest, bucket: bucket(ids.length), people });
      break;
    }

    // A random sample of everyone online, shown below the interest results
    case 'browse': {
      const wait = takeToken(ws, '_searchBucket', SEARCH_BURST, SEARCH_REFILL_MS);
      if (wait) return err('rate_limited', { retryMs: wait });
      const exclude = new Set(Array.isArray(msg.exclude) ? msg.exclude.slice(0, SEARCH_RESULTS * 2) : []);
      const ids = [];
      for (const o of profiles.values()) {
        if (o !== me && !exclude.has(o.id) && !blockedBetween(me, o)) ids.push(o.id);
      }
      for (let i = 0; i < Math.min(SEARCH_RESULTS, ids.length); i++) {
        const j = i + crypto.randomInt(ids.length - i);
        [ids[i], ids[j]] = [ids[j], ids[i]];
      }
      const people = ids.slice(0, SEARCH_RESULTS).map(id => ({ ...summary(profiles.get(id)), askedBefore: me.noAnswer.has(id) }));
      send(ws, { type: 'browse_results', people });
      break;
    }

    case 'request_send': {
      const to = typeof msg.to === 'string' && profiles.get(msg.to);
      // Blocked looks exactly like offline, so a block can't be detected
      if (!to || to === me || blockedBetween(me, to)) return err('offline', { to: msg.to });
      if (!validCiphertext(msg, MAX_REQUEST_CT_B64)) return err('message_rejected', { to: to.id });
      if (chatBetween(me, to)) return err('already_chatting', { to: to.id });
      if (pendingBetween(me, to)) return err('already_pending', { to: to.id });
      if (me.noAnswer.has(to.id)) return err('asked_before', { to: to.id });
      if (!to.accepting) return err('not_accepting', { to: to.id });
      if (me.outgoing.size >= MAX_OUTGOING_REQUESTS) return err('outgoing_full', { to: to.id });
      if (activeChats(me) >= MAX_ACTIVE_CHATS) return err('chats_full', { to: to.id });
      if (openIncoming(to) >= MAX_INCOMING_REQUESTS) return err('busy', { to: to.id });
      const wait = takeToken(ws, '_requestBucket', REQUEST_BURST, REQUEST_REFILL_MS);
      if (wait) return err('rate_limited', { to: to.id, retryMs: wait });
      if (requests.size >= MAX_REQUESTS) return err('server_busy', { to: to.id });

      const now = Date.now();
      const r = { id: newId(), from: me.id, to: to.id, ciphertext: msg.ciphertext, nonce: msg.nonce,
                  createdAt: now, expiresAt: now + REQUEST_TTL_MS, declined: false, timer: null };
      r.timer = setTimeout(() => expireRequest(r), REQUEST_TTL_MS);
      requests.set(r.id, r);
      me.outgoing.add(r.id);
      to.inbound.add(r.id);
      // expiresIn, not a timestamp: the browser's clock may be off
      send(ws, { type: 'request_sent', requestId: r.id, to: to.id, expiresIn: REQUEST_TTL_MS });
      toProfile(to, { type: 'request_in', requestId: r.id, from: summary(me), ciphertext: r.ciphertext, nonce: r.nonce, expiresIn: REQUEST_TTL_MS });
      break;
    }

    case 'request_withdraw': {
      const r = typeof msg.requestId === 'string' && requests.get(msg.requestId);
      if (r && r.from === me.id) dropRequest(r, 'withdrawn');
      break;
    }

    case 'request_answer': {
      const r = typeof msg.requestId === 'string' && requests.get(msg.requestId);
      if (!r || r.to !== me.id || r.declined) return;
      const from = profiles.get(r.from);
      if (msg.accept !== true) {
        // Silent: the request just disappears here; the sender keeps waiting
        // until it expires, exactly as if nobody had answered.
        r.declined = true;
        me.inbound.delete(r.id);
        return;
      }
      if (!from) return dropRequest(r, 'from_gone');
      if (activeChats(me) >= MAX_ACTIVE_CHATS) return err('chats_full');
      if (chats.size >= MAX_CHATS) return err('server_busy');
      dropRequest(r, 'accepted');
      const c = { id: newId(), a: from.id, b: me.id, ai: false, bot: null, open: new Set([from.id, me.id]) };
      chats.set(c.id, c);
      from.chats.add(c.id);
      me.chats.add(c.id);
      toProfile(from, { type: 'chat_open', chatId: c.id, requestId: r.id, partner: summary(me) });
      send(ws,        { type: 'chat_open', chatId: c.id, requestId: r.id, partner: summary(from) });
      break;
    }

    case 'set_accepting':
      me.accepting = msg.on === true;
      send(ws, { type: 'accepting', on: me.accepting });
      break;

    case 'chat_message': {
      const c = typeof msg.chatId === 'string' && chats.get(msg.chatId);
      if (!c || !c.open.has(me.id)) return;
      // The sender's own label for this message, echoed back in the ack
      const ref = typeof msg.ref === 'string' && /^[A-Za-z0-9]{1,16}$/.test(msg.ref) ? msg.ref : undefined;
      // Only relay E2EE frames — plaintext relay intentionally absent.
      // Oversized or malformed frames are rejected, never truncated.
      if (!validCiphertext(msg, MAX_CIPHERTEXT_B64)) return err('message_rejected', { chatId: c.id, ref });
      if (!isActiveChat(c)) return err('chat_closed', { chatId: c.id, ref });
      if (takeToken(ws, '_msgBucket', MSG_BURST, MSG_REFILL_MS)) return err('rate_limited', { chatId: c.id, ref });
      if (c.ai) {
        send(c.bot, { type: 'message', ciphertext: msg.ciphertext, nonce: msg.nonce });
        send(ws, { type: 'chat_ack', chatId: c.id, ref, queued: false });
        break;
      }
      const other = profiles.get(partnerId(c, me.id));
      if (!other) return err('chat_closed', { chatId: c.id, ref });
      if (!other.ws) {
        // Reconnecting: the message waits, still encrypted, until they're back
        // (resume) or gone (deleteProfile drops it with the rest of the profile)
        const waiting = other.queue.get(c.id) || [];
        if (waiting.length >= MAX_QUEUED_PER_CHAT) return err('partner_away', { chatId: c.id, ref });
        waiting.push({ ciphertext: msg.ciphertext, nonce: msg.nonce });
        other.queue.set(c.id, waiting);
        send(ws, { type: 'chat_ack', chatId: c.id, ref, queued: true });
        break;
      }
      send(other.ws, { type: 'chat_message', chatId: c.id, ciphertext: msg.ciphertext, nonce: msg.nonce });
      send(ws, { type: 'chat_ack', chatId: c.id, ref, queued: false });
      break;
    }

    case 'chat_typing': {
      const c = typeof msg.chatId === 'string' && chats.get(msg.chatId);
      if (!c || !c.open.has(me.id) || !isActiveChat(c)) return;
      if (c.ai) send(c.bot, { type: 'typing' });
      else toProfile(profiles.get(partnerId(c, me.id)), { type: 'chat_typing', chatId: c.id });
      break;
    }

    case 'chat_end': {
      const c = typeof msg.chatId === 'string' && chats.get(msg.chatId);
      if (c && c.open.has(me.id)) leaveChat(c, me, 'ended');
      break;
    }

    case 'block': {
      const other = typeof msg.profileId === 'string' && profiles.get(msg.profileId);
      if (!other || other === me || me.blocked.has(other.id)) return;
      me.blocked.add(other.id);
      other.blockedBy.add(me.id);
      for (const rid of [...me.outgoing]) {
        const r = requests.get(rid);
        if (r?.to === other.id) dropRequest(r, 'withdrawn');
      }
      for (const rid of [...other.outgoing]) {
        const r = requests.get(rid);
        // Their request to me: treated as declined, so it looks like no answer
        if (r?.to === me.id && !r.declined) { r.declined = true; me.inbound.delete(r.id); }
      }
      for (const cid of [...me.chats]) {
        const c = chats.get(cid);
        if (c && !c.ai && partnerId(c, me.id) === other.id) leaveChat(c, me, 'ended');
      }
      break;
    }

    case 'report': {
      if (rateExceeded(reportThrottle, ws._ip, MAX_REPORTS_PER_IP, 3_600_000)) return err('rate_limited');
      const reason = typeof msg.reason === 'string' && VALID_REASONS.has(msg.reason) ? msg.reason : null;
      if (!reason) return err('invalid_reason');
      const subject = typeof msg.profileId === 'string' && profiles.get(msg.profileId);
      const fallbackName = typeof msg.name === 'string' && NAME_RE.test(msg.name) ? msg.name : '';
      const clean = (s, n) => typeof s === 'string' ? s.replace(/[<>]/g, '').trim().slice(0, n) : '';
      const entry = {
        ts: new Date().toISOString(),
        reason,
        details: clean(msg.details, 500),
        reported: subject ? subject.name : fallbackName,
        // deliberately: no IP, no reporter identity
      };
      const requestText = clean(msg.requestText, MAX_REQUEST_CHARS);
      if (requestText) entry.requestTextUnverified = requestText; // provided by the reporter; the server can't check it
      fs.appendFile(REPORTS_LOG, JSON.stringify(entry) + '\n', e => {
        if (e) console.error('[report] failed to write log:', e.message);
      });
      send(ws, { type: 'report_ok' });
      break;
    }

    case 'ai_start': {
      if (activeChats(me) >= MAX_ACTIVE_CHATS) return err('chats_full');
      for (const cid of me.chats) if (chats.get(cid)?.ai) return err('ai_already_open');
      const wait = joinWait(ws);
      if (wait) return err('slow_down', { retryMs: wait });
      let bot = null;
      for (const b of idleBots) { if (b.readyState === WS.OPEN) { bot = b; break; } }
      if (!bot || chats.size >= MAX_CHATS) return err('ai_unavailable');
      idleBots.delete(bot);
      const c = { id: newId(), a: me.id, b: null, ai: true, bot, open: new Set([me.id]) };
      chats.set(c.id, c);
      me.chats.add(c.id);
      bot._aiChat = c.id;
      // The bot gets the person's profile: interests as conversation topics,
      // plus the name and gender ('' = not shown) so it can address them
      send(bot, { type: 'matched', ai: true, keywords: me.interests, name: me.name, gender: me.gender, partnerPubKey: me.pubKey });
      send(ws,  { type: 'chat_open', chatId: c.id, ai: true, partner: { name: 'Emberline AI', pubKey: bot.pubKey } });
      console.log(`[ai] chat opened chats=${chats.size}`);
      break;
    }

    case 'logoff':
      deleteProfile(me, 'logoff');
      break;

    // Unknown types are silently ignored
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cleanup on close / error
// ─────────────────────────────────────────────────────────────────────────────
// Only an actual socket close releases the per-IP connection slot, so an open
// socket always counts against the cap. A profile outlives an unclean close
// by RECONNECT_GRACE_MS; a log off (sent by the page on unload) deletes it now.

function handleClose(ws) {
  if (ws._closed) return;
  ws._closed = true;

  if (ws._isBot) {
    botSockets.delete(ws);
    idleBots.delete(ws);
    botLeft(ws);
    console.log(`[bot] disconnected bots=${botSockets.size}`);
  }

  if (ws._ip) {
    const n = (ipConnections.get(ws._ip) || 1) - 1;
    if (n <= 0) ipConnections.delete(ws._ip);
    else        ipConnections.set(ws._ip, n);
  }

  const p = ws._profile && profiles.get(ws._profile);
  ws._profile = null;
  if (p && p.ws === ws) startGrace(p);
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
  // People online with a profile; bots are never counted.
  res.json({ count: profiles.size, ai: idleBots.size > 0 });
});

// ─────────────────────────────────────────────────────────────────────────────
// REST: /privacy
// ─────────────────────────────────────────────────────────────────────────────

// Effective dates — update manually when the corresponding policy changes.
// Hardcoding avoids the bug where `new Date()` made the "effective date"
// slide forward every time someone loaded the page.
const POLICY_EFFECTIVE_DATE = '27 September 2026';
const TERMS_EFFECTIVE_DATE  = '27 September 2026';

// One stylesheet for both policy pages: the site's colours, light or dark
// following the reader's system setting (these pages run no script).
const POLICY_STYLE = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root { color-scheme: dark; --paper: #060d17; --ink: #dbe9f2; --ink-strong: #f2f8fc; --muted: #8fabbe; --border: #3a5a74; --accent: #e87834; --notice: #ffb070; }
  @media (prefers-color-scheme: light) {
    :root { color-scheme: light; --paper: #f2f7fa; --ink: #1c3242; --ink-strong: #12293a; --muted: #5b7587; --border: #9fbccd; --accent: #b8531a; --notice: #9a4413; }
  }
  body { font-family: 'Manrope', system-ui, sans-serif; font-weight: 400; background: var(--paper); color: var(--ink); max-width: 680px; margin: 0 auto; padding: 3rem 1.5rem; line-height: 1.7; }
  h1, h2 { font-family: 'Manrope', system-ui, sans-serif; font-weight: 700; letter-spacing: -0.02em; text-transform: uppercase; color: var(--ink-strong); }
  h1 { font-size: 2rem; margin-bottom: 0.4rem; }
  h2 { font-size: 1.2rem; margin: 2rem 0 0.5rem; }
  p { margin-bottom: 1rem; } ul { padding-left: 1.5rem; margin-bottom: 1rem; }
  li { margin-bottom: 0.4rem; } a { color: var(--accent); }
  .date { font-size: 0.85rem; color: var(--muted); margin-bottom: 2rem; }
  .notice { border-left: 2px solid var(--accent); padding-left: 1rem; margin: 1.5rem 0; }
  .notice p { color: var(--notice); }
  hr { border: none; border-top: 1px solid var(--border); margin: 2rem 0; }
  .small { font-size: 0.85rem; color: var(--muted); }
`;

const PRIVACY_HTML = allowStyleBlocks(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark light">
<title>Privacy Policy — Emberline</title>
<link href="/fonts/fonts.css" rel="stylesheet">
<style>${POLICY_STYLE}</style>
</head>
<body>
<h1>Privacy Policy</h1>
<p class="date">Effective date: ${POLICY_EFFECTIVE_DATE} &nbsp;·&nbsp; Jurisdiction: Switzerland</p>
<p>Emberline is an ephemeral chat platform with temporary profiles. This policy describes what data we collect, what we do not collect, and your rights under Swiss law (nFADP).</p>
<h2>What we do not collect</h2>
<p>We do not collect email addresses, phone numbers, real names, or any other identifying information. There is no registration and no account. We do not store chat messages — messages are relayed in real time using end-to-end encryption and are never written to disk. If the other person's connection drops for a moment, your messages wait for them in server memory, still encrypted, for up to 5 minutes; if they don't come back, the messages are discarded. We have no ability to retrieve or reconstruct past conversations.</p>
<h2>Your profile</h2>
<p>To go online you create a temporary profile: a username, optionally a gender, and up to ten interests. Your profile is visible to anyone who is online at the same time: it can appear in their random list of people online, and in their searches for one of your interests. It is held only in the server's memory, never written to disk, and deleted when you log off, when you close or reload the page, after 30 minutes without activity, 5 minutes after your connection drops, or when the server restarts.</p>
<p>Other people can see, remember or copy what your profile shows while you are online; we cannot delete what they saw. Gender is optional. It, and your interests, can reveal sensitive information about you (for example that you are transgender, or your religion, health or orientation). Only add what you are comfortable showing to strangers, and nothing that identifies you.</p>
<p>The server refuses usernames containing certain reserved words (such as "admin" or "emberline") and may refuse words on a block list in usernames and interests. These checks run in memory when you create a profile; nothing is logged.</p>
<h2>Requests and chats</h2>
<p>Nobody can write to you until you accept their request. A request carries a short message, which is end-to-end encrypted like chat messages: the server holds it, encrypted, for up to 10 minutes until it is accepted, declined or expires, and cannot read it. A declined request looks to the sender exactly like one that wasn't answered.</p>
<p>For the rest of your session the server also keeps, in memory: whether you accept requests, who you blocked, and who did not answer your requests (you can't ask them again that session). All of it is deleted with your profile.</p>
<p>When a chat ends, it is removed from your list; the other person keeps their copy on their screen until they close it.</p>
<h2>Reports</h2>
<p>When you report someone, we record the report timestamp, the reason category, the reported person's username, and — only if you choose to write it — up to 500 characters of free-text details. If you choose to attach the request message that person sent you, it is recorded too, marked as unverified: because of the encryption, we cannot check that it is what they actually sent. No chat messages are attached, and no IP address or information about you is recorded with the report. Please do not include personal information in the details. Reports are retained for a maximum of 90 days.</p>
<h2>IP addresses</h2>
<p>We do not log IP addresses in association with chat content, profiles, reports, or any durable user record. An IP-based abuse defense runs at the connection layer: when a client trips a rate limit, floods the server with messages, fails a proof-of-work check, hits a honeypot, or tries to connect from another website, an entry is written to an abuse log containing only a timestamp, the triggered rule, and the source IP. The same log records when an IP is banned. Separately, to enforce rate limits and the limit of five profiles per network at a time, the server keeps IP addresses in memory while you are connected and for up to two hours afterwards (24 hours for a banned IP); this is never written to disk. The abuse log feeds a ban system that temporarily blocks repeat offenders and is rotated after 90 days. It is never cross-referenced against reports, profiles, or conversations — and cannot be, because none of those are stored. This is the minimum defense a fully anonymous service requires to remain functional.</p>
<h2>Hosting</h2>
<p>Emberline is reached through a virtual server we rent from a hosting provider in Switzerland. It terminates the HTTPS connection and forwards the traffic through an encrypted tunnel to the server that runs Emberline, also in Switzerland. Because it sits in the connection path, the provider's infrastructure necessarily handles your IP address and the traffic passing through — for chat messages and requests, only end-to-end encrypted data. Access logging is disabled on this server. The provider only supplies the infrastructure; we share no data with it for any other purpose. Both servers are located in Switzerland.</p>
<h2>End-to-end encryption</h2>
<p>Requests and chat messages are encrypted on your device using the NaCl box construction (Curve25519 + XSalsa20 + Poly1305). Only the two participants can decrypt them. The server relays encrypted data it cannot read. In an AI chat, the AI is the other participant (see below).</p>
<h2>AI chat</h2>
<p>You can choose to chat with an AI instead of a person. This only happens if you start it, and an AI chat is labeled as such for its entire duration. The AI is a language model running on hardware operated by Emberline. It is the other participant in the conversation, so to reply it decrypts your messages and receives your profile: your username, your gender if you chose to show one, and your interests as conversation topics. AI conversations are held in memory only while the chat lasts; they are not stored, logged, or used to train models. The AI can be wrong or say strange things — do not rely on it for advice, and do not share personal information with it.</p>
<h2>Cookies, tracking, and storage</h2>
<p>We use no cookies, no analytics, no tracking pixels, and no third-party services in your browser. We do not use localStorage, sessionStorage, or any other form of persistent client-side storage: your profile, requests and chats exist only in the open page. If you open Emberline in a second tab of the same browser, that tab can take over your session; the two tabs hand it over directly in memory, and nothing is stored. All fonts and cryptography libraries are self-hosted — no external requests are made by your browser.</p>
<h2>Illegal content</h2>
<p>Use of Emberline to share, solicit, or facilitate illegal content — including CSAM, harassment, or content illegal under Swiss law — is strictly prohibited. We cooperate with Swiss law enforcement under the Swiss Criminal Code.</p>
<h2>Your rights under nFADP</h2>
<p>You have the right to request access to any personal data we hold about you and to request its deletion. Your profile, requests and session data are deleted automatically when you log off, and we store no messages and no session history, so there is typically nothing to disclose or delete. Reports contain the username of the person reported, which is no longer linked to anyone once their profile is gone. The one category of data that could constitute personal data about you under nFADP is the IP entries in the abuse log described above; these can be removed on request if you provide the IP and an approximate time window. Contact: <a href="mailto:contactall@emberline.ch">contactall@emberline.ch</a>.</p>
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
<meta name="color-scheme" content="dark light">
<title>Terms of Service — Emberline</title>
<link href="/fonts/fonts.css" rel="stylesheet">
<style>${POLICY_STYLE}</style>
</head>
<body>
<h1>Terms of Service</h1>
<p class="date">Effective date: ${TERMS_EFFECTIVE_DATE} &nbsp;·&nbsp; Jurisdiction: Switzerland &nbsp;·&nbsp; Governing law: Swiss Code of Obligations (OR)</p>
<div class="notice"><p>By using Emberline, you agree to these terms. If you do not agree, please do not use the platform.</p></div>
<h2>1. What Emberline is</h2>
<p>Emberline is an ephemeral chat service. You go online with a temporary profile (a username, optionally a gender, and your interests), find people who share an interest, and chat with them once they accept your request. No accounts required. No messages stored. Requests and conversations are end-to-end encrypted. Your profile, requests and chats are deleted when you log off.</p>
<h2>2. Eligibility</h2>
<p>You must be at least 18 years old to use Emberline. By creating a profile you confirm this.</p>
<h2>3. Your profile</h2>
<p>Your profile is visible to other people online. You are responsible for what it shows. Do not use a username or interests that impersonate another person or Emberline, that are illegal, hateful or sexually explicit, or that contain someone else's personal data. Emberline may refuse usernames and words without giving a reason.</p>
<h2>4. Requests and chats</h2>
<p>A request must carry a message, so the other person can decide whether to accept. Do not send requests in bulk, and respect a request that is not answered: you cannot ask the same person again in that session. You can end a chat, block a person or report them at any time.</p>
<h2>5. Prohibited conduct</h2>
<p>You agree not to transmit, solicit, share, or facilitate:</p>
<ul>
  <li>Child sexual abuse material (CSAM) or any content sexualising minors</li>
  <li>Threats of violence, harassment, stalking, or intimidation</li>
  <li>Content illegal under Swiss law or your country of residence</li>
  <li>Coordinated manipulation, deception, or fraud</li>
  <li>Automated access (bots, scrapers, scripts), other than Emberline's own clearly labeled AI chat</li>
  <li>Attempts to circumvent security or encryption mechanisms</li>
</ul>
<h2>6. CSAM — zero tolerance</h2>
<p>Any user who transmits, solicits, or facilitates CSAM will be reported to KOBIK immediately. Report directly at <a href="https://www.kobik.ch" target="_blank" rel="noopener noreferrer">www.kobik.ch</a>.</p>
<h2>7. AI chat</h2>
<p>Emberline offers an optional chat with an AI model operated by Emberline. It only starts at your request and is labeled as AI for its entire duration. AI replies are generated automatically, can be inaccurate or inappropriate, and are not advice of any kind. These terms apply to AI chats as well. The AI ends a chat if a user indicates they are under 18.</p>
<h2>8. Anonymity and its limits</h2>
<p>Emberline is designed to be anonymous. We require no accounts, store no messages, and keep profiles only while you are online. An IP-based abuse defense log is maintained for bot prevention only — see the <a href="/privacy">Privacy Policy</a> for full details. Anonymity at the technical layer does not exempt users from legal responsibility under Swiss law.</p>
<h2>9. No warranty</h2>
<p>Emberline is provided as-is without warranty of any kind. Use is at your own risk.</p>
<h2>10. Governing law</h2>
<p>These terms are governed exclusively by Swiss law. Disputes are subject to the exclusive jurisdiction of Swiss courts.</p>
<h2>11. Contact</h2>
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
// Errors — replaces Express's default handler, which logs every error's stack
// and, outside production, sends it back.
// Client errors are answered and never logged; server bugs log the stack only.
// ─────────────────────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err.status >= 400 && err.status < 500 ? err.status : 500;
  if (status === 500) console.error('[http] error:', err.stack || err);
  res.status(status).json({ error: status === 500 ? 'server error' : 'bad request' });
});

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
