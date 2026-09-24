// End-to-end tests: start a real server on a free port and talk to it over
// HTTP and WebSocket like a browser would. Run with `npm test`.

'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const WS = require('ws');
const nacl = require('tweetnacl');

const ROOT = path.join(__dirname, '..');
const MAX_CONNS_PER_IP = 3; // small cap so the connection-limit test is fast
const BOT_TOKEN = 'test-bot-token-' + crypto.randomBytes(8).toString('hex');

let server, logDir, HTTP, WS_URL;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const b64 = u => Buffer.from(u).toString('base64');
const pubKey = () => b64(nacl.box.keyPair().publicKey);

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer().listen(0, () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    }).on('error', reject);
  });
}

before(async () => {
  const port = await freePort();
  HTTP   = `http://127.0.0.1:${port}`;
  WS_URL = `ws://127.0.0.1:${port}`;
  logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'emberline-test-'));
  server = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), LOG_DIR: logDir, TRUST_PROXY: '1',
           MAX_CONNS_PER_IP: String(MAX_CONNS_PER_IP), BAN_ALLOWLIST: '', BOT_TOKEN },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  server.stdout.on('data', d => { output += d; });
  server.stderr.on('data', d => { output += d; });
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(HTTP + '/count')).ok) return; } catch {}
    await sleep(100);
  }
  throw new Error('server did not start:\n' + output);
});

after(() => {
  server?.kill();
  fs.rmSync(logDir, { recursive: true, force: true });
});

// ── Helpers ────────────────────────────────────────────────────────────────

// Every test uses its own fake client IP (via X-Forwarded-For, trusted one
// hop) so rate limits and bans in one test can't leak into another.
let nextIp = 1;
const freshIp = () => `198.51.100.${nextIp++}`;

async function pow(ip) {
  const res = await fetch(HTTP + '/challenge', { headers: { 'X-Forwarded-For': ip } });
  const { token, prefix, difficulty } = await res.json();
  for (let n = 0; ; n++) {
    const h = crypto.createHash('sha256').update(prefix + n).digest('hex');
    if (h.startsWith('0'.repeat(difficulty))) return { token, nonce: n };
  }
}

function client(ip, opts = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WS(WS_URL, { headers: { 'X-Forwarded-For': ip }, ...opts });
    ws.ip = ip;
    ws.inbox = [];
    ws.closeCode = null;
    ws.on('message', d => ws.inbox.push(JSON.parse(d)));
    ws.on('close', code => { ws.closeCode = code; });
    ws.on('open', () => resolve(ws));
    ws.on('error', reject);
  });
}

const tx  = (ws, obj) => ws.send(JSON.stringify(obj));
const got = (ws, type) => ws.inbox.filter(m => m.type === type);

// abuse.log lines for one IP (endsWith, so 198.51.100.1 doesn't match .12)
const abuseLines = ip => fs.readFileSync(path.join(logDir, 'abuse.log'), 'utf8')
  .split('\n').filter(l => l.endsWith(` ip=${ip}`));

// Opens a socket and resolves once the server has closed or refused it
function refused(ip, opts = {}, onOpen) {
  return new Promise(r => {
    const w = new WS(WS_URL, { headers: { 'X-Forwarded-For': ip }, ...opts });
    if (onOpen) w.on('open', () => onOpen(w));
    w.on('error', () => {}); w.on('close', r);
  });
}

async function join(ws, keywords, { verified = false } = {}) {
  tx(ws, { type: 'join', keywords, pubKey: pubKey(), ...(verified ? {} : await pow(ws.ip)) });
  await sleep(150);
}

async function pair(keyword) {
  const a = await client(freshIp());
  const b = await client(freshIp());
  await join(a, [keyword]);
  await join(b, [keyword]);
  assert.equal(got(a, 'matched').length, 1, 'a matched');
  assert.equal(got(b, 'matched').length, 1, 'b matched');
  return [a, b];
}

// An encrypted-looking frame; the server can't and doesn't decrypt it.
function frame(text) {
  const nonce = nacl.randomBytes(24);
  const ct = nacl.secretbox(Buffer.from(text, 'utf8'), nonce, nacl.randomBytes(32));
  return { type: 'message', ciphertext: b64(ct), nonce: b64(nonce) };
}

// ── HTTP surface ───────────────────────────────────────────────────────────

test('only public/ is served; source, logs and dotfiles are not', async () => {
  for (const p of ['/', '/app.js', '/manifest.json', '/privacy', '/terms', '/count']) {
    assert.equal((await fetch(HTTP + p)).status, 200, p);
  }
  for (const p of ['/server.js', '/package.json', '/abuse.log', '/reports.log',
                   '/.git/config', '/node_modules/ws/package.json', '/sw.js']) {
    assert.equal((await fetch(HTTP + p)).status, 404, p);
  }
});

test('CSP has no unsafe-inline and allows the page style blocks by hash', async () => {
  const csp = (await fetch(HTTP + '/')).headers.get('content-security-policy');
  assert.ok(!csp.includes('unsafe-inline'));
  assert.match(csp, /style-src 'self'( 'sha256-[A-Za-z0-9+/=]+'){3}/);
  const html = (await (await fetch(HTTP + '/')).text()).replace(/<style>[\s\S]*?<\/style>/g, '');
  assert.ok(!/\sstyle="/.test(html), 'no inline style attributes');
});

test('client IP comes from the proxy-added X-Forwarded-For entry', async () => {
  // A client-supplied first entry must be ignored: the "proxy" appends the
  // real address, and only that one is trusted (TRUST_PROXY=1).
  const spoofed = '203.0.113.50', real = freshIp();
  await new Promise(r => {
    const w = new WS(WS_URL, { headers: { 'X-Forwarded-For': `${spoofed}, ${real}` }, origin: 'https://evil.example' });
    w.on('error', r); w.on('close', r);
  });
  await sleep(100);
  const log = fs.readFileSync(path.join(logDir, 'abuse.log'), 'utf8');
  assert.match(log, new RegExp(`\\[ws_origin\\] ip=${real.replace(/\./g, '\\.')}`));
  assert.ok(!log.includes(spoofed));
});

// ── Chat relay ─────────────────────────────────────────────────────────────

test('a 300-character CJK message is relayed intact', async () => {
  const [a, b] = await pair('cjk');
  const f = frame('漢'.repeat(300));
  tx(a, f); await sleep(150);
  assert.equal(got(b, 'message')[0]?.ciphertext, f.ciphertext);
  tx(a, { type: 'message', ciphertext: 'A'.repeat(1300), nonce: f.nonce }); await sleep(100);
  assert.ok(got(a, 'error').some(e => e.code === 'message_rejected'), 'oversized frame rejected, not truncated');
  a.close(); b.close();
});

test('message bursts are delivered; excess gets an explicit error', async () => {
  const [a, b] = await pair('burst');
  for (let i = 0; i < 6; i++) tx(a, frame('m' + i));
  await sleep(150);
  assert.equal(got(b, 'message').length, 5);
  assert.ok(got(a, 'error').some(e => e.code === 'rate_limited'));
  await sleep(400);
  tx(a, frame('after refill')); await sleep(100);
  assert.equal(got(b, 'message').length, 6);
  a.close(); b.close();
});

test('join while in a room is ignored; Next → still works', async () => {
  const [a, b] = await pair('rooms');
  const c = await client(freshIp());
  await join(c, ['other']);
  a.inbox = [];
  await join(a, ['other', '__random__'], { verified: true });
  assert.equal(got(a, 'matched').length + got(a, 'waiting').length, 0, 'second join ignored');
  assert.equal(got(c, 'matched').length, 0);

  tx(a, { type: 'leave' }); await sleep(100);
  assert.equal(got(b, 'partner_left').length, 1);
  await join(b, ['other'], { verified: true });
  assert.equal(got(b, 'matched').length, 2, 'left-behind partner can match again');
  for (const s of [a, b, c]) s.close();
});

test('malformed public keys are rejected at join', async () => {
  const ws = await client(freshIp());
  tx(ws, { type: 'join', keywords: ['badkey'], pubKey: 'AAAA', ...(await pow(ws.ip)) });
  await sleep(150);
  assert.ok(got(ws, 'error').some(e => e.code === 'invalid_key'));
  assert.equal(got(ws, 'waiting').length, 0);
  ws.close();
});

test('re-joining while waiting keeps the place in line', async () => {
  const a = await client(freshIp()), c = await client(freshIp()), d = await client(freshIp());
  await join(a, ['alpha']);
  await join(c, ['gamma']);
  await join(a, ['alpha', 'omega'], { verified: true }); // random-fallback style re-join
  await join(d, ['omega', 'gamma']);                    // a and c tie; oldest must win
  assert.equal(got(a, 'matched').length, 1);
  assert.equal(got(c, 'matched').length, 0);
  for (const s of [a, c, d]) s.close();
});

// ── Abuse limits ───────────────────────────────────────────────────────────

test("'leave' does not free a connection slot; closing does", async () => {
  const ip = freshIp();
  const held = [];
  for (let i = 0; i < MAX_CONNS_PER_IP; i++) {
    const s = await client(ip);
    tx(s, { type: 'leave' });
    held.push(s);
  }
  await sleep(150);
  const extra = await client(ip);
  await sleep(150);
  assert.equal(extra.closeCode, 4429, 'over the cap despite leave');

  held.forEach(s => s.close());
  await sleep(150);
  const again = await client(ip);
  await sleep(150);
  assert.equal(again.readyState, WS.OPEN, 'slot freed after real close');
  again.close();
});

test('an oversized frame on a refused connection does not crash the server', async () => {
  const ip = freshIp();
  const held = [];
  for (let i = 0; i < MAX_CONNS_PER_IP; i++) held.push(await client(ip));
  await refused(ip, {}, w => w.send('x'.repeat(10_000))); // over the cap, then > maxPayload
  await sleep(100);
  assert.equal((await fetch(HTTP + '/count')).status, 200, 'server still running');
  held.forEach(s => s.close());
});

test('a frame flood closes the socket and counts as one strike', async () => {
  const ws = await client(freshIp());
  for (let i = 0; i < 100; i++) tx(ws, { type: 'typing' });
  await sleep(150);
  assert.equal(ws.closeCode, 1008);
  assert.equal(abuseLines(ws.ip).filter(l => l.includes('[ws_flood]')).length, 1);
});

test('joins are paced per socket; the retry after retryMs goes through', async () => {
  const ws = await client(freshIp());
  await join(ws, ['pace1']);
  for (let i = 2; i <= 5; i++) await join(ws, ['pace' + i], { verified: true });
  ws.inbox = [];
  await join(ws, ['pace6'], { verified: true });
  const slow = got(ws, 'error').find(e => e.code === 'slow_down');
  assert.ok(slow?.retryMs > 0 && slow.retryMs <= 3000, 'sixth join in a row is paced');
  assert.equal(got(ws, 'waiting').length, 0);
  await sleep(slow.retryMs);
  await join(ws, ['pace6'], { verified: true });
  assert.equal(got(ws, 'waiting').length, 1);
  ws.close();
});

test('rate-limit hits alone never ban a busy shared IP', async () => {
  const ip = freshIp();
  const opt = { headers: { 'X-Forwarded-For': ip } };
  const held = [];
  for (let i = 0; i < MAX_CONNS_PER_IP; i++) held.push(await client(ip));
  for (let i = 0; i < 25; i++) await refused(ip);                  // conn cap, then connect rate
  for (let i = 0; i < 70; i++) await fetch(HTTP + '/terms', opt);  // API budget
  assert.equal((await fetch(HTTP + '/count', opt)).status, 200, 'not banned');
  assert.equal(abuseLines(ip).length, 1, 'one strike per minute');
  held.forEach(s => s.close());
});

test('/count polling does not use the API budget', async () => {
  const opt = { headers: { 'X-Forwarded-For': freshIp() } };
  for (let i = 0; i < 70; i++) assert.equal((await fetch(HTTP + '/count', opt)).status, 200);
  assert.equal((await fetch(HTTP + '/challenge', opt)).status, 200);
});

test('repeated abuse bans the IP for HTTP and WebSocket only', async () => {
  const spam = freshIp(), bystander = freshIp();
  for (let i = 0; i < 21; i++) {
    await new Promise(r => {
      const w = new WS(WS_URL, { headers: { 'X-Forwarded-For': spam }, origin: 'https://evil.example' });
      w.on('error', r); w.on('close', r);
    });
  }
  const status = async ip => (await fetch(HTTP + '/count', { headers: { 'X-Forwarded-For': ip } })).status;
  assert.equal(await status(spam), 403);
  assert.equal(await status(bystander), 200);
  await assert.rejects(client(spam), 'WebSocket upgrade refused');
  assert.match(fs.readFileSync(path.join(logDir, 'abuse.log'), 'utf8'), new RegExp(`\\[banned\\] ip=${spam.replace(/\./g, '\\.')}`));
});

// ── Optional AI chat ───────────────────────────────────────────────────────

function bot(token = BOT_TOKEN) {
  return client(freshIp(), { headers: { Authorization: `Bearer ${token}` } });
}
const countInfo = async () => (await fetch(HTTP + '/count')).json();

test('AI chat: opt-in only, always labeled, bots never counted as people', async () => {
  const before = await countInfo();
  const b = await bot();
  tx(b, { type: 'bot_ready', pubKey: pubKey() }); await sleep(100);
  const withBot = await countInfo();
  assert.equal(withBot.ai, true, 'AI offered once a bot is ready');
  assert.equal(withBot.count, before.count, 'bot not counted as an ember');

  // A human who only searches by keyword is never matched with the bot
  const h = await client(freshIp());
  await join(h, ['aitopic', 'music']);
  assert.equal(got(h, 'matched').length, 0);
  assert.equal(got(h, 'waiting').length, 1);

  // Opting in matches with the bot; both sides are told it is an AI chat
  tx(h, { type: 'join_ai', pubKey: pubKey() }); await sleep(150);
  const hm = got(h, 'matched')[0], bm = got(b, 'matched')[0];
  assert.equal(hm?.ai, true, 'human sees ai: true');
  assert.equal(bm?.ai, true);
  assert.deepEqual(bm.keywords, ['aitopic', 'music'], 'bot gets the keywords as topics');
  assert.equal((await countInfo()).ai, false, 'busy bot is not offered');

  // Relay works both ways; leaving frees the bot only after it re-offers
  tx(b, frame('hello from the AI')); tx(h, frame('hi')); await sleep(150);
  assert.equal(got(h, 'message').length, 1);
  assert.equal(got(b, 'message').length, 1);
  tx(h, { type: 'leave' }); await sleep(100);
  assert.equal(got(b, 'partner_left').length, 1);
  assert.equal((await countInfo()).ai, false);
  tx(b, { type: 'bot_ready', pubKey: pubKey() }); await sleep(100);
  assert.equal((await countInfo()).ai, true);
  b.close(); h.close(); await sleep(100);
  assert.equal((await countInfo()).ai, false, 'disconnected bot is not offered');
});

test('AI chat: wrong token is an ordinary client; join_ai needs a bot and a verified socket', async () => {
  const fake = await bot('wrong-token');
  tx(fake, { type: 'bot_ready', pubKey: pubKey() }); await sleep(100);
  assert.equal((await countInfo()).ai, false, 'unauthenticated bot_ready ignored');

  const h = await client(freshIp());
  tx(h, { type: 'join_ai', pubKey: pubKey() }); await sleep(100);
  assert.equal(got(h, 'matched').length + got(h, 'error').length, 0, 'unverified join_ai ignored');

  await join(h, ['nobots']);
  tx(h, { type: 'join_ai', pubKey: pubKey() }); await sleep(100);
  assert.ok(got(h, 'error').some(e => e.code === 'ai_unavailable'));
  assert.equal(got(h, 'matched').length, 0);
  fake.close(); h.close();
});
