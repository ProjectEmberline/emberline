// End-to-end tests: start real servers on free ports and talk to them over
// HTTP and WebSocket like a browser would. Run with
// `node --test test/server.test.js`.
//
// Two servers: `main` with production timings, and `fast`, whose request
// expiry, idle log off, reconnect grace and count ticks are shortened so
// those paths can be tested in seconds.

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
const MAX_CONNS_PER_IP = 3;    // small caps so the limit tests are fast
const MAX_PROFILES_PER_IP = 2;
const BOT_TOKEN = 'test-bot-token-' + crypto.randomBytes(8).toString('hex');
const FAST = { REQUEST_TTL_MS: 800, IDLE_WARNING_MS: 2500, IDLE_LOGOFF_MS: 4000, RECONNECT_GRACE_MS: 800, COUNTS_TICK_MS: 150 };

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

async function startServer(extraEnv) {
  const port = await freePort();
  const s = {
    HTTP: `http://127.0.0.1:${port}`, WS_URL: `ws://127.0.0.1:${port}`,
    logDir: fs.mkdtempSync(path.join(os.tmpdir(), 'emberline-test-')), output: '',
  };
  s.proc = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), LOG_DIR: s.logDir, TRUST_PROXY: '1', BAN_ALLOWLIST: '',
           MAX_CONNS_PER_IP: String(MAX_CONNS_PER_IP), MAX_PROFILES_PER_IP: String(MAX_PROFILES_PER_IP),
           BOT_TOKEN, ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  s.proc.stdout.on('data', d => { s.output += d; });
  s.proc.stderr.on('data', d => { s.output += d; });
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(s.HTTP + '/count')).ok) return s; } catch {}
    await sleep(100);
  }
  throw new Error('server did not start:\n' + s.output);
}

let main, fast, HTTP, WS_URL, logDir;

before(async () => {
  [main, fast] = await Promise.all([startServer({}), startServer(Object.fromEntries(Object.entries(FAST).map(([k, v]) => [k, String(v)])))]);
  ({ HTTP, WS_URL, logDir } = main);
});

after(() => {
  for (const s of [main, fast]) { s?.proc.kill(); if (s) fs.rmSync(s.logDir, { recursive: true, force: true }); }
});

// ── Helpers ────────────────────────────────────────────────────────────────

// Every test uses its own fake client IP (via X-Forwarded-For, trusted one
// hop) so rate limits and bans in one test can't leak into another.
let nextIp = 1;
const freshIp = () => `198.51.${100 + (nextIp >> 8)}.${nextIp++ & 255}`;
let nextName = 1;
const freshName = () => `user${nextName++}`;

async function pow(ip, srv = main) {
  const res = await fetch(srv.HTTP + '/challenge', { headers: { 'X-Forwarded-For': ip } });
  const { token, prefix, difficulty } = await res.json();
  for (let n = 0; ; n++) {
    const h = crypto.createHash('sha256').update(prefix + n).digest('hex');
    if (h.startsWith('0'.repeat(difficulty))) return { token, nonce: n };
  }
}

function client(ip, opts = {}, srv = main) {
  return new Promise((resolve, reject) => {
    const ws = new WS(srv.WS_URL, { headers: { 'X-Forwarded-For': ip }, ...opts });
    ws.ip = ip;
    ws.srv = srv;
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
const errs = ws => got(ws, 'error').map(e => e.code);

// Waits until `ws` has received `count` frames of `type`, and returns the last
async function until(ws, type, count = 1, ms = 2000) {
  for (let t = 0; t < ms; t += 20) {
    const m = got(ws, type);
    if (m.length >= count) return m[count - 1];
    await sleep(20);
  }
  throw new Error(`no ${type} (#${count}) within ${ms}ms; inbox: ${JSON.stringify(ws.inbox.map(m => m.type))}`);
}

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

// A connected socket with a profile. Returns the socket, with .id, .token, .kp
async function profile({ srv = main, name = freshName(), interests = ['chess'], gender = '', ip = freshIp() } = {}) {
  const ws = await client(ip, {}, srv);
  const kp = nacl.box.keyPair();
  tx(ws, { type: 'profile_create', name, gender, interests, pubKey: b64(kp.publicKey), ...(await pow(ip, srv)) });
  const ok = await until(ws, 'profile_ok');
  Object.assign(ws, { id: ok.id, token: ok.resumeToken, kp, name: ok.name, pub: b64(kp.publicKey) });
  return ws;
}

// Encrypts text from `a` to `b` the way the browser does
function sealed(a, b, text) {
  const nonce = nacl.randomBytes(24);
  const ct = nacl.box(Buffer.from(text, 'utf8'), nonce, Buffer.from(b.pub, 'base64'), a.kp.secretKey);
  return { ciphertext: b64(ct), nonce: b64(nonce) };
}
const opened = (b, fromPub, m) => Buffer.from(nacl.box.open(
  Buffer.from(m.ciphertext, 'base64'), Buffer.from(m.nonce, 'base64'), Buffer.from(fromPub, 'base64'), b.kp.secretKey)).toString('utf8');

async function request(a, b, text = 'hello there, fancy a chat?') {
  const nSent = got(a, 'request_sent').length, nIn = got(b, 'request_in').length;
  tx(a, { type: 'request_send', to: b.id, ...sealed(a, b, text) });
  const sent = await until(a, 'request_sent', nSent + 1);
  const inb = await until(b, 'request_in', nIn + 1);
  return { requestId: sent.requestId, inb };
}

async function chatPair(opts = {}) {
  const a = await profile(opts), b = await profile(opts);
  const { requestId } = await request(a, b);
  tx(b, { type: 'request_answer', requestId, accept: true });
  const ca = await until(a, 'chat_open'), cb = await until(b, 'chat_open');
  assert.equal(ca.chatId, cb.chatId);
  a.chatId = b.chatId = ca.chatId;
  return [a, b];
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
  const js = await (await fetch(HTTP + '/app.js')).text();
  assert.ok(!/\sstyle=\\?"/.test(js), 'no inline style attributes built by the script either');
});

test('a malformed report gets a plain 400: no stack trace sent or logged', async () => {
  const res = await fetch(HTTP + '/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': freshIp() },
    body: '{"reason":"spam","details":"my name is Alice" x}',
  });
  assert.equal(res.status, 400);
  const body = await res.text();
  assert.doesNotMatch(body, /SyntaxError|node_modules|Alice/);
  await sleep(100);
  assert.doesNotMatch(main.output, /SyntaxError|Alice/);
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

// ── Profiles ───────────────────────────────────────────────────────────────

test('profile: validation, reserved and unique names, interest cleanup', async () => {
  const ip = freshIp();
  const ws = await client(ip);
  const create = (o) => tx(ws, { type: 'profile_create', name: freshName(), gender: '', interests: ['chess'], pubKey: pubKey(), ...o });
  create({ name: 'ab', ...(await pow(ip)) }); await sleep(100);        // too short; the PoW is spent either way
  create({ name: 'TheAdminGuy' }); await sleep(100);
  create({ gender: 'robot' }); await sleep(100);
  create({ interests: ['!!', '_'] }); await sleep(100);
  create({ interests: Array.from({ length: 11 }, (_, i) => 'topic' + i) }); await sleep(100);
  create({ pubKey: 'AAAA' }); await sleep(100);
  assert.deepEqual(errs(ws), ['name_invalid', 'name_reserved', 'gender_invalid', 'interests_invalid', 'interests_invalid', 'invalid_key']);

  ws.inbox = [];
  create({ name: 'Nightowl', gender: 'trans woman (MtF)', interests: ['Käse', 'board games', 'käse', '-rock-'] });
  const ok = await until(ws, 'profile_ok');
  assert.deepEqual(ok.interests, ['käse', 'boardgames', 'rock']);
  assert.equal(ok.gender, 'trans woman (MtF)');

  const other = await client(freshIp());
  tx(other, { type: 'profile_create', name: 'NIGHTOWL', gender: '', interests: ['x1'], pubKey: pubKey(), ...(await pow(other.ip)) });
  await sleep(150);
  assert.deepEqual(errs(other), ['name_taken'], 'unique regardless of case');
  tx(ws, { type: 'logoff' }); await until(ws, 'logged_off');
  tx(other, { type: 'profile_create', name: 'NIGHTOWL', gender: '', interests: ['x1'], pubKey: pubKey() });
  await until(other, 'profile_ok');
  ws.close(); other.close();
});

test('profile: at most MAX_PROFILES_PER_IP at the same time', async () => {
  const ip = freshIp();
  const a = await profile({ ip }), b = await profile({ ip });
  const c = await client(ip);
  tx(c, { type: 'profile_create', name: freshName(), gender: '', interests: ['chess'], pubKey: pubKey(), ...(await pow(ip)) });
  await sleep(150);
  assert.deepEqual(errs(c), ['too_many_profiles']);
  tx(a, { type: 'logoff' }); await until(a, 'logged_off');
  tx(c, { type: 'profile_create', name: freshName(), gender: '', interests: ['chess'], pubKey: pubKey() });
  await until(c, 'profile_ok');
  for (const s of [a, b, c]) s.close();
});

test('the honeypot interest bans the IP', async () => {
  const ip = freshIp();
  const ws = await client(ip);
  tx(ws, { type: 'profile_create', name: freshName(), gender: '', interests: ['chess', '__honeypot__'], pubKey: pubKey(), ...(await pow(ip)) });
  await sleep(150);
  assert.equal(ws.closeCode, 1008);
  assert.equal((await fetch(HTTP + '/count', { headers: { 'X-Forwarded-For': ip } })).status, 403);
});

test('search: random sample by interest, never yourself; counts are rounded', async () => {
  const people = [];
  for (let i = 0; i < 4; i++) people.push(await profile({ interests: ['searchtopic', 'x' + i] }));
  const me = people[0];
  tx(me, { type: 'search', interest: 'SearchTopic' });
  const res = await until(me, 'results');
  assert.equal(res.interest, 'searchtopic');
  assert.equal(res.people.length, 3);
  assert.ok(!res.people.some(p => p.id === me.id), 'not yourself');
  assert.deepEqual(Object.keys(res.people[0]).sort(), ['accepting', 'askedBefore', 'gender', 'id', 'interests', 'name', 'pubKey']);
  assert.equal(res.bucket, '1–4');

  tx(me, { type: 'counts_watch', on: true, interests: ['nobodyhere'] });
  const counts = await until(me, 'counts');
  assert.equal(counts.buckets.searchtopic, '1–4');
  assert.equal(counts.buckets.nobodyhere, '0');
  assert.ok(Array.isArray(counts.top));
  people.forEach(s => s.close());
});

test('counts are pushed again only when a bucket changes', async () => {
  const me = await profile({ srv: fast, interests: ['tickwatch'] });
  tx(me, { type: 'counts_watch', on: true, interests: [] });
  await until(me, 'counts');
  await sleep(400);
  assert.equal(got(me, 'counts').length, 1, 'no change, no push');
  const more = [];
  for (let i = 0; i < 4; i++) more.push(await profile({ srv: fast, interests: ['tickwatch'] }));
  const c = await until(me, 'counts', 2);
  assert.equal(c.buckets.tickwatch, '5–9');
  tx(me, { type: 'counts_watch', on: false });
  for (const s of [...more, me]) { tx(s, { type: 'logoff' }); s.close(); }
});

// ── Requests ───────────────────────────────────────────────────────────────

test('request → accept → end-to-end encrypted chat', async () => {
  const a = await profile(), b = await profile();
  const { requestId, inb } = await request(a, b, 'Hi! Want to talk about chess?');
  assert.equal(inb.from.id, a.id);
  assert.equal(opened(b, inb.from.pubKey, inb), 'Hi! Want to talk about chess?');

  tx(b, { type: 'request_answer', requestId, accept: true });
  const ca = await until(a, 'chat_open'), cb = await until(b, 'chat_open');
  assert.equal(ca.requestId, requestId);
  assert.equal(ca.partner.id, b.id);
  assert.equal(cb.partner.id, a.id);

  const text = '漢'.repeat(300);
  tx(a, { type: 'chat_message', chatId: ca.chatId, ...sealed(a, b, text) });
  const m = await until(b, 'chat_message');
  assert.equal(opened(b, a.pub, m), text, 'a 300-character CJK message arrives intact');
  tx(a, { type: 'chat_message', chatId: ca.chatId, ciphertext: 'A'.repeat(1300), nonce: m.nonce });
  tx(b, { type: 'chat_typing', chatId: ca.chatId });
  await until(a, 'chat_typing');
  assert.ok(errs(a).includes('message_rejected'), 'oversized frame rejected, not truncated');
  a.close(); b.close();
});

test('message bursts are delivered; excess gets an explicit error', async () => {
  const [a, b] = await chatPair();
  for (let i = 0; i < 6; i++) tx(a, { type: 'chat_message', chatId: a.chatId, ...sealed(a, b, 'm' + i) });
  await sleep(150);
  assert.equal(got(b, 'chat_message').length, 5);
  assert.ok(errs(a).includes('rate_limited'));
  await sleep(400);
  tx(a, { type: 'chat_message', chatId: a.chatId, ...sealed(a, b, 'after refill') });
  await until(b, 'chat_message', 6);
  a.close(); b.close();
});

test('requests: 5 a minute, no duplicates, not while chatting, not when switched off', async () => {
  const a = await profile();
  const targets = [];
  for (let i = 0; i < 6; i++) targets.push(await profile());
  for (let i = 0; i < 5; i++) await request(a, targets[i]);
  tx(a, { type: 'request_send', to: targets[5].id, ...sealed(a, targets[5], 'one too many') });
  await sleep(100);
  assert.ok(errs(a).includes('rate_limited'));

  const b = await profile(), c = await profile();
  const { requestId } = await request(b, c);
  tx(c, { type: 'request_send', to: b.id, ...sealed(c, b, 'and back to you') }); await sleep(100);
  assert.deepEqual(errs(c), ['already_pending']);
  tx(c, { type: 'request_answer', requestId, accept: true }); await until(b, 'chat_open');
  tx(b, { type: 'request_send', to: c.id, ...sealed(b, c, 'again while chatting') }); await sleep(100);
  assert.deepEqual(errs(b), ['already_chatting']);

  const d = await profile(), e = await profile();
  tx(e, { type: 'set_accepting', on: false }); await until(e, 'accepting');
  tx(d, { type: 'request_send', to: e.id, ...sealed(d, e, 'are you there?') }); await sleep(100);
  assert.deepEqual(errs(d), ['not_accepting']);
  tx(d, { type: 'request_send', to: e.id, ...sealed(d, e, 'x'), ciphertext: 'A'.repeat(900) }); await sleep(100);
  assert.ok(errs(d).includes('message_rejected'), 'request over 200 characters rejected');
  for (const s of [a, ...targets, b, c, d, e]) s.close();
});

test('a decline looks exactly like no answer; no second request this session', async () => {
  const a = await profile({ srv: fast }), b = await profile({ srv: fast }), c = await profile({ srv: fast });
  const rb = await request(a, b), rc = await request(a, c);
  tx(b, { type: 'request_answer', requestId: rb.requestId, accept: false });   // declined
  await sleep(200);                                                             // c never answers
  const before = a.inbox.length;
  const t0 = Date.now();
  await until(a, 'request_expired', 2, 2000);
  assert.ok(Date.now() - t0 < 1000, 'both expire on the timer');
  const frames = a.inbox.slice(before);
  assert.deepEqual(frames.map(f => f.type), ['request_expired', 'request_expired'], 'nothing else reaches the sender');
  assert.deepEqual(frames.map(f => f.requestId).sort(), [rb.requestId, rc.requestId].sort());
  assert.equal(got(b, 'request_gone').length, 0, 'b already declined it');
  assert.equal(got(c, 'request_gone').length, 1, 'c sees it go');

  tx(a, { type: 'request_send', to: b.id, ...sealed(a, b, 'please answer me') }); await sleep(100);
  assert.deepEqual(errs(a), ['asked_before']);
  tx(a, { type: 'search', interest: 'chess' });
  const res = await until(a, 'results');
  assert.equal(res.people.find(p => p.id === b.id)?.askedBefore, true);
  tx(b, { type: 'request_send', to: a.id, ...sealed(b, a, 'my turn now then') });
  await until(a, 'request_in');   // the other way round is still fine
  for (const s of [a, b, c]) { tx(s, { type: 'logoff' }); s.close(); }
});

test('withdrawing a request removes it for the recipient', async () => {
  const a = await profile(), b = await profile();
  const { requestId } = await request(a, b);
  tx(a, { type: 'request_withdraw', requestId });
  const gone = await until(b, 'request_gone');
  assert.equal(gone.requestId, requestId);
  a.close(); b.close();
});

// ── Chats, blocks, log off ─────────────────────────────────────────────────

test('ending a chat leaves the partner a read-only copy; a new request is allowed', async () => {
  const [a, b] = await chatPair();
  tx(a, { type: 'chat_end', chatId: a.chatId });
  const ended = await until(b, 'chat_ended');
  assert.deepEqual(ended, { type: 'chat_ended', chatId: a.chatId, reason: 'ended' });
  tx(b, { type: 'chat_message', chatId: b.chatId, ...sealed(b, a, 'still there?') }); await sleep(100);
  assert.ok(errs(b).includes('chat_closed'));
  await request(a, b, 'sorry, let us talk again');
  a.close(); b.close();
});

test('block: ends the chat, hides both ways, looks like offline', async () => {
  const [a, b] = await chatPair({ interests: ['blocktopic'] });
  tx(b, { type: 'block', profileId: a.id });
  await until(a, 'chat_ended');
  tx(a, { type: 'search', interest: 'blocktopic' });
  const ra = await until(a, 'results');
  assert.ok(!ra.people.some(p => p.id === b.id), 'blocked person hidden from the blocked');
  tx(b, { type: 'search', interest: 'blocktopic' });
  const rb = await until(b, 'results');
  assert.ok(!rb.people.some(p => p.id === a.id), 'and from the blocker');
  tx(a, { type: 'request_send', to: b.id, ...sealed(a, b, 'why did you go?') }); await sleep(100);
  assert.deepEqual(errs(a), ['offline'], 'indistinguishable from logged off');
  a.close(); b.close();
});

test('log off deletes everything at once and tells the other side', async () => {
  const [a, b] = await chatPair();
  const c = await profile();
  const { requestId } = await request(a, c);
  tx(a, { type: 'logoff' });
  assert.equal((await until(a, 'logged_off')).reason, 'logoff');
  assert.deepEqual(await until(b, 'chat_ended'), { type: 'chat_ended', chatId: b.chatId, reason: 'logged_off' });
  assert.equal((await until(c, 'request_gone')).requestId, requestId);
  const again = await client(freshIp());
  tx(again, { type: 'profile_create', name: a.name, gender: '', interests: ['chess'], pubKey: pubKey(), ...(await pow(again.ip)) });
  await until(again, 'profile_ok');
  for (const s of [a, b, c, again]) s.close();
});

test('an unclean drop keeps the profile for the grace period; resume restores it', async () => {
  const [a, b] = await chatPair({ srv: fast });
  a.terminate();
  await until(b, 'partner_reconnecting');
  const a2 = await client(freshIp(), {}, fast);
  tx(a2, { type: 'resume', resumeToken: a.token });
  const ok = await until(a2, 'profile_ok');
  assert.equal(ok.id, a.id);
  assert.notEqual(ok.resumeToken, a.token, 'token rotates');
  const state = await until(a2, 'state');
  assert.deepEqual(state.chats.map(c => c.chatId), [a.chatId]);
  await until(b, 'partner_back');

  tx(a2, { type: 'resume', resumeToken: a.token }); // the old token is spent
  const a3 = await client(freshIp(), {}, fast);
  tx(a3, { type: 'resume', resumeToken: a.token }); await sleep(100);
  assert.deepEqual(errs(a3), ['resume_failed']);

  a2.terminate();
  assert.equal((await until(b, 'chat_ended', 1, 3000)).reason, 'logged_off', 'deleted after the grace period');
  for (const s of [b, a3]) { tx(s, { type: 'logoff' }); s.close(); }
});

test('newest tab wins: resuming from a second socket closes the first', async () => {
  const a = await profile({ srv: fast });
  const tab2 = await client(freshIp(), {}, fast);
  tx(tab2, { type: 'resume', resumeToken: a.token });
  await until(tab2, 'profile_ok');
  await until(a, 'replaced');
  await sleep(100);
  assert.equal(a.closeCode, 4001);
  tx(tab2, { type: 'logoff' }); tab2.close();
});

test('idle: a warning, then log off; activity resets the timer', async () => {
  const a = await profile({ srv: fast }), b = await profile({ srv: fast });
  await until(a, 'idle_warning', 1, 4000);
  tx(a, { type: 'still_here' });
  await until(b, 'idle_warning', 1, 1500);
  assert.equal((await until(b, 'logged_off', 1, 3000)).reason, 'idle');
  assert.equal(got(a, 'logged_off').length, 0, 'still here');
  tx(a, { type: 'logoff' }); a.close(); b.close();
});

test('everything is released once all profiles are gone', async () => {
  // Earlier fast-server tests logged everyone off or let them time out
  await sleep(4500);
  assert.equal((await (await fetch(fast.HTTP + '/count')).json()).count, 0);
});

test('a report records the reported name and reason, never the reporter', async () => {
  const [a, b] = await chatPair();
  tx(a, { type: 'report', profileId: b.id, reason: 'harassment', details: 'rude <b>', requestText: 'the text they sent' });
  await until(a, 'report_ok');
  const line = fs.readFileSync(path.join(logDir, 'reports.log'), 'utf8').trim().split('\n').pop();
  const entry = JSON.parse(line);
  assert.equal(entry.reported, b.name);
  assert.equal(entry.reason, 'harassment');
  assert.equal(entry.details, 'rude b');
  assert.equal(entry.requestTextUnverified, 'the text they sent');
  assert.ok(!line.includes(a.ip) && !line.includes(a.name), 'nothing about the reporter');
  a.close(); b.close();
});

// ── Abuse limits ───────────────────────────────────────────────────────────

test('connection slots are released only by closing', async () => {
  const ip = freshIp();
  const held = [];
  for (let i = 0; i < MAX_CONNS_PER_IP; i++) {
    const s = await client(ip);
    tx(s, { type: 'logoff' });
    held.push(s);
  }
  await sleep(150);
  const extra = await client(ip);
  await sleep(150);
  assert.equal(extra.closeCode, 4429, 'over the cap');

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
  for (let i = 0; i < 100; i++) tx(ws, { type: 'chat_typing' });
  await sleep(150);
  assert.equal(ws.closeCode, 1008);
  assert.equal(abuseLines(ws.ip).filter(l => l.includes('[ws_flood]')).length, 1);
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

// ── AI chat ────────────────────────────────────────────────────────────────

function bot(token = BOT_TOKEN) {
  return client(freshIp(), { headers: { Authorization: `Bearer ${token}` } });
}
const countInfo = async () => (await fetch(HTTP + '/count')).json();

test('AI chat: on request only, labeled, bots never counted as people', async () => {
  const h = await profile({ interests: ['aitopic', 'music'], gender: 'non-binary' });
  const before = await countInfo();
  const b = await bot();
  const botKp = nacl.box.keyPair();
  tx(b, { type: 'bot_ready', pubKey: b64(botKp.publicKey) }); await sleep(100);
  const withBot = await countInfo();
  assert.equal(withBot.ai, true, 'AI offered once a bot is ready');
  assert.equal(withBot.count, before.count, 'bot not counted');

  tx(h, { type: 'ai_start' });
  const open = await until(h, 'chat_open');
  const bm = await until(b, 'matched');
  assert.equal(open.ai, true, 'labeled as AI');
  assert.equal(open.partner.pubKey, b64(botKp.publicKey));
  assert.equal(bm.ai, true);
  assert.deepEqual(bm.keywords, ['aitopic', 'music'], 'the bot gets the interests as topics');
  assert.equal(bm.name, h.name, 'and the username');
  assert.equal(bm.gender, 'non-binary', 'and the gender');
  assert.equal(bm.partnerPubKey, h.pub);
  assert.equal((await countInfo()).ai, false, 'busy bot is not offered');

  tx(h, { type: 'ai_start' }); await sleep(100);
  assert.ok(errs(h).includes('ai_already_open'));

  // Relay both ways, in the bot's old frame format
  const nonce = nacl.randomBytes(24);
  tx(b, { type: 'message', ciphertext: b64(nacl.box(Buffer.from('hello from the AI'), nonce, Buffer.from(h.pub, 'base64'), botKp.secretKey)), nonce: b64(nonce) });
  const m = await until(h, 'chat_message');
  assert.equal(m.chatId, open.chatId);
  assert.equal(opened(h, b64(botKp.publicKey), m), 'hello from the AI');
  tx(h, { type: 'chat_message', chatId: open.chatId, ...sealed(h, { pub: b64(botKp.publicKey) }, 'hi') });
  await until(b, 'message');
  tx(b, { type: 'typing' });
  await until(h, 'chat_typing');

  tx(h, { type: 'chat_end', chatId: open.chatId });
  await until(b, 'partner_left');
  assert.equal((await countInfo()).ai, false, 'free again only after it re-offers');
  tx(b, { type: 'bot_ready', pubKey: pubKey() }); await sleep(100);
  assert.equal((await countInfo()).ai, true);

  // The bot ending the chat closes it for the person
  tx(h, { type: 'ai_start' });
  const open2 = await until(h, 'chat_open', 2, 4000);
  await until(b, 'matched', 2);
  tx(b, { type: 'leave' });
  assert.equal((await until(h, 'chat_ended')).chatId, open2.chatId);
  b.close(); h.close(); await sleep(100);
  assert.equal((await countInfo()).ai, false, 'disconnected bot is not offered');
});

test('AI chat: wrong token is an ordinary client; no bot means unavailable', async () => {
  const fake = await bot('wrong-token');
  tx(fake, { type: 'bot_ready', pubKey: pubKey() }); await sleep(100);
  assert.equal((await countInfo()).ai, false, 'unauthenticated bot_ready ignored');

  const loose = await client(freshIp());
  tx(loose, { type: 'ai_start' }); await sleep(100);
  assert.equal(loose.inbox.length, 0, 'no profile, no AI');

  const h = await profile();
  tx(h, { type: 'ai_start' }); await sleep(100);
  assert.deepEqual(errs(h), ['ai_unavailable']);
  fake.close(); loose.close(); h.close();
});
