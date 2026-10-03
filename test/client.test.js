// Tests for the page itself (public/index.html + public/app.js): two real
// pages, loaded in jsdom, talk to a real server and go through a whole visit:
// go online, find each other, request, accept, chat, log off.
// Run with `node --test test/client.test.js`.

'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { webcrypto } = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { JSDOM, VirtualConsole } = require('jsdom');

const ROOT = path.join(__dirname, '..');
const sleep = ms => new Promise(r => setTimeout(r, ms));

// The NaCl libraries the page loads from /vendor are copied there by
// setup-assets.js; the tests take them straight from node_modules instead.
const NACL = ['tweetnacl/nacl-fast.min.js', 'tweetnacl-util/nacl-util.min.js']
  .map(f => fs.readFileSync(path.join(ROOT, 'node_modules', f), 'utf8'));

let srv, base;
const pages = [];

before(async () => {
  const port = await new Promise((resolve, reject) => {
    const s = net.createServer().listen(0, () => { const { port } = s.address(); s.close(() => resolve(port)); }).on('error', reject);
  });
  base = `http://127.0.0.1:${port}`;
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'emberline-client-test-'));
  srv = spawn(process.execPath, ['server.js'], {
    cwd: ROOT, stdio: 'ignore',
    env: { ...process.env, PORT: String(port), LOG_DIR: logDir, TRUST_PROXY: '0', BOT_TOKEN: '', COUNTS_TICK_MS: '150' },
  });
  srv.logDir = logDir;
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(base + '/count')).ok) return; } catch {}
    await sleep(100);
  }
  throw new Error('server did not start');
});

after(() => {
  for (const p of pages) p.window.close();
  srv?.kill();
  if (srv) fs.rmSync(srv.logDir, { recursive: true, force: true });
});

// A page as a browser would load it, with the few browser features jsdom lacks
async function openPage() {
  const dom = await JSDOM.fromURL(base + '/', {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true,
    virtualConsole: new VirtualConsole(), // stylesheets and fonts jsdom can't use: not our concern
    beforeParse(window) {
      window.fetch = (url, opts) => fetch(new URL(url, base), opts);
      window.TextEncoder = TextEncoder;
      Object.defineProperty(window.crypto, 'subtle', { value: webcrypto.subtle });
      window.ResizeObserver = class { observe() {} disconnect() {} };
      window.matchMedia = () => ({ matches: false, addEventListener() {} });
      window.CSS ??= {};
      window.CSS.escape ??= v => String(v).replace(/["\\]/g, '\\$&');
      for (const src of NACL) window.eval(src);
    },
  });
  pages.push(dom);
  const { window } = dom, { document } = window;
  await until(() => document.readyState === 'complete' && typeof window.goOnline === 'function', 'page loaded');
  const $ = id => document.getElementById(id);
  return {
    window, document, $,
    q: sel => document.querySelector(sel),
    type(el, text) { el.value = text; el.dispatchEvent(new window.Event('input', { bubbles: true })); },
    key(el, key) { el.dispatchEvent(new window.KeyboardEvent('keydown', { key, bubbles: true, cancelable: true })); },
    async goOnline(name, interests) {
      $('name-input').value = name;
      this.type($('keyword-input'), interests + ' '); // a space ends each interest, as when typing
      $('adult').checked = true;
      $('btn-go').click();
      await until(() => !$('view-main').hidden, name + ' is online: ' + $('err-go').textContent + $('err-name').textContent);
    },
  };
}

async function until(fn, what, ms = 5000) {
  for (let t = 0; t < ms; t += 25) {
    const v = fn();
    if (v) return v;
    await sleep(25);
  }
  throw new Error('timed out waiting for: ' + what);
}

test('a whole visit: go online, find each other, request, accept, chat, log off', async () => {
  const a = await openPage(), b = await openPage();

  // Alone: your own interest counts the others, not you, and it says so once
  await a.goOnline('alice', 'chess');
  await until(() => a.q('#chips-mine .chip .n')?.textContent === '0', "alice's chess chip reads 0");
  await until(() => a.q('#results .empty-state'), 'one empty state');
  assert.equal(a.$('browse').textContent, '', 'no second "nobody online" below it');
  assert.ok(a.document.body.classList.contains('online'));

  // Bob arrives; Alice's open results pick him up by themselves
  await b.goOnline('bob', 'chess go');
  await until(() => a.q('#results [data-req]'), 'bob shows up for alice without a refresh');
  assert.equal(a.q('#chips-mine .chip .n').textContent, '1–4');

  // A draft survives closing the dialog; a click beside it doesn't close it
  (await until(() => b.q('#results [data-req]'), 'alice in bob\'s results')).click();
  assert.equal(b.$('modal-request').hidden, false);
  assert.equal(b.document.activeElement, b.$('request-text'), 'focus moves into the dialog');
  b.type(b.$('request-text'), 'Hello Alice, fancy a game of chess?');
  b.$('modal-request').click();
  assert.equal(b.$('modal-request').hidden, false, 'a click beside a written message keeps the dialog');
  b.key(b.document, 'Escape');
  assert.equal(b.$('modal-request').hidden, true);
  b.q('#results [data-req]').click();
  assert.equal(b.$('request-text').value, 'Hello Alice, fancy a game of chess?', 'the draft is back');

  // Sending, then closing straight away: the request still keeps its text
  b.$('btn-request-send').click();
  b.key(b.document, 'Escape');
  await until(() => b.q('#results .ghost.done'), 'request marked as sent');
  assert.match(b.$('note').textContent, /Request sent to alice/);
  b.$('tab-requests').click();
  assert.match(b.q('#panel-requests .message.mine').textContent, /fancy a game of chess/);

  // Alice sees it in the title and under requests, and accepts
  await until(() => a.document.title === '(1) Emberline', 'request counted in the title');
  a.$('tab-requests').click();
  assert.match(a.q('#panel-requests .message').textContent, /fancy a game of chess/);
  a.q('[data-acc]').click();
  await until(() => !a.$('view-chat').hidden, 'chat opens for alice');
  assert.match(a.q('#chat-box .msg.them').textContent, /fancy a game of chess/);

  // Bob: the new chat counts in the title too
  await until(() => b.document.title === '(1) Emberline', 'accepted chat counted in the title');
  a.type(a.$('chat-input'), 'Sure! White or black?');
  a.$('btn-send').click();
  b.$('tab-messages').click();
  await until(() => b.q('#panel-messages .pv')?.textContent === 'Sure! White or black?', 'preview is the message as written');
  assert.equal(b.document.title, '(1) Emberline', 'still counted while unread');
  b.q('#panel-messages [data-open]').click();
  assert.equal(b.document.title, 'Emberline');
  const theirs = [...b.document.querySelectorAll('#chat-box .msg.them')].pop();
  assert.match(theirs.textContent, /^Sure! White or black\?/);
  assert.ok(theirs.querySelector('.msg-time'), 'messages carry a time');

  b.type(b.$('chat-input'), 'Black, please.');
  b.$('btn-send').click();
  await until(() => [...a.document.querySelectorAll('#chat-box .msg.them')].some(m => m.textContent.startsWith('Black, please.')), 'reply reaches alice');

  // Tabs: arrow keys move between them
  b.$('btn-back').click();
  b.$('tab-messages').focus();
  b.key(b.$('tab-messages'), 'ArrowLeft');
  assert.equal(b.$('tab-requests').getAttribute('aria-selected'), 'true');
  assert.equal(b.document.activeElement, b.$('tab-requests'));

  // Log off: everything is gone, on both pages
  b.$('btn-logoff').click();
  assert.equal(b.$('modal-logoff').hidden, false);
  b.$('btn-logoff-ok').click();
  await until(() => !b.$('view-gone').hidden, 'bob logged off');
  assert.ok(!b.document.body.classList.contains('online'));
  await until(() => /bob logged off/.test(a.$('chat-box').textContent), 'alice is told');
});

test('an error lands on the action it belongs to', async () => {
  const a = await openPage(), b = await openPage();
  await a.goOnline('carol', 'tea');
  // The same name again: the error shows at the name field, opened for editing
  b.$('name-input').value = 'carol';
  b.type(b.$('keyword-input'), 'tea ');
  b.$('adult').checked = true;
  b.$('btn-go').click();
  await until(() => /using that name/.test(b.$('err-name').textContent), 'name taken shown at the name');
  assert.equal(b.$('view-main').hidden, true);
  assert.equal(b.$('btn-go').disabled, false);
});
