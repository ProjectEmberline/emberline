'use strict';
// Emberline client: profiles, requests and end-to-end encrypted chats.
// Everything lives in this page's memory. No cookies, no localStorage,
// no sessionStorage: reloading or closing the page logs you off.

const WS_URL = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`;
const REQUEST_MIN = 10, REQUEST_MAX = 200;
const MAX_OUTGOING = 20, MAX_ACTIVE_CHATS = 20;
const GRACE_MS = 5 * 60_000;       // server keeps a dropped profile this long
const BASE_TITLE = document.title;

// ── Proof-of-work solver ──────────────────────────────────────────────────────
// Finds a nonce such that SHA-256(prefix + nonce) starts with `difficulty` zeros.
// Runs in a tight loop — finishes in < 100ms on any modern browser.
async function solveChallenge(prefix, difficulty) {
  const encoder  = new TextEncoder();
  const fullBytes = difficulty >> 1;
  const halfByte  = difficulty & 1;
  const BATCH     = 512;

  for (let base = 0; base < 10_000_000; base += BATCH) {
    const pending = [];
    for (let i = 0; i < BATCH; i++) {
      const data = encoder.encode(prefix + String(base + i));
      pending.push(crypto.subtle.digest('SHA-256', data));
    }
    const results = await Promise.all(pending);
    for (let i = 0; i < results.length; i++) {
      const view = new Uint8Array(results[i]);
      let ok = true;
      for (let j = 0; j < fullBytes; j++) {
        if (view[j] !== 0) { ok = false; break; }
      }
      if (ok && halfByte && (view[fullBytes] >> 4) !== 0) ok = false;
      if (ok) return base + i;
    }
  }
  return 0;
}

async function fetchAndSolveChallenge() {
  const res  = await fetch('/challenge');
  if (!res.ok) throw new Error(res.status === 429 ? 'busy' : 'unreachable');
  const data = await res.json();
  const nonce = await solveChallenge(data.prefix, data.difficulty);
  return { token: data.token, nonce };
}

// ── Pre-warm cache: solve PoW before the user clicks ─────────────────────────
let _cachedPow  = null;   // { token, nonce, solvedAt }
let _powPromise = null;   // in-flight pre-solve

function prewarmChallenge() {
  if (_powPromise) return _powPromise;
  _powPromise = fetchAndSolveChallenge()
    .then(pow => { _cachedPow = { ...pow, solvedAt: Date.now() }; _powPromise = null; return _cachedPow; })
    .catch(() => { _powPromise = null; return null; });
  return _powPromise;
}

// Returns a ready-to-use PoW — from cache if fresh, otherwise solves a new one.
// Challenge TTL is 60s; we consider the cache stale after 50s to leave margin.
async function getPow() {
  if (_cachedPow && (Date.now() - _cachedPow.solvedAt) < 50_000) {
    const pow = _cachedPow;
    _cachedPow = null;
    return pow;
  }
  _cachedPow = null;
  return fetchAndSolveChallenge();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const minsLeft = at => Math.max(1, Math.ceil((at - Date.now()) / 60_000));

// Letters of any language, digits and "-"; lowercase, 2–24 chars (as the server)
const cleanTag = raw => raw.trim().toLowerCase().normalize('NFC')
  .replace(/[^\p{L}\p{N}-]/gu, '').replace(/^-+|-+$/g, '').slice(0, 24);

// ── State (memory only) ───────────────────────────────────────────────────────

let ws = null;
let wsVerified = false;          // this socket passed the proof-of-work
let keyPair = null;              // one NaCl box key pair per profile
let me = null;                   // { id, name, gender, interests, resumeToken }
let tags = [];
let gender = '';

const people   = new Map();      // id → public profile, as last seen
const incoming = new Map();      // requestId → { requestId, fromId, text, expiresAt }
const outgoing = new Map();      // requestId → { requestId, toId, text, expiresAt, state: pending|expired|gone }
const chatMap  = new Map();      // chatId → { chatId, partnerId, ai, name, pubKey, msgs[], unread, isNew, closed, closedReason, away, lastAt }
const requestTexts = new Map();  // person id → the request message they sent me (for an optional report)
const noAnswer = new Set();      // people who let my request expire: not again this session
const blocked  = new Set();
let accepting = true;
let counts = { buckets: {}, top: [] };
const lastBuckets = new Map();
let allInterests = null;         // [[interest, bucket]] when "show all" is open
let showAll = false;
let searchState = null;          // { interest, ids[], bucket, at }
let browseState = null;          // { ids[], at }: random people online, below the results
let aiAvailable = false;
let openChatId = null;
let currentTab = 'discover';
let lastAction = '';             // for errors that don't say what they belong to
let pendingRequest = null;       // { toId, text } while the request dialog waits for the server

// ── Views ─────────────────────────────────────────────────────────────────────

function show(view) {
  for (const v of ['entry', 'main', 'chat', 'gone']) $('view-' + v).hidden = v !== view;
  document.body.classList.toggle('is-chat', view === 'chat');
  if (view !== 'chat') openChatId = null;
  $('btn-logoff').hidden = !me;
  updateTagline();
}

function tab(name) {
  currentTab = name;
  for (const t of ['discover', 'requests', 'messages']) {
    $('tab-' + t).setAttribute('aria-selected', String(t === name));
    $('panel-' + t).hidden = t !== name;
  }
  renderCurrent();
}

function renderCurrent() {
  if (!me || $('view-main').hidden) return;
  if (currentTab === 'discover') renderDiscover();
  else if (currentTab === 'requests') renderRequests();
  else renderMessages();
}

// Feedback in the page flow, never a pop-up over the tabs
let _noteTimer = null;
function note(text) {
  const el = $('view-chat').hidden ? $('note') : $('chat-note');
  $('note').textContent = ''; $('chat-note').textContent = '';
  el.textContent = text;
  clearTimeout(_noteTimer);
  _noteTimer = setTimeout(() => { $('note').textContent = ''; $('chat-note').textContent = ''; }, 5000);
}

function updateTagline() {
  const t = $('tagline');
  if (me) {
    const recon = !ws || ws.readyState !== WebSocket.OPEN;
    t.innerHTML = `<span class="dot${recon ? ' recon' : ''}"></span><span class="me-name">${esc(me.name)}</span>`;
  }
}

function updateBadges() {
  const nReq = incoming.size;
  let nMsg = 0;
  for (const c of chatMap.values()) nMsg += c.unread || (c.isNew ? 1 : 0);
  $('badge-requests').textContent = nReq || '';
  $('badge-messages').textContent = nMsg || '';
  // The only alert: a count in the page title. No sound, no notifications.
  document.title = nReq ? `(${nReq}) Emberline` : (me ? 'Emberline' : BASE_TITLE);
}

// ── Person rows ───────────────────────────────────────────────────────────────

function personRow(p, actions, extra = '', attrs = '') {
  const mine = me ? me.interests : [];
  const ints = (p.interests || []).map(t => mine.includes(t) ? `<b>${esc(t)}</b>` : esc(t)).join(' · ');
  return `<div class="person${p.gone ? ' gone' : ''}" ${attrs}>
    <div class="who"><div class="u">${esc(p.name)}<span class="g">${esc(p.gender || '')}</span></div><div class="t">${ints}</div>${extra}</div>
    <div class="acts">${actions}</div></div>`;
}

function remember(p) {
  if (!p || typeof p.id !== 'string') return null;
  const old = people.get(p.id) || {};
  const merged = { ...old, ...p, gone: false };
  people.set(p.id, merged);
  return merged;
}

// ── Entry: profile form ───────────────────────────────────────────────────────

const GENDERS = [['woman', 'woman'], ['man', 'man'], ['trans woman (MtF)', 'trans woman (MtF)'], ['trans man (FtM)', 'trans man (FtM)'],
  ['non-binary', 'non-binary'], ['genderfluid', 'genderfluid'], ['', "don't show"]];

$('gender-choices').innerHTML = GENDERS.map(([v, l]) =>
  `<button type="button" class="choice" data-g="${esc(v)}" aria-pressed="${v === ''}">${esc(l)}</button>`).join('');
$('gender-choices').addEventListener('click', e => {
  const b = e.target.closest('[data-g]'); if (!b) return;
  gender = b.dataset.g;
  for (const x of $('gender-choices').children) x.setAttribute('aria-pressed', String(x === b));
  renderPreview();
});

function addTag(raw) {
  const word = cleanTag(raw);
  if (word.length < 2 || tags.includes(word) || tags.length >= 10) return;
  tags.push(word);
  renderTags();
}

function removeTag(word) {
  tags = tags.filter(t => t !== word);
  renderTags();
}

function renderTags() {
  const list = $('tag-list');
  list.innerHTML = '';
  tags.forEach(word => {
    const pill = document.createElement('span');
    pill.className = 'tag-pill';
    pill.appendChild(document.createTextNode(word));
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.title = 'remove';
    btn.textContent = '×';
    btn.addEventListener('click', e => { e.stopPropagation(); removeTag(word); });
    pill.appendChild(btn);
    list.appendChild(pill);
  });
  const input = $('keyword-input');
  input.placeholder = tags.length === 0 ? 'type here…' : tags.length < 10 ? 'add another…' : '';
  input.disabled = tags.length >= 10;
  $('err-tags').textContent = '';
  renderPreview();
}

function flushTagInput() {
  const input = $('keyword-input');
  if (input.value.trim()) { addTag(input.value); input.value = ''; }
}

// ── Username: locks into a pill like the interests ──────────────────────────
// Enter, Space or comma confirms the name; the × on the pill reopens it.
let lockedName = '';
const NAME_RE = /^[A-Za-z0-9_.-]{3,20}$/;
const currentName = () => lockedName || $('name-input').value.trim();

function lockName(raw) {
  const name = raw.trim();
  if (!name) return false;
  if (!NAME_RE.test(name)) { $('err-name').textContent = CREATE_ERRORS.name_invalid[1]; return false; }
  lockedName = name;
  $('name-input').value = '';
  renderName();
  return true;
}

function unlockName() {
  $('name-input').value = lockedName;
  lockedName = '';
  renderName();
  $('name-input').focus();
}

function renderName() {
  $('name-pill').hidden = !lockedName;
  $('name-pill-text').textContent = lockedName;
  $('name-input').hidden = !!lockedName;
  renderPreview();
}

$('name-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' || e.key === ' ' || e.key === ',') {
    e.preventDefault();
    if (lockName($('name-input').value)) $('keyword-input').focus();
  }
});
// Phone keyboards: the space lands in the field (see splitTypedTags)
$('name-input').addEventListener('input', e => {
  $('err-name').textContent = '';
  const v = e.target.value;
  if (!e.isComposing && /[\s,]/.test(v)) {
    const first = v.split(/[\s,]+/)[0];
    if (!lockName(first)) e.target.value = first;
    else $('keyword-input').focus();
  }
  renderPreview();
});
$('btn-name-edit').addEventListener('click', e => { e.stopPropagation(); unlockName(); });
$('name-field').addEventListener('click', () => { if (!lockedName) $('name-input').focus(); });

function renderPreview() {
  const typed = currentName();
  $('preview').innerHTML = personRow({ name: typed || 'your name', gender, interests: tags.length ? tags : ['your interests'] }, '');
  // Stand-in text until something is typed, so it doesn't read as filled in
  const who = $('preview').querySelector('.who');
  who.querySelector('.u').classList.toggle('is-sample', !typed);
  who.querySelector('.t').classList.toggle('is-sample', !tags.length);
}

$('keyword-input').addEventListener('keydown', e => {
  const input = e.target;
  // Enter, Space and comma create a tag from whatever is typed
  if (e.key === 'Enter' || e.key === ' ' || e.key === ',') {
    e.preventDefault();
    if (input.value.trim()) { addTag(input.value); input.value = ''; }
  }
  // Backspace on empty input removes last tag
  if (e.key === 'Backspace' && input.value === '' && tags.length > 0) {
    removeTag(tags[tags.length - 1]);
  }
});

// Phone keyboards (Android in particular) report Space and comma as
// "Unidentified" keydowns, so the character lands in the field instead of
// being caught above. Split on it once it's there; this also handles pasting
// "music, films games". Text after the last separator is still being typed.
const TAG_SEPARATOR = /[\s,，、]+/;
function splitTypedTags(input) {
  if (!TAG_SEPARATOR.test(input.value)) return;
  const parts = input.value.split(TAG_SEPARATOR);
  input.value = parts.pop();
  parts.forEach(addTag);
}
$('keyword-input').addEventListener('input', e => { if (!e.isComposing) splitTypedTags(e.target); });
$('keyword-input').addEventListener('compositionend', e => splitTypedTags(e.target));
$('tag-field').addEventListener('click', () => { if (!$('keyword-input').disabled) $('keyword-input').focus(); });
$('adult').addEventListener('change', () => { $('err-adult').textContent = ''; });

const CREATE_ERRORS = {
  name_invalid:      ['err-name', '3–20 characters: letters, numbers, dots, dashes and underscores.'],
  name_reserved:     ['err-name', "That name isn't available. Try another."],
  name_taken:        ['err-name', 'Someone online is using that name right now. Try another.'],
  gender_invalid:    ['err-go', 'Pick one of the gender options, or "don\'t show".'],
  interests_invalid: ['err-tags', "One of these interests isn't allowed. Check them and try again."],
  too_many_profiles: ['err-go', 'Too many people from your network are online right now. Try again later.'],
  server_busy:       ['err-go', 'Emberline is full right now. Try again in a few minutes.'],
  invalid_key:       ['err-go', 'Could not set up encryption. Reload the page and try again.'],
};

async function goOnline() {
  flushTagInput();
  if (!lockedName && $('name-input').value.trim()) lockName($('name-input').value);
  const name = lockedName;
  const eName = name ? '' : $('name-input').value.trim() ? CREATE_ERRORS.name_invalid[1] : 'Choose a username.';
  const eTags = tags.length ? '' : 'Add at least one interest, so people can find you.';
  const eAdult = $('adult').checked ? '' : 'Emberline is for adults only.';
  $('err-name').textContent = eName; $('err-tags').textContent = eTags; $('err-adult').textContent = eAdult; $('err-go').textContent = '';
  if (eName || eTags || eAdult) return;

  $('btn-go').disabled = true;
  if (!keyPair) keyPair = nacl.box.keyPair();
  const frame = {
    type: 'profile_create', name, gender,
    // A field hidden from people; if something filled it in, the server bans it
    interests: $('hp-field').value ? [...tags, '__honeypot__'] : tags,
    pubKey: nacl.util.encodeBase64(keyPair.publicKey),
  };
  try {
    if (!ws || ws.readyState !== WebSocket.OPEN || !wsVerified) {
      const [, pow] = await Promise.all([connect(), getPow()]);
      Object.assign(frame, pow);
    }
  } catch (e) {
    $('btn-go').disabled = false;
    $('err-go').textContent = e?.message === 'busy'
      ? 'Lots of people from your network right now. Please wait a minute and try again.'
      : 'Could not reach Emberline. Check your connection and try again.';
    return;
  }
  lastAction = 'create';
  _lastCreate = frame;
  wsSend(frame);
}
let _lastCreate = null;

// ── Connection ────────────────────────────────────────────────────────────────

function connect() {
  return new Promise((resolve, reject) => {
    // Handlers refer to this socket, not the global `ws`: by the time a close
    // event fires, `ws` may already be a newer connection.
    const sock = ws = new WebSocket(WS_URL);
    wsVerified = false;
    sock._intentionalClose = false;
    sock.onopen    = () => { resolve(); updateTagline(); };
    sock.onerror   = () => reject(new Error('unreachable'));
    sock.onmessage = e => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      if (ws === sock) handleMessage(msg);
    };
    sock.onclose = event => {
      if (ws !== sock) return; // a stale socket — the UI has moved on
      ws = null;
      if (event.code === 4429) {
        $('btn-go').disabled = false;
        $('err-go').textContent = "Too many connections from your IP address right now. If you're on a VPN or a shared network, wait a minute or switch VPN servers, then try again.";
        if (me) connectionLost();
        return;
      }
      if (sock._intentionalClose) return;
      if (me) connectionLost();
      else $('btn-go').disabled = false;
    };
  });
}

function wsSend(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) { ws.send(JSON.stringify(obj)); return true; }
  return false;
}

// ── Reconnect within the grace period ─────────────────────────────────────────
// The server keeps a dropped profile for 5 minutes. Keep trying to resume it,
// spaced out so a server restart isn't hit by everyone at once.
let _resumeDeadline = 0, _resumeTimer = null, _resumeDelay = 1000;

function connectionLost() {
  // Unsent messages stay in the outbox and go out once the session resumes
  if (!_resumeDeadline) _resumeDeadline = Date.now() + GRACE_MS - 5_000;
  setBanner('reconnect', 'Connection lost, reconnecting… Your profile and chats are kept for 5 minutes.');
  updateTagline();
  scheduleResume();
}

function scheduleResume() {
  clearTimeout(_resumeTimer);
  _resumeTimer = setTimeout(tryResume, _resumeDelay + Math.random() * 1000);
  _resumeDelay = Math.min(_resumeDelay * 2, 15_000);
}

async function tryResume() {
  if (!me) return;
  if (Date.now() > _resumeDeadline) return gone('timeout');
  try {
    await connect();
    lastAction = 'resume';
    wsSend({ type: 'resume', resumeToken: me.resumeToken });
  } catch {
    scheduleResume();
  }
}

// Page came back (phone unlocked, tab visible) with a dead socket: try now
function resumeSoon() {
  if (me && !ws) { _resumeDelay = 0; scheduleResume(); _resumeDelay = 1000; }
}

// ── Incoming frames ───────────────────────────────────────────────────────────

function handleMessage(msg) {
  if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;
  switch (msg.type) {

    case 'profile_ok': {
      wsVerified = true;
      const first = !me;
      me = { id: msg.id, name: msg.name, gender: msg.gender, interests: msg.interests, resumeToken: msg.resumeToken };
      if (first) {
        accepting = true;
        show('main'); tab('discover');
        watchCounts(true);
        if (me.interests[0]) search(me.interests[0]);
        refreshCount();
      } else {
        // Resumed after a dropped connection or a tab handover
        _resumeDeadline = 0; _resumeDelay = 1000;
        clearBanner('reconnect');
        flushOutbox();
        watchCounts(document.visibilityState === 'visible');
        updateTagline();
      }
      $('btn-go').disabled = false;
      break;
    }

    case 'state': reconcile(msg); break;

    case 'counts':
      counts = { buckets: msg.buckets || {}, top: Array.isArray(msg.top) ? msg.top : [] };
      if (currentTab === 'discover') renderDiscover();
      break;

    case 'interests_all':
      allInterests = Array.isArray(msg.list) ? msg.list : [];
      renderDiscover();
      break;

    case 'results': {
      const ids = [];
      for (const p of msg.people || []) {
        const r = remember(p);
        if (!r || blocked.has(r.id)) continue;
        if (p.askedBefore) noAnswer.add(p.id);
        ids.push(r.id);
      }
      searchState = { interest: msg.interest, ids, bucket: msg.bucket, at: Date.now() };
      if (!browseState) requestBrowse();
      renderDiscover();
      break;
    }

    case 'browse_results': {
      const ids = [];
      for (const p of msg.people || []) {
        const r = remember(p);
        if (!r || blocked.has(r.id)) continue;
        if (p.askedBefore) noAnswer.add(p.id);
        ids.push(r.id);
      }
      browseState = { ids, at: Date.now() };
      renderDiscover();
      break;
    }

    case 'request_sent': {
      const pr = pendingRequest && pendingRequest.toId === msg.to ? pendingRequest : null;
      outgoing.set(msg.requestId, { requestId: msg.requestId, toId: msg.to, text: pr ? pr.text : '', expiresAt: Date.now() + (msg.expiresIn || 0), state: 'pending' });
      if (pr) { pendingRequest = null; closeModal('modal-request'); }
      const p = people.get(msg.to);
      note(`Request sent to ${p ? p.name : 'them'}. You'll find it under requests.`);
      renderCurrent();
      break;
    }

    case 'request_in': {
      const from = remember(msg.from);
      if (!from || blocked.has(from.id)) break;
      const text = unseal(msg, from.pubKey);
      if (text === null) break; // not encrypted by that person: ignore it
      incoming.set(msg.requestId, { requestId: msg.requestId, fromId: from.id, text, expiresAt: Date.now() + (msg.expiresIn || 0) });
      requestTexts.set(from.id, text);
      updateBadges();
      renderCurrent();
      break;
    }

    case 'request_gone':
      if (incoming.delete(msg.requestId)) { updateBadges(); renderCurrent(); break; }
      if (outgoing.has(msg.requestId)) {
        const r = outgoing.get(msg.requestId);
        r.state = 'gone';
        const p = people.get(r.toId); if (p) p.gone = true;
        renderCurrent();
      }
      break;

    case 'request_expired': {
      const r = outgoing.get(msg.requestId);
      if (r) { r.state = 'expired'; noAnswer.add(r.toId); renderCurrent(); }
      break;
    }

    case 'accepting':
      accepting = msg.on === true;
      renderCurrent();
      break;

    case 'chat_open': openedChat(msg); break;

    case 'chat_message': {
      const c = chatMap.get(msg.chatId);
      if (!c) break;
      const text = unseal(msg, c.pubKey);
      addChatMsg(c, 'them', text === null ? '[could not decrypt this message]' : text);
      break;
    }

    case 'chat_typing': {
      const c = chatMap.get(msg.chatId);
      if (c && openChatId === c.chatId) showTypingIndicator(c.ai);
      break;
    }

    case 'chat_ack': {
      const c = chatMap.get(msg.chatId);
      const m = c && c.msgs.find(x => x.ref && x.ref === msg.ref);
      if (!m) break;
      if (msg.queued) {
        setMsgState(c, m, 'waiting');
        if (!c.away) { c.away = true; openChatId === c.chatId ? renderChatHead() : renderCurrent(); }
      } else setMsgState(c, m, undefined);
      break;
    }

    case 'chat_ended': {
      const c = chatMap.get(msg.chatId);
      if (!c || c.closed) break;
      c.closed = true;
      c.closedReason = msg.reason === 'logged_off' ? 'logged_off' : 'ended';
      // Messages still waiting for them won't arrive now
      const lost = c.msgs.filter(m => m.state === 'waiting' || m.state === 'sending');
      lost.forEach(m => setMsgState(c, m, 'failed'));
      if (lost.length) addChatMsg(c, 'system', `${plural(lost.length, 'message')} marked "not delivered" didn't reach ${c.name}.`);
      addChatMsg(c, 'system', c.closedReason === 'logged_off' ? `${c.name} logged off.` : `${c.name} ended the chat.`);
      if (openChatId === c.chatId) renderChat();
      break;
    }

    case 'partner_reconnecting':
    case 'partner_back': {
      const c = chatMap.get(msg.chatId);
      if (!c) break;
      c.away = msg.type === 'partner_reconnecting';
      if (!c.away) {
        // The server handed over everything that waited for them
        const waited = c.msgs.filter(m => m.state === 'waiting');
        waited.forEach(m => setMsgState(c, m, undefined));
        if (waited.length) addChatMsg(c, 'system', `${c.name} is back. Your ${waited.length === 1 ? 'message was' : 'messages were'} delivered.`);
      }
      if (openChatId === c.chatId) renderChatHead();
      else renderCurrent();
      break;
    }

    case 'idle_warning': showIdleWarning(Number(msg.secondsLeft) || 120); break;

    case 'logged_off': gone(msg.reason); break;

    case 'replaced': gone('replaced'); break;

    case 'report_ok': closeModal('modal-report'); note('Report sent. Thank you.'); break;

    case 'error': handleError(msg); break;

    default: break; // Unknown message type — ignore silently
  }
}

// Bring the local view in line with the server after a resume
function reconcile(st) {
  accepting = st.accepting !== false;
  const inIds = new Set();
  for (const r of st.incoming || []) {
    inIds.add(r.requestId);
    if (incoming.has(r.requestId)) continue;
    const from = remember(r.from);
    const text = from && unseal(r, from.pubKey);
    if (text !== null && text !== undefined) incoming.set(r.requestId, { requestId: r.requestId, fromId: from.id, text, expiresAt: Date.now() + (r.expiresIn || 0) });
  }
  for (const id of incoming.keys()) if (!inIds.has(id)) incoming.delete(id);
  const outIds = new Set((st.outgoing || []).map(r => r.requestId));
  for (const r of outgoing.values()) if (r.state === 'pending' && !outIds.has(r.requestId)) r.state = 'expired';
  const serverChats = new Map((st.chats || []).map(c => [c.chatId, c]));
  for (const c of chatMap.values()) {
    const s = serverChats.get(c.chatId);
    if (!c.closed && (!s || !s.open)) {
      c.closed = true; c.closedReason = 'ended';
      addChatMsg(c, 'system', 'This chat ended while you were away.');
    }
    if (s) c.away = !!s.away;
  }
  updateBadges();
  renderCurrent();
  if (openChatId) renderChat();
}

const REQUEST_ERRORS = {
  offline:          n => `${n} is no longer online.`,
  not_accepting:    n => `${n} isn't taking requests right now.`,
  busy:             n => `${n} has too many open requests right now. Try again later.`,
  outgoing_full:    () => `You have ${MAX_OUTGOING} open requests. Wait for answers or withdraw one.`,
  chats_full:       () => `You have ${MAX_ACTIVE_CHATS} active chats. End one to start another.`,
  asked_before:     n => `${n} didn't answer your earlier request. You can't ask again this session.`,
  already_pending:  () => "There's already an open request between you two. Check your requests.",
  already_chatting: () => "You're already chatting. Find it under messages.",
  rate_limited:     () => 'Slow down: you can send 5 requests a minute.',
  message_rejected: () => 'That message is too long.',
  server_busy:      () => 'Emberline is busy right now. Try again shortly.',
};

function handleError(msg) {
  const code = msg.code;
  // Request errors carry the person they're about
  if (typeof msg.to === 'string' && REQUEST_ERRORS[code]) {
    const p = people.get(msg.to);
    const name = p ? p.name : 'They';
    if (code === 'offline' && p) p.gone = true;
    if (code === 'not_accepting' && p) p.accepting = false;
    if (code === 'asked_before') noAnswer.add(msg.to);
    const text = REQUEST_ERRORS[code](name);
    if (pendingRequest && pendingRequest.toId === msg.to && !$('modal-request').hidden) {
      $('request-err').textContent = text;
      $('btn-request-send').disabled = false;
      pendingRequest = null;
    } else note(text);
    renderCurrent();
    return;
  }
  // Chat errors carry the chat
  if (typeof msg.chatId === 'string') {
    const c = chatMap.get(msg.chatId);
    const name = c ? c.name : 'They';
    const m = c && msg.ref && c.msgs.find(x => x.ref === msg.ref);
    if (m) setMsgState(c, m, 'failed');
    const text = code === 'partner_away' ? `${name} is reconnecting and too many messages are waiting for them. This one wasn't delivered.`
      : code === 'chat_closed' ? 'This chat has ended. Your message wasn\'t delivered.'
      : code === 'rate_limited' ? 'A message could not be delivered. Slow down a little.'
      : 'A message could not be delivered.';
    if (c) addChatMsg(c, 'system', text);
    return;
  }
  if (lastAction === 'create' && !me) {
    if (code === 'slow_down') { setTimeout(() => wsSend(_lastCreate), (Number(msg.retryMs) || 3000) + 100); return; }
    if (code === 'challenge_expired') { wsVerified = false; ws && (ws._intentionalClose = true, ws.close()); ws = null; goOnline(); return; }
    const [field, text] = CREATE_ERRORS[code] || ['err-go', 'Something went wrong. Please try again.'];
    if (field === 'err-name' && lockedName) unlockName(); // taken or refused: open it for editing
    $(field).textContent = text;
    $('btn-go').disabled = false;
    return;
  }
  if (code === 'resume_failed') return gone('timeout');
  if (lastAction === 'ai') {
    note(code === 'ai_unavailable' ? 'The AI is busy right now. Try again in a moment.'
      : code === 'ai_already_open' ? 'You already have a chat with the AI open. Find it under messages.'
      : code === 'chats_full' ? REQUEST_ERRORS.chats_full()
      : 'The AI chat could not start. Try again in a moment.');
    if (code === 'ai_unavailable') { aiAvailable = false; renderCurrent(); }
    return;
  }
  if (lastAction === 'report') { $('report-err').textContent = code === 'rate_limited' ? 'Too many reports from your network. Try again later.' : 'Could not send the report.'; return; }
  if (lastAction === 'accept' && code === 'chats_full') { note(REQUEST_ERRORS.chats_full()); return; }
  if (code === 'rate_limited') note('Slow down a little and try again.');
}

// ── Encryption ────────────────────────────────────────────────────────────────

function seal(text, pubB64) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const ct = nacl.box(nacl.util.decodeUTF8(text), nonce, nacl.util.decodeBase64(pubB64), keyPair.secretKey);
  return { ciphertext: nacl.util.encodeBase64(ct), nonce: nacl.util.encodeBase64(nonce) };
}

// Returns the plaintext, or null if it wasn't encrypted by that key
function unseal(m, pubB64) {
  if (!keyPair || typeof m.ciphertext !== 'string' || typeof m.nonce !== 'string' || typeof pubB64 !== 'string') return null;
  try {
    const out = nacl.box.open(nacl.util.decodeBase64(m.ciphertext), nacl.util.decodeBase64(m.nonce), nacl.util.decodeBase64(pubB64), keyPair.secretKey);
    return out ? nacl.util.encodeUTF8(out) : null;
  } catch { return null; }
}

// ── Discover ──────────────────────────────────────────────────────────────────

function watchCounts(on) {
  wsSend({ type: 'counts_watch', on, interests: searchState ? [searchState.interest] : [] });
}

function chipHtml(t, b) {
  const key = t, changed = lastBuckets.has(key) && lastBuckets.get(key) !== b;
  lastBuckets.set(key, b);
  const sel = searchState && searchState.interest === t;
  return `<button type="button" class="chip${sel ? ' sel' : ''}${changed ? ' flash' : ''}" data-t="${esc(t)}">${esc(t)} <span class="n">${esc(b)}</span></button>`;
}

function renderDiscover() {
  if (!me) return;
  $('chips-mine').innerHTML = me.interests.map(t => chipHtml(t, counts.buckets[t] || '…')).join('');
  let top;
  if (showAll && allInterests) top = allInterests.filter(([t]) => !me.interests.includes(t));
  else top = counts.top.filter(t => !me.interests.includes(t)).map(t => [t, counts.buckets[t] || '…']);
  $('chips-top').innerHTML = top.map(([t, b]) => chipHtml(t, b)).join('') || '<span class="hint">Nobody else online yet.</span>';
  $('top-label').textContent = showAll ? `all interests online${allInterests ? ' · ' + allInterests.length : ''}` : 'popular now';
  $('btn-all').textContent = showAll ? 'show fewer' : 'show all';
  setTimeout(() => document.querySelectorAll('.chip.flash').forEach(e => e.classList.remove('flash')), 700);

  const aiChat = [...chatMap.values()].find(c => c.ai && !c.closed);
  $('ai-card').hidden = !aiAvailable && !aiChat;
  $('btn-ai').textContent = aiChat ? 'open AI chat' : 'start AI chat';

  renderResults();
}

function relationAction(p) {
  const chat = [...chatMap.values()].find(c => c.partnerId === p.id && !c.closed);
  if (chat) return `<button type="button" class="ghost accent" data-open="${esc(chat.chatId)}">open chat</button>`;
  if ([...outgoing.values()].some(r => r.toId === p.id && r.state === 'pending')) return '<span class="ghost done">requested</span>';
  if ([...incoming.values()].some(r => r.fromId === p.id)) return '<button type="button" class="ghost accent" data-goto="requests">sent you a request</button>';
  if (p.gone) return '<span class="hint">no longer online</span>';
  if (noAnswer.has(p.id)) return '<span class="hint">no answer earlier</span>';
  if (!p.accepting) return '<span class="hint">not taking requests</span>';
  return `<button type="button" class="ghost accent" data-req="${esc(p.id)}">request</button>`;
}

function renderResults() {
  const s = searchState;
  if (!s) { $('results').innerHTML = ''; return; }
  const secs = Math.round((Date.now() - s.at) / 1000);
  const ids = s.ids.filter(id => !blocked.has(id));
  let h = `<div class="meta"><span class="label">${esc(s.interest)} · ${esc(s.bucket)} online</span>
    <span class="hint">${ids.length ? `${ids.length} shown, random · ` : ''}${secs < 5 ? 'just now' : secs < 60 ? secs + ' s ago' : Math.round(secs / 60) + ' min ago'} · <button type="button" class="link" id="btn-refresh">refresh</button></span></div>`;
  if (!ids.length) h += '<div class="empty serif">No one else online with this interest right now. The count updates live, so check back.</div>';
  for (const id of ids) {
    const p = people.get(id);
    if (p) h += personRow(p, relationAction(p));
  }
  $('results').innerHTML = h;
  renderBrowse();
}

const ago = at => { const s = Math.round((Date.now() - at) / 1000); return s < 5 ? 'just now' : s < 60 ? s + ' s ago' : Math.round(s / 60) + ' min ago'; };

// Random people online, whatever their interests; never repeats the list above
function renderBrowse() {
  const b = browseState;
  if (!b) { $('browse').innerHTML = ''; return; }
  const above = new Set(searchState ? searchState.ids : []);
  const ids = b.ids.filter(id => !blocked.has(id) && !above.has(id));
  let h = `<div class="meta"><span class="label">others online · random</span>
    <span class="hint">${ago(b.at)} · <button type="button" class="link" id="btn-browse-refresh">show others</button></span></div>`;
  if (!ids.length) h += '<div class="empty serif">Nobody else is online right now.</div>';
  for (const id of ids) {
    const p = people.get(id);
    if (p) h += personRow(p, relationAction(p));
  }
  $('browse').innerHTML = h;
}

function requestBrowse() {
  lastAction = 'search';
  wsSend({ type: 'browse', exclude: searchState ? searchState.ids : [] });
}

function search(interest) {
  const t = cleanTag(interest);
  if (t.length < 2) return;
  lastAction = 'search';
  if (!searchState || searchState.interest !== t) watchCountsFor(t);
  wsSend({ type: 'search', interest: t });
}
function watchCountsFor(t) { wsSend({ type: 'counts_watch', on: true, interests: [t] }); }

$('panel-discover').addEventListener('click', e => {
  const chip = e.target.closest('.chip'); if (chip) return search(chip.dataset.t);
  if (e.target.id === 'btn-refresh' && searchState) return search(searchState.interest);
  if (e.target.id === 'btn-browse-refresh') return requestBrowse();
  if (e.target.id === 'btn-all') {
    showAll = !showAll;
    if (showAll) { lastAction = 'all'; wsSend({ type: 'interests_all' }); }
    return renderDiscover();
  }
  if (e.target.id === 'btn-ai') return startAi();
  const r = e.target.closest('[data-req]'); if (r) return openRequestDialog(r.dataset.req);
  const o = e.target.closest('[data-open]'); if (o) return openChat(o.dataset.open);
  if (e.target.closest('[data-goto]')) return tab('requests');
});
$('search-input').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const v = $('search-input').value;
  if (cleanTag(v).length > 1) { search(v); $('search-input').value = ''; }
});

// ── AI chat ───────────────────────────────────────────────────────────────────

function startAi() {
  const existing = [...chatMap.values()].find(c => c.ai && !c.closed);
  if (existing) return openChat(existing.chatId);
  lastAction = 'ai';
  wsSend({ type: 'ai_start' });
}

// ── Sending a request (message required) ──────────────────────────────────────

let _requestTo = null;
function openRequestDialog(id) {
  const p = people.get(id);
  if (!p) return;
  if ([...outgoing.values()].filter(r => r.state === 'pending').length >= MAX_OUTGOING) return note(REQUEST_ERRORS.outgoing_full());
  if (activeChatCount() >= MAX_ACTIVE_CHATS) return note(REQUEST_ERRORS.chats_full());
  _requestTo = id;
  const shared = (p.interests || []).filter(t => me.interests.includes(t));
  $('request-title').textContent = `Chat with ${p.name}?`;
  $('request-why').textContent = `${shared.length ? 'You both like ' + shared.join(', ') + '. ' : ''}They'll see your profile and your message, and can accept or decline.`;
  $('request-lead2').textContent = `It's all ${p.name} sees when deciding whether to accept.`;
  $('request-text').value = '';
  $('request-err').textContent = '';
  $('btn-request-send').disabled = false;
  updateRequestCount();
  openModal('modal-request');
  $('request-text').focus();
}

function updateRequestCount() {
  const n = $('request-text').value.trim().length;
  const ok = n >= REQUEST_MIN;
  const c = $('request-count');
  c.classList.toggle('ok-text', ok);
  c.classList.toggle('warn-text', !ok);
  c.textContent = ok ? `✓ ready to send · ${n} / ${REQUEST_MAX}`
    : `${REQUEST_MIN - n} more character${REQUEST_MIN - n === 1 ? '' : 's'} needed · ${n} / ${REQUEST_MIN} minimum`;
  $('btn-request-send').classList.toggle('dim', !ok);
}
$('request-text').addEventListener('input', () => { updateRequestCount(); $('request-err').textContent = ''; });

function sendRequest() {
  const p = people.get(_requestTo);
  const text = $('request-text').value.trim();
  if (text.length < REQUEST_MIN) { $('request-err').textContent = `Write at least ${REQUEST_MIN} characters. Your message is what they decide on.`; return; }
  if (!p || !p.pubKey) { $('request-err').textContent = `${p ? p.name : 'They'} is no longer online.`; return; }
  pendingRequest = { toId: p.id, text };
  $('btn-request-send').disabled = true;
  if (!wsSend({ type: 'request_send', to: p.id, ...seal(text, p.pubKey) })) {
    pendingRequest = null;
    $('btn-request-send').disabled = false;
    $('request-err').textContent = 'Not connected right now. Try again in a moment.';
  }
}
$('btn-request-send').addEventListener('click', sendRequest);
$('btn-request-cancel').addEventListener('click', () => { pendingRequest = null; closeModal('modal-request'); });

// ── Requests tab ──────────────────────────────────────────────────────────────

function renderRequests() {
  let h = `<label class="switch"><input type="checkbox" id="accepting" ${accepting ? 'checked' : ''}><span class="track"></span>
    <span><strong>${accepting ? 'Accepting new requests' : 'Not accepting new requests'}</strong><span class="hint">${accepting
      ? 'Switch off to stay visible without getting new requests.'
      : 'You stay visible; your profile shows "not taking requests".'}</span></span></label>`;

  const ins = [...incoming.values()].sort((a, b) => a.expiresAt - b.expiresAt);
  h += `<div class="meta first"><span class="label">requests for you · ${ins.length}</span><span class="hint">expire after 10 min · declining is silent: they only see "no answer" once it expires</span></div>`;
  if (!ins.length) h += '<div class="empty">No requests right now. When someone wants to chat, their message shows up here and you decide.</div>';
  for (const r of ins) {
    const p = people.get(r.fromId) || { name: '?', interests: [] };
    h += `<div class="req">${personRow(p, `<span class="when">expires in ${minsLeft(r.expiresAt)} min</span>`)}
      <div class="message">“${esc(r.text)}”</div>
      <div class="acts"><button type="button" class="ghost accent" data-acc="${esc(r.requestId)}">accept</button><button type="button" class="ghost" data-dec="${esc(r.requestId)}">decline</button><button type="button" class="ghost danger" data-blk="${esc(r.fromId)}">block</button><button type="button" class="ghost" data-rep="${esc(r.fromId)}">report</button></div></div>`;
  }

  const outs = [...outgoing.values()];
  const pending = outs.filter(r => r.state === 'pending').length;
  h += `<div class="meta"><span class="label">sent · ${pending} of ${MAX_OUTGOING}</span><span class="hint">expire after 10 min without an answer</span></div>`;
  if (!outs.length) h += '<div class="empty">Requests you send wait here until they\'re answered. Accepted ones move to messages.</div>';
  for (const r of outs) {
    const p = people.get(r.toId) || { name: '?', interests: [] };
    const when = r.state === 'pending' ? `waiting · expires in ${minsLeft(r.expiresAt)} min` : r.state === 'gone' ? `${esc(p.name)} logged off` : 'no answer · expired';
    h += `<div class="req${r.state === 'pending' ? '' : ' gone'}">${personRow(p, `<span class="when">${when}</span>`)}
      ${r.text ? `<div class="message mine">“${esc(r.text)}”</div>` : ''}
      <div class="acts"><button type="button" class="ghost" data-cancel="${esc(r.requestId)}">${r.state === 'pending' ? 'withdraw' : 'remove'}</button></div></div>`;
  }
  $('panel-requests').innerHTML = h;
}

$('panel-requests').addEventListener('change', e => {
  if (e.target.id !== 'accepting') return;
  accepting = e.target.checked;
  wsSend({ type: 'set_accepting', on: accepting });
  renderRequests();
});
$('panel-requests').addEventListener('click', e => {
  const b = e.target.closest('[data-acc],[data-dec],[data-blk],[data-rep],[data-cancel]');
  if (!b) return;
  if (b.dataset.acc) {
    if (activeChatCount() >= MAX_ACTIVE_CHATS) return note(REQUEST_ERRORS.chats_full());
    lastAction = 'accept';
    wsSend({ type: 'request_answer', requestId: b.dataset.acc, accept: true });
  } else if (b.dataset.dec) {
    wsSend({ type: 'request_answer', requestId: b.dataset.dec, accept: false });
    incoming.delete(b.dataset.dec);
    updateBadges(); renderRequests();
  } else if (b.dataset.blk) blockPerson(b.dataset.blk);
  else if (b.dataset.rep) openReport(b.dataset.rep);
  else if (b.dataset.cancel) {
    const r = outgoing.get(b.dataset.cancel);
    if (r && r.state === 'pending') wsSend({ type: 'request_withdraw', requestId: r.requestId });
    outgoing.delete(b.dataset.cancel);
    renderRequests();
  }
});

// ── Messages tab ──────────────────────────────────────────────────────────────

function activeChatCount() { let n = 0; for (const c of chatMap.values()) if (!c.closed) n++; return n; }

function chatStatus(c) {
  if (c.closed) return c.closedReason === 'logged_off' ? 'logged off' : 'ended the chat';
  if (c.away) return '<span class="recon">reconnecting…</span>';
  return '<span class="on">online</span>';
}

function renderMessages() {
  let h = '<div class="meta first"><span class="label">chats</span><span class="e2e">end-to-end encrypted</span></div>';
  const list = [...chatMap.values()].sort((a, b) => b.lastAt - a.lastAt);
  if (!list.length) h += '<div class="empty">No chats yet. Send a request from discover, or accept one under requests.</div>';
  for (const c of list) {
    const last = c.msgs.filter(m => m.side !== 'system').slice(-1)[0];
    const badge = c.isNew ? '<span class="badge">new</span>' : c.unread ? `<span class="badge">${c.unread}</span>` : '<span class="ghost">open</span>';
    const p = c.ai ? { name: c.name, gender: 'AI', interests: [] } : (people.get(c.partnerId) || { name: c.name, interests: [] });
    h += personRow(p, badge, `<div class="t">${chatStatus(c)}${last ? ' · ' + esc(last.text.slice(0, 80)) : ''}</div>`, `data-open="${esc(c.chatId)}" role="button" tabindex="0"`)
      .replace('class="person', 'class="person clickable');
  }
  $('panel-messages').innerHTML = h;
}
$('panel-messages').addEventListener('click', e => { const r = e.target.closest('[data-open]'); if (r) openChat(r.dataset.open); });
$('panel-messages').addEventListener('keydown', e => { if (e.key === 'Enter') { const r = e.target.closest('[data-open]'); if (r) openChat(r.dataset.open); } });

// ── Chats ─────────────────────────────────────────────────────────────────────

function openedChat(msg) {
  if (chatMap.has(msg.chatId)) return;
  const partner = msg.ai ? null : remember(msg.partner);
  if (!msg.ai && !partner) return;
  const c = {
    chatId: msg.chatId, ai: msg.ai === true, partnerId: partner ? partner.id : null,
    name: msg.ai ? 'Emberline AI' : partner.name, pubKey: msg.partner && msg.partner.pubKey,
    msgs: [], unread: 0, isNew: false, closed: false, closedReason: '', away: false, lastAt: Date.now(),
  };
  c.msgs.push({ side: 'system', text: c.ai
    ? "Connected to an AI, not a person. It sees your profile and reads your messages to reply, and can be wrong. Nothing is stored."
    : 'Chat started · end-to-end encrypted · never stored' });
  chatMap.set(c.chatId, c);
  const sent = msg.requestId && outgoing.get(msg.requestId);
  const received = msg.requestId && incoming.get(msg.requestId);
  if (sent) {
    // They accepted my request: no pop-up; the chat shows up under messages, marked new
    outgoing.delete(msg.requestId);
    if (sent.text) c.msgs.push({ side: 'me', text: sent.text });
    c.isNew = true;
    updateBadges();
    renderCurrent();
  } else {
    // I accepted theirs, or started the AI chat: open it straight away
    if (received) { incoming.delete(msg.requestId); c.msgs.push({ side: 'them', text: received.text }); }
    updateBadges();
    openChat(c.chatId);
  }
}

function openChat(chatId) {
  const c = chatMap.get(chatId);
  if (!c) return;
  c.unread = 0; c.isNew = false;
  updateBadges();
  show('chat');
  openChatId = chatId;
  renderChat();
  if (!c.closed) $('chat-input').focus();
}

function renderChatHead() {
  const c = chatMap.get(openChatId);
  if (!c) return;
  const p = c.ai ? null : people.get(c.partnerId);
  $('chat-name').innerHTML = esc(c.name) + (p && p.gender ? `<span class="g">${esc(p.gender)}</span>` : '');
  const shared = p ? (p.interests || []).filter(t => me.interests.includes(t)) : [];
  $('chat-status').innerHTML = (c.ai ? '<span class="on">AI</span>' : chatStatus(c)) + (shared.length ? ' · you share ' + shared.map(esc).join(', ') : '');
}

function renderChat() {
  const c = chatMap.get(openChatId);
  if (!c) return;
  renderChatHead();
  $('ai-banner').hidden = !c.ai;
  const box = chatBoxEl;
  box.innerHTML = '';
  box.classList.toggle('chat-over', c.closed);
  for (const m of c.msgs) box.appendChild(msgEl(m, c.name));
  $('chat-input-row').hidden = c.closed;
  $('chat-closed').hidden = !c.closed;
  $('chat-closed').textContent = c.closed
    ? `${c.name} ${c.closedReason === 'logged_off' ? 'logged off' : 'ended the chat'}. You can't write anymore; your copy stays until you close it.` : '';
  $('btn-end').textContent = c.closed ? 'close' : 'end chat';
  $('btn-report').hidden = c.ai;
  $('btn-block').hidden = c.ai;
  scrollChatToEnd();
}

const MSG_STATUS = { sending: () => '', waiting: name => `waiting for ${name}…`, failed: () => 'not delivered' };

function msgEl(m, name) {
  const d = document.createElement('div');
  d.className = 'msg ' + m.side + (m.state ? ' ' + m.state : '');
  if (m.ref) d.dataset.ref = m.ref;
  // Messages show in full, so cap blank-line padding (300 newlines = a wall)
  d.textContent = m.text.replace(/\n{3,}/g, '\n\n');
  if (m.state && MSG_STATUS[m.state](name)) {
    const s = document.createElement('span');
    s.className = 'msg-status';
    s.textContent = MSG_STATUS[m.state](name);
    d.appendChild(s);
  }
  return d;
}

// sending → (sent | waiting → delivered) | failed; updates the open chat in place
function setMsgState(c, m, state) {
  if (m.state === state) return;
  m.state = state;
  if (openChatId !== c.chatId || $('view-chat').hidden) return;
  const el = chatBoxEl.querySelector(`[data-ref="${m.ref}"]`);
  if (el) el.replaceWith(msgEl(m, c.name));
}

function addChatMsg(c, side, text, extra) {
  const m = { side, text, ...extra };
  c.msgs.push(m);
  if (side !== 'system') c.lastAt = Date.now();
  if (openChatId === c.chatId && !$('view-chat').hidden) {
    if (side === 'them') hideTypingIndicator();
    chatBoxEl.appendChild(msgEl(m, c.name));
    if (side === 'me' || chatPinned) scrollChatToEnd();
  } else {
    if (side === 'them') c.unread++;
    updateBadges();
    renderCurrent();
  }
}

// Stay pinned to the newest message unless the reader scrolled up. Tracked on
// scroll rather than measured on arrival: a growing input or the phone keyboard
// shrinks the box without scrolling it.
const chatBoxEl = $('chat-box');
let chatPinned = true;
function scrollChatToEnd() { chatBoxEl.scrollTop = chatBoxEl.scrollHeight; chatPinned = true; }
chatBoxEl.addEventListener('scroll', () => {
  chatPinned = chatBoxEl.scrollHeight - chatBoxEl.scrollTop - chatBoxEl.clientHeight <= 20;
}, { passive: true });
new ResizeObserver(() => { if (chatPinned) scrollChatToEnd(); }).observe(chatBoxEl);

let _typingTimeout = null;
const _lastTypingSent = new Map();
function showTypingIndicator(ai) {
  let el = $('typing-indicator');
  if (!el) {
    el = document.createElement('div');
    el.id = 'typing-indicator';
    el.className = 'typing-indicator';
  }
  el.textContent = ai ? 'AI is writing…' : 'typing...';
  chatBoxEl.appendChild(el);
  if (chatPinned) scrollChatToEnd();
  clearTimeout(_typingTimeout);
  _typingTimeout = setTimeout(hideTypingIndicator, 3000);
}
function hideTypingIndicator() { const el = $('typing-indicator'); if (el) el.remove(); clearTimeout(_typingTimeout); }

function sendMessage() {
  const c = chatMap.get(openChatId);
  const input = $('chat-input');
  const text = input.value.trim();
  if (!c || c.closed || !text) return;
  if (!c.pubKey) return addChatMsg(c, 'system', 'Encryption not established — cannot send message.');
  input.value = '';
  input.style.height = 'auto';
  input.classList.remove('at-height-limit');
  $('chat-char-count').textContent = '';
  $('chat-char-count').classList.remove('visible', 'urgent');
  // The ref comes back in the server's ack, so this message's state can follow it
  const ref = Math.random().toString(36).slice(2, 12);
  addChatMsg(c, 'me', text, { ref, state: 'sending' });
  queueFrame({ type: 'chat_message', chatId: c.chatId, ref, ...seal(text, c.pubKey) });
}

// The server refills one message token every 300ms. Pace frames slightly
// slower so fast typing or pasting several lines never drops a message.
const SEND_INTERVAL_MS = 350;
let _outbox = [], _outboxTimer = null, _lastSentAt = 0;
function queueFrame(frame) { _outbox.push(frame); flushOutbox(); }
function flushOutbox() {
  if (_outboxTimer || _outbox.length === 0) return;
  const wait = Math.max(0, _lastSentAt + SEND_INTERVAL_MS - Date.now());
  _outboxTimer = setTimeout(() => {
    _outboxTimer = null;
    if (!ws || ws.readyState !== WebSocket.OPEN) return; // offline: resumes with the session
    wsSend(_outbox.shift());
    _lastSentAt = Date.now();
    flushOutbox();
  }, wait);
}
function clearOutbox(chatId) {
  _outbox = chatId ? _outbox.filter(f => f.chatId !== chatId) : [];
  if (!_outbox.length) { clearTimeout(_outboxTimer); _outboxTimer = null; }
}

function closeChat(c) {
  clearOutbox(c.chatId);
  wsSend({ type: 'chat_end', chatId: c.chatId });
  chatMap.delete(c.chatId);
  show('main'); tab('messages');
}

$('btn-send').addEventListener('click', sendMessage);
$('btn-back').addEventListener('click', () => { show('main'); tab('messages'); });
$('btn-end').addEventListener('click', () => {
  const c = chatMap.get(openChatId);
  if (!c) return;
  if (c.closed) return closeChat(c); // already over: "close" just removes your copy
  confirmBox(`End chat with ${c.name}?`,
    c.ai ? 'The conversation is deleted.' : `It's removed from your list. ${c.name} keeps their copy until they close it, but can't write to you anymore.`,
    'End chat', () => { closeChat(c); note('Chat ended.'); });
});
$('btn-block').addEventListener('click', () => { const c = chatMap.get(openChatId); if (c && c.partnerId) blockPerson(c.partnerId); });
$('btn-report').addEventListener('click', () => { const c = chatMap.get(openChatId); if (c && c.partnerId) openReport(c.partnerId); });

$('chat-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && (e.shiftKey || e.altKey)) {
    e.preventDefault();
    const ta = $('chat-input');
    if (ta.classList.contains('at-height-limit')) return;
    const start = ta.selectionStart, end = ta.selectionEnd;
    ta.value = ta.value.slice(0, start) + '\n' + ta.value.slice(end);
    ta.selectionStart = ta.selectionEnd = start + 1;
    ta.dispatchEvent(new Event('input'));
    return;
  }
  if (e.key === 'Enter') { e.preventDefault(); sendMessage(); }
});

$('chat-input').addEventListener('input', () => {
  const ta = $('chat-input');
  const c = chatMap.get(openChatId);
  if (c && !c.closed) {
    const now = Date.now();
    if (now - (_lastTypingSent.get(c.chatId) || 0) > 2000) { _lastTypingSent.set(c.chatId, now); wsSend({ type: 'chat_typing', chatId: c.chatId }); }
  }
  ta.style.height = 'auto';
  ta.style.height = ta.scrollHeight + 'px';
  if (chatPinned) scrollChatToEnd();
  ta.classList.toggle('at-height-limit', ta.scrollHeight > 200);
  const counter = $('chat-char-count');
  const len = ta.value.length, max = parseInt(ta.getAttribute('maxlength'), 10) || 300;
  if (len / max >= 0.75) {
    counter.textContent = len + ' / ' + max;
    counter.classList.add('visible');
    counter.classList.toggle('urgent', len / max >= 0.9);
  } else {
    counter.textContent = '';
    counter.classList.remove('visible', 'urgent');
  }
});

// ── Block and report ──────────────────────────────────────────────────────────

function blockPerson(id) {
  const p = people.get(id);
  const name = p ? p.name : 'this person';
  confirmBox(`Block ${name}?`, "They can't find you or send you requests until one of you logs off. Any chat with them ends.", 'Block', () => {
    wsSend({ type: 'block', profileId: id });
    blocked.add(id);
    for (const [rid, r] of incoming) if (r.fromId === id) incoming.delete(rid);
    for (const [rid, r] of outgoing) if (r.toId === id) outgoing.delete(rid);
    for (const [cid, c] of chatMap) if (c.partnerId === id) { clearOutbox(cid); chatMap.delete(cid); }
    updateBadges();
    const wasChat = !$('view-chat').hidden;
    show('main'); tab(wasChat ? 'messages' : currentTab);
    note('Blocked.');
  });
}

let _reportId = null;
function openReport(id) {
  _reportId = id;
  const p = people.get(id);
  $('report-title').textContent = `Report ${p ? p.name : ''}`.trim();
  $('report-reason').value = '';
  $('report-details').value = '';
  $('report-char-count').textContent = '0 / 500';
  $('report-err').textContent = '';
  $('report-attach').checked = false;
  $('report-attach-row').hidden = !requestTexts.has(id);
  openModal('modal-report');
}
$('report-details').addEventListener('input', () => { $('report-char-count').textContent = $('report-details').value.length + ' / 500'; });
$('btn-report-cancel').addEventListener('click', () => closeModal('modal-report'));
$('btn-report-submit').addEventListener('click', () => {
  const reason = $('report-reason').value;
  if (!reason) { $('report-err').textContent = 'Select a reason.'; return; }
  const p = people.get(_reportId);
  lastAction = 'report';
  wsSend({
    type: 'report', profileId: _reportId, name: p ? p.name : '', reason,
    details: $('report-details').value.trim().slice(0, 500),
    ...($('report-attach').checked && requestTexts.has(_reportId) ? { requestText: requestTexts.get(_reportId) } : {}),
  });
});

// ── Modals ────────────────────────────────────────────────────────────────────

function openModal(id) { $(id).hidden = false; }
function closeModal(id) { $(id).hidden = true; }
let _confirmFn = null;
function confirmBox(title, body, okLabel, fn) {
  $('confirm-title').textContent = title;
  $('confirm-body').textContent = body;
  $('btn-confirm-ok').textContent = okLabel;
  _confirmFn = fn;
  openModal('modal-confirm');
  $('btn-confirm-ok').focus();
}
$('btn-confirm-ok').addEventListener('click', () => { closeModal('modal-confirm'); const f = _confirmFn; _confirmFn = null; if (f) f(); });
$('btn-confirm-cancel').addEventListener('click', () => { closeModal('modal-confirm'); _confirmFn = null; });
for (const m of document.querySelectorAll('.modal')) {
  m.addEventListener('click', e => { if (e.target === m) { m.hidden = true; if (m.id === 'modal-request') pendingRequest = null; } });
}
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  for (const m of document.querySelectorAll('.modal')) m.hidden = true;
  pendingRequest = null;
});

// ── Log off ───────────────────────────────────────────────────────────────────

$('btn-logoff').addEventListener('click', () => {
  if (!me) return;
  const nChats = chatMap.size, nIn = incoming.size, nOut = [...outgoing.values()].filter(r => r.state === 'pending').length;
  $('logoff-list').innerHTML = `<li>your profile: ${esc(me.name)}, ${plural(me.interests.length, 'interest')}</li>
    <li>your copy of ${plural(nChats, 'chat')} (the other person keeps theirs until they close it)</li>
    <li>${plural(nIn, 'request')} for you, ${nOut} you sent</li>`;
  openModal('modal-logoff');
  $('btn-logoff-cancel').focus();
});
$('btn-logoff-cancel').addEventListener('click', () => closeModal('modal-logoff'));
$('btn-logoff-ok').addEventListener('click', () => {
  closeModal('modal-logoff');
  if (!wsSend({ type: 'logoff' })) return gone('logoff');
  // The server confirms with logged_off; don't wait long for it
  setTimeout(() => { if (me) gone('logoff'); }, 1500);
});

const GONE = {
  logoff:   ['Deleted', "you're logged off, and everything is gone", 'Your profile, your requests and your chats were deleted from the server when you logged off. The people you talked to still have whatever they saw on their own screens.'],
  idle:     ['Deleted', 'logged off after 30 minutes without activity', 'Your profile, your requests and your chats were deleted from the server. The people you talked to still have whatever they saw on their own screens.'],
  timeout:  ['Lost', 'the connection was gone for too long', 'After 5 minutes without a connection, your profile, requests and chats were deleted from the server.'],
  replaced: ['Moved', 'continued in another tab', 'Your profile is now open in another tab. Nothing was deleted.'],
  server:   ['Deleted', 'you were logged off', 'Your profile, your requests and your chats are gone from the server.'],
};

// Everything local is forgotten too
function gone(reason) {
  const [title, sub, text] = GONE[reason] || GONE.server;
  me = null;
  if (ws) { ws._intentionalClose = true; if (reason !== 'replaced') ws.close(1000); ws = null; }
  wsVerified = false;
  keyPair = null;
  clearTimeout(_resumeTimer); _resumeDeadline = 0;
  clearOutbox();
  for (const map of [people, incoming, outgoing, chatMap, requestTexts]) map.clear();
  noAnswer.clear(); blocked.clear(); lastBuckets.clear();
  counts = { buckets: {}, top: [] }; allInterests = null; showAll = false; searchState = null; browseState = null; pendingRequest = null;
  for (const m of document.querySelectorAll('.modal')) m.hidden = true;
  clearBanner();
  $('gone-title').textContent = title; $('gone-sub').textContent = sub; $('gone-text').textContent = text;
  $('tagline').textContent = '';
  updateBadges();
  show('gone');
  refreshCount();
}

$('btn-again').addEventListener('click', () => {
  $('adult').checked = false;
  $('btn-go').disabled = false;
  renderTags();
  show('entry');
  prewarmChallenge();
  askForOtherTab();
});

// ── Banner: reconnecting, idle warning ────────────────────────────────────────

let _bannerKind = '', _idleTimer = null;
function setBanner(kind, html) { _bannerKind = kind; $('banner').innerHTML = html; }
function clearBanner(kind) {
  if (kind && _bannerKind !== kind) return;
  _bannerKind = ''; $('banner').innerHTML = ''; clearInterval(_idleTimer);
}

function showIdleWarning(seconds) {
  let left = seconds;
  const render = () => setBanner('idle', `<span>No activity for a while. You'll be logged off and everything deleted in <b>${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}</b>.</span> <button type="button" class="ghost accent" id="btn-still-here">I'm still here</button>`);
  render();
  clearInterval(_idleTimer);
  _idleTimer = setInterval(() => { left = Math.max(0, left - 1); if (_bannerKind === 'idle') render(); else clearInterval(_idleTimer); }, 1000);
  if (!$('view-chat').hidden) note("You'll be logged off soon for inactivity. Send a message or go back to stay online.");
}
$('banner').addEventListener('click', e => {
  if (e.target.id === 'btn-still-here') { wsSend({ type: 'still_here' }); clearBanner('idle'); }
});

// ── Tabs ──────────────────────────────────────────────────────────────────────

$('tab-discover').addEventListener('click', () => tab('discover'));
$('tab-requests').addEventListener('click', () => tab('requests'));
$('tab-messages').addEventListener('click', () => tab('messages'));

// Expiry countdowns and "results from" stay current
setInterval(() => { if (me && currentTab !== 'discover') renderCurrent(); }, 30_000);

// ── Page lifecycle ────────────────────────────────────────────────────────────

document.addEventListener('visibilitychange', () => {
  if (!me) return;
  if (document.visibilityState === 'visible') {
    if (!ws) return resumeSoon();
    watchCounts(true);
    wsSend({ type: 'still_here' });
    clearBanner('idle');
  } else {
    watchCounts(false);
  }
});

// Leaving the page logs off: nothing is kept for a reload or a return visit
// Reloading or closing while online would delete everything: ask first. The
// wording of this dialog is up to the browser; many phone browsers skip it.
window.addEventListener('beforeunload', e => {
  if (!me) return;
  e.preventDefault();
  e.returnValue = '';
});

window.addEventListener('pagehide', () => {
  if (me && ws && ws.readyState === WebSocket.OPEN) {
    ws._intentionalClose = true;
    wsSend({ type: 'logoff' });
  }
});

// ── Newest tab wins ───────────────────────────────────────────────────────────
// Tabs of the same browser talk over a BroadcastChannel (in memory, no
// storage). A new tab asks whether a profile is online; the old tab can hand
// over its session, and the server then closes the old tab's connection.

const channel = 'BroadcastChannel' in window ? new BroadcastChannel('emberline') : null;
let _handoverWanted = false;

function askForOtherTab() { if (channel && !me) channel.postMessage({ type: 'who' }); }

function exportSession() {
  return {
    me, accepting,
    keyPair: { publicKey: nacl.util.encodeBase64(keyPair.publicKey), secretKey: nacl.util.encodeBase64(keyPair.secretKey) },
    people: [...people.values()], incoming: [...incoming.values()], outgoing: [...outgoing.values()],
    chats: [...chatMap.values()], requestTexts: [...requestTexts], noAnswer: [...noAnswer], blocked: [...blocked],
  };
}

function importSession(s) {
  me = s.me;
  accepting = s.accepting;
  keyPair = { publicKey: nacl.util.decodeBase64(s.keyPair.publicKey), secretKey: nacl.util.decodeBase64(s.keyPair.secretKey) };
  for (const p of s.people) people.set(p.id, p);
  for (const r of s.incoming) incoming.set(r.requestId, r);
  for (const r of s.outgoing) outgoing.set(r.requestId, r);
  for (const c of s.chats) chatMap.set(c.chatId, c);
  for (const [k, v] of s.requestTexts) requestTexts.set(k, v);
  s.noAnswer.forEach(id => noAnswer.add(id));
  s.blocked.forEach(id => blocked.add(id));
}

if (channel) {
  channel.onmessage = async e => {
    const m = e.data || {};
    if (m.type === 'who' && me) channel.postMessage({ type: 'here', name: me.name });
    else if (m.type === 'here' && !me) { $('handover-name').textContent = m.name; $('handover').hidden = false; }
    else if (m.type === 'handover_request' && me) channel.postMessage({ type: 'handover', session: exportSession() });
    else if (m.type === 'handover' && _handoverWanted && !me) {
      _handoverWanted = false;
      importSession(m.session);
      $('handover').hidden = true;
      show('main'); tab('discover');
      updateBadges();
      try {
        await connect();
        lastAction = 'resume';
        wsSend({ type: 'resume', resumeToken: me.resumeToken });
        if (me.interests[0]) search(me.interests[0]);
      } catch { connectionLost(); }
    }
  };
}
$('btn-handover').addEventListener('click', () => { _handoverWanted = true; channel.postMessage({ type: 'handover_request' }); });

// ── Live count and AI availability ────────────────────────────────────────────

const EMBER_PHRASES = [
  'ember is online', 'embers are online', 'embers are sparkling', 'embers are glowing',
  'embers are wandering', 'embers are awake', 'embers are out tonight', 'embers are burning',
];
async function refreshCount() {
  try {
    const data = await (await fetch('/count')).json();
    if (me) {
      if (aiAvailable !== !!data.ai) { aiAvailable = !!data.ai; if (currentTab === 'discover') renderDiscover(); }
      return;
    }
    const n = data.count || 0;
    const phrase = n === 1 ? EMBER_PHRASES[0] : EMBER_PHRASES[Math.floor(Math.random() * (EMBER_PHRASES.length - 1)) + 1];
    $('tagline').textContent = n + ' ' + phrase;
  } catch {}
}
refreshCount();
setInterval(() => { if (document.visibilityState === 'visible') refreshCount(); }, 30_000);

// ── Theme toggle ──────────────────────────────────────────────────────────────
// Theme follows the OS colour scheme on every page load (prefers-color-scheme
// is already exposed to CSS, so reading it adds no fingerprinting surface).
// The toggle persists only for the current session — no storage of any kind.

(function initTheme() {
  const light = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  setTheme(light ? 'light' : 'dark');
})();
function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = $('btn-theme');
  btn.textContent = theme === 'dark' ? '☀' : '☾';
  btn.title = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
}
$('btn-theme').addEventListener('click', () => {
  setTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
});

// ── Entry wiring ──────────────────────────────────────────────────────────────

$('btn-go').addEventListener('click', goOnline);

// Footer links open in a new tab while online, so reading the policy doesn't log you off
for (const a of document.querySelectorAll('footer a[href^="/"], .check a')) { a.target = '_blank'; a.rel = 'noopener'; }

// Pre-warm the proof-of-work on first interaction, not on load: crawlers and
// tabs closed right away don't cost a /challenge token.
let _prewarmed = false;
function triggerPrewarm() { if (_prewarmed) return; _prewarmed = true; prewarmChallenge(); }
for (const id of ['name-input', 'keyword-input']) {
  $(id).addEventListener('focus', triggerPrewarm, { once: true });
  $(id).addEventListener('keydown', triggerPrewarm, { once: true });
}

renderTags();
show('entry');
askForOtherTab();

// ── Install link ─────────────────────────────────────────────────────────────
// Shown in the footer on browsers that support installing Emberline as a PWA.
// Three cases:
//   1. Already installed (standalone display mode) → hide link entirely
//   2. Chrome/Edge/Android Chrome → capture beforeinstallprompt, click triggers native prompt
//   3. iOS Safari → prompt unavailable; click opens a small modal with instructions

(function installLink() {
  const link = $('install-link');
  const sep  = $('install-sep');
  if (!link || !sep) return;
  link.target = ''; // opens a prompt, not a page
  const isStandalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
  if (isStandalone) return;
  const isIOS = /iPhone|iPad|iPod/.test(navigator.userAgent) && !window.MSStream;
  let deferredPrompt = null;
  const showLink = () => { link.classList.add('shown'); sep.classList.add('shown'); };
  const hideLink = () => { link.classList.remove('shown'); sep.classList.remove('shown'); };

  if (isIOS) {
    showLink();
    const modal = $('install-ios');
    link.addEventListener('click', e => { e.preventDefault(); modal.hidden = false; });
    $('btn-install-close').addEventListener('click', () => { modal.hidden = true; });
    return;
  }
  window.addEventListener('beforeinstallprompt', e => { e.preventDefault(); deferredPrompt = e; showLink(); });
  link.addEventListener('click', async e => {
    e.preventDefault();
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    deferredPrompt = null;
    if (outcome === 'accepted') hideLink();
  });
  window.addEventListener('appinstalled', hideLink);
})();
