const WS_URL = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`;

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
  const data = await res.json();
  const nonce = await solveChallenge(data.prefix, data.difficulty);
  return { token: data.token, nonce };
}

// ── Pre-warm cache: solve PoW and generate keypair before the user clicks ────
let _cachedPow    = null;   // { token, nonce, solvedAt }
let _powPromise   = null;   // in-flight pre-solve

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
    _cachedPow = null;          // consume it — one use only
    prewarmChallenge();         // start solving the next one in background
    return pow;
  }
  _cachedPow = null;
  return fetchAndSolveChallenge();
}

let ws   = null;
let tags = [];

// ── E2EE state ─────────────────────────────────────────────────────────────
let myKeyPair     = null;   // nacl box keypair (generated fresh each session)
let sharedSecret  = null;   // nacl box shared key derived after match


function show(section) {
  // entry and waiting toggled via inline style
  ['entry','waiting'].forEach(s =>
    document.getElementById('section-'+s).style.display = s===section ? 'flex' : 'none'
  );
  // matched is controlled by body.is-matched CSS class, not inline style
}

// ── Tag pill UI ───────────────────────────────────────────────────────────────

function addTag(raw) {
  const word = raw.trim().toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 20);
  if (!word || tags.includes(word) || tags.length >= 10) return;
  tags.push(word);
  renderTags();
}

function removeTag(word) {
  tags = tags.filter(t => t !== word);
  renderTags();
}

function renderTags() {
  const list = document.getElementById('tag-list');
  list.innerHTML = '';
  tags.forEach(word => {
    const pill = document.createElement('span');
    pill.className = 'tag-pill';
    const label = document.createTextNode(word);
    const btn = document.createElement('button');
    btn.title = 'remove';
    btn.textContent = '×';
    btn.addEventListener('click', () => removeTag(word));
    pill.appendChild(label);
    pill.appendChild(btn);
    list.appendChild(pill);
  });
  // Update placeholder
  const input = document.getElementById('keyword-input');
  input.placeholder = tags.length === 0 ? 'type a word, press Enter\u2026' :
                      tags.length < 10  ? 'add another\u2026' : '';
  input.disabled = tags.length >= 10;
  // Update button state
  document.getElementById('btn-enter').disabled = tags.length === 0;
}

// ── Safe DOM helpers ──────────────────────────────────────────────────────────

function resetChatBox(text) {
  const box = document.getElementById('chat-box');
  box.innerHTML = '';
  const d = document.createElement('div');
  d.className = 'msg system';
  d.textContent = text || 'Finding your match…';
  box.appendChild(d);
}

// ── Connect & send ────────────────────────────────────────────────────────────

function connect() {
  return new Promise((resolve, reject) => {
    ws = new WebSocket(WS_URL);
    ws._intentionalClose = false;
    ws.onopen    = () => resolve();
    ws.onerror   = () => reject();
    ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      handleMessage(msg);
    };
    ws.onclose   = (event) => {
      // Connection cap — too many users sharing this IP
      if (event.code === 4429) {
        show('entry');
        document.getElementById('btn-enter').disabled = tags.length === 0;
        alert('Too many connections from your IP address. If you\'re using a VPN, try switching servers or disconnecting it.\n\nEmberline is end-to-end encrypted and does not log IP addresses — your privacy is protected without a VPN.');
        if (ws) { ws._intentionalClose = true; ws = null; }
        return;
      }
      // Only show "connection lost" for unexpected drops during an active conversation.
      // Intentional closes (Leave, Next →) set ws._intentionalClose = true first.
      if (!ws._intentionalClose && document.body.classList.contains('is-matched')) {
        appendSystemMsg('Connection lost.');
      }
    };
  });
}

function wsSend(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

// ── Incoming messages ─────────────────────────────────────────────────────────

function handleMessage(msg) {
  if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;
  switch (msg.type) {
    case 'waiting': break;

    case 'error':
      if (msg.code === 'challenge_expired') {
        appendSystemMsg('Connection challenge expired — please try again.');
        cancelSearch();
      }
      break;

    case 'matched':
      clearTimeout(window._matchFallbackTimer);
      document.body.classList.add('is-matched');
      if (msg.partnerPubKey && myKeyPair) {
        const partnerPub = nacl.util.decodeBase64(msg.partnerPubKey);
        sharedSecret = nacl.box.before(partnerPub, myKeyPair.secretKey);
      }
      const matchedKws = Array.isArray(msg.matchedKeywords) ? msg.matchedKeywords : [];
      const isRandom = matchedKws.length === 0;
      const chatBox = document.getElementById('chat-box');
      chatBox.innerHTML = '';
      const sysDiv = document.createElement('div');
      sysDiv.className = 'msg system';
      if (isRandom) {
        sysDiv.textContent = 'Connected to a random ember.';
      } else if (matchedKws.length === 1) {
        sysDiv.textContent = 'Match found on ';
        const em = document.createElement('em');
        em.style.fontFamily = '"Unbounded", sans-serif';
        em.style.color = '#c87941';
        em.textContent = matchedKws[0];
        sysDiv.appendChild(em);
        sysDiv.appendChild(document.createTextNode('.'));
      } else {
        sysDiv.textContent = 'Match found on ';
        matchedKws.forEach((kw, i) => {
          if (i > 0 && i < matchedKws.length - 1) sysDiv.appendChild(document.createTextNode(', '));
          if (i > 0 && i === matchedKws.length - 1) sysDiv.appendChild(document.createTextNode(' and '));
          const em = document.createElement('em');
          em.style.fontFamily = '"Unbounded", sans-serif';
          em.style.color = '#c87941';
          em.textContent = kw;
          sysDiv.appendChild(em);
        });
        sysDiv.appendChild(document.createTextNode('.'));
      }
      chatBox.appendChild(sysDiv);
      show('matched');
      break;

    case 'message': {
      let plaintext = msg.text || '';
      if (msg.ciphertext && msg.nonce && sharedSecret) {
        try {
          const decrypted = nacl.box.open.after(
            nacl.util.decodeBase64(msg.ciphertext),
            nacl.util.decodeBase64(msg.nonce),
            sharedSecret
          );
          if (decrypted) plaintext = nacl.util.encodeUTF8(decrypted);
          else plaintext = '[decryption failed]';
        } catch(e) {
          plaintext = '[decryption error]';
        }
      }
      hideTypingIndicator();
      appendMsg(plaintext, 'them');
      break;
    }

    case 'typing':
      showTypingIndicator();
      break;

    case 'partner_left':
      hideTypingIndicator();
      appendSystemMsg('Your match left the conversation.');
      document.getElementById('chat-input').disabled = true;
      document.getElementById('btn-send').disabled = true;
      break;

    default:
      // Unknown message type — ignore silently
      break;
  }
}

// ── Entry point ───────────────────────────────────────────────────────────────

async function enterKeyword() {
  // Also add whatever is currently typed in the input as a tag
  const inputVal = document.getElementById('keyword-input').value.trim();
  if (inputVal) { addTag(inputVal); document.getElementById('keyword-input').value = ''; }

  if (tags.length === 0) return;

  document.getElementById('btn-enter').disabled = true;

  // Show all keywords as badges in the waiting screen
  const displayEl = document.getElementById('display-keyword');
  displayEl.innerHTML = '';
  tags.forEach(t => {
    const span = document.createElement('span');
    span.className = 'keyword-badge';
    span.style.margin = '2px';
    span.textContent = t;
    displayEl.appendChild(span);
  });

  show('waiting');
  // Clear any stale fallback text from a previous search
  const waitingInfoEl = document.getElementById('waiting-info');
  if (waitingInfoEl) waitingInfoEl.textContent = '';

  // Keypair is pre-generated on page load; regenerate only if missing
  if (!myKeyPair) myKeyPair = nacl.box.keyPair();
  const pubKeyB64 = nacl.util.encodeBase64(myKeyPair.publicKey);

  // PoW is pre-solved on page load — getPow() returns instantly if cached
  let pow;
  try {
    [, pow] = await Promise.all([
      connect(),
      getPow()
    ]);
  } catch(e) {
    alert('Could not reach the server. Make sure server.js is running.');
    show('entry');
    document.getElementById('btn-enter').disabled = false;
    if (ws) { ws.close(); ws = null; }
    return;
  }

  wsSend({ type: 'join', keywords: tags, pubKey: pubKeyB64, token: pow.token, nonce: pow.nonce });

  // Fallback: if no keyword match after 10s, also join the random pool.
  // We send ALL current tags plus __random__ so the server registers us
  // in every pool simultaneously — the original keywords are NOT abandoned.
  window._matchFallbackTimer = setTimeout(async () => {
    if (document.getElementById('section-waiting').style.display !== 'none') {
      const el = document.getElementById('waiting-info');
      if (el) el.textContent = 'No keyword match yet — trying random…';
      let pow2;
      try { pow2 = await getPow(); } catch(e) { return; }
      wsSend({ type: 'join', keywords: [...tags, '__random__'], pubKey: pubKeyB64, token: pow2.token, nonce: pow2.nonce });
    }
  }, 10000);
}

// ── Chat ──────────────────────────────────────────────────────────────────────

function appendMsg(text, side) {
  const box = document.getElementById('chat-box');
  const atBottom = box.scrollHeight - box.scrollTop <= box.clientHeight + 20;
  const d = document.createElement('div');
  d.className = 'msg ' + side;
  d.textContent = text;

  box.appendChild(d);
  if (atBottom) requestAnimationFrame(() => { box.scrollTop = box.scrollHeight; });
}

function appendSystemMsg(text) {
  const box = document.getElementById('chat-box');
  const d = document.createElement('div');
  d.className = 'msg system';
  d.textContent = text;
  box.appendChild(d);
  requestAnimationFrame(() => { box.scrollTop = box.scrollHeight; });
}

// ── Typing indicator ─────────────────────────────────────────────────────────

let _typingTimeout = null;
let _lastTypingSent = 0;

function showTypingIndicator() {
  const box = document.getElementById('chat-box');
  let el = document.getElementById('typing-indicator');
  if (!el) {
    el = document.createElement('div');
    el.id = 'typing-indicator';
    el.className = 'typing-indicator';
    el.textContent = 'typing...';
  }
  el.style.display = 'block';
  box.appendChild(el);
  requestAnimationFrame(() => { box.scrollTop = box.scrollHeight; });
  clearTimeout(_typingTimeout);
  _typingTimeout = setTimeout(hideTypingIndicator, 3000);
}

function hideTypingIndicator() {
  const el = document.getElementById('typing-indicator');
  if (el) el.remove();
  clearTimeout(_typingTimeout);
}

function sendTypingEvent() {
  const now = Date.now();
  if (now - _lastTypingSent < 2000) return;
  _lastTypingSent = now;
  wsSend({ type: 'typing' });
}

function sendMessage() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text) return;
  if (!sharedSecret) {
    appendSystemMsg('Encryption not established — cannot send message.');
    return;
  }
  input.value = '';
  input.style.height = 'auto';
  input.classList.remove('at-height-limit');
  hideTypingIndicator();
  // Encrypt with a random nonce; send nonce + ciphertext (both base64)
  const nonce      = nacl.randomBytes(nacl.box.nonceLength);
  const ciphertext = nacl.box.after(nacl.util.decodeUTF8(text), nonce, sharedSecret);
  wsSend({
    type:       'message',
    ciphertext: nacl.util.encodeBase64(ciphertext),
    nonce:      nacl.util.encodeBase64(nonce)
  });
  appendMsg(text, 'me');
}

// ── Cancel / Leave ────────────────────────────────────────────────────────────

function resetEntry(keepTags) {
  if (!keepTags) tags = [];
  renderTags();
  document.getElementById('keyword-input').value = '';
  document.getElementById('keyword-input').disabled = false;
}

function cancelSearch() {
  clearTimeout(window._matchFallbackTimer);
  wsSend({ type: 'leave' });
  if (ws) { ws._intentionalClose = true; ws.close(); ws = null; }
  myKeyPair    = null;
  sharedSecret = null;
  resetEntry(true);
  show('entry');
  // Pre-warm for the next attempt
  myKeyPair = nacl.box.keyPair();
  prewarmChallenge();
}

function leaveChat() {
  wsSend({ type: 'leave' });
  if (ws) { ws._intentionalClose = true; ws.close(); ws = null; }
  myKeyPair    = null;
  sharedSecret = null;
  hideTypingIndicator();
  document.body.classList.remove('is-matched');
  document.getElementById('chat-input').disabled = false;
  document.getElementById('btn-send').disabled = false;
  resetChatBox();
  resetEntry(true);
  show('entry');
  // Pre-warm for the next session while user is back on entry
  myKeyPair = nacl.box.keyPair();
  prewarmChallenge();
}

async function nextConversation() {
  // Tell the server to leave the current room — but keep the WS connection open.
  // There is no need to disconnect and reconnect: the same verified connection
  // can simply rejoin. This avoids the timing check, a new PoW solve, a new
  // TCP + WS handshake, and all the complexity that caused previous regressions.
  wsSend({ type: 'leave' });

  // Reset E2EE — generate a fresh keypair for the new session
  myKeyPair    = nacl.box.keyPair();
  sharedSecret = null;

  hideTypingIndicator();
  document.body.classList.remove('is-matched');
  document.getElementById('chat-input').disabled = false;
  document.getElementById('btn-send').disabled = false;
  resetChatBox();
  clearTimeout(window._matchFallbackTimer);

  if (tags.length === 0) { show('entry'); return; }

  const displayEl = document.getElementById('display-keyword');
  displayEl.innerHTML = '';
  tags.forEach(t => {
    const span = document.createElement('span');
    span.className = 'keyword-badge';
    span.style.margin = '2px';
    span.textContent = t;
    displayEl.appendChild(span);
  });

  show('waiting');
  // Clear any stale fallback text from a previous search
  const waitingInfoEl = document.getElementById('waiting-info');
  if (waitingInfoEl) waitingInfoEl.textContent = '';

  // Reuse the already-verified connection — send join immediately
  const pubKeyB64 = nacl.util.encodeBase64(myKeyPair.publicKey);
  wsSend({ type: 'join', keywords: tags, pubKey: pubKeyB64 });

  window._matchFallbackTimer = setTimeout(async () => {
    if (document.getElementById('section-waiting').style.display !== 'none') {
      const el = document.getElementById('waiting-info');
      if (el) el.textContent = 'No keyword match yet — trying random…';
      wsSend({ type: 'join', keywords: [...tags, '__random__'], pubKey: pubKeyB64 });
    }
  }, 10000);
}

// ── Keyboard listeners ────────────────────────────────────────────────────────

document.getElementById('keyword-input').addEventListener('keydown', e => {
  const input = e.target;
  // Space creates a tag from whatever is typed
  if (e.key === ' ') {
    e.preventDefault();
    if (input.value.trim()) { addTag(input.value); input.value = ''; }
  }
  // Enter creates a tag (same as Space)
  if (e.key === 'Enter') {
    e.preventDefault();
    if (input.value.trim()) { addTag(input.value); input.value = ''; }
  }
  // Backspace on empty input removes last tag
  if (e.key === 'Backspace' && input.value === '' && tags.length > 0) {
    removeTag(tags[tags.length - 1]);
  }
});

// Expose globals
// ── Report ───────────────────────────────────────────────────────────────────

function openReport() {
  const modal = document.getElementById('report-modal');
  modal.style.display = 'flex';
  // Wire up live character counter (idempotent)
  const ta = document.getElementById('report-details');
  const counter = document.getElementById('report-char-count');
  ta.oninput = () => {
    const len = ta.value.length;
    counter.textContent = len + ' / 500';
    counter.style.color = len > 450 ? '#c87941' : '#4a4038';
  };
}

function closeReport() {
  document.getElementById('report-modal').style.display = 'none';
  document.getElementById('report-reason').value = '';
  document.getElementById('report-details').value = '';
  document.getElementById('report-char-count').textContent = '0 / 500';
}

async function submitReport() {
  const reason  = document.getElementById('report-reason').value;
  const details = document.getElementById('report-details').value.trim().slice(0, 500);
  if (!reason) { alert('Please select a reason.'); return; }
  try {
    await fetch('/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason, details, ts: new Date().toISOString() })
    });
  } catch(e) {}
  closeReport();
  appendSystemMsg('Report submitted. Thank you.');
}

// ── Live user count ──────────────────────────────────────────────────────────

const EMBER_PHRASES = [
  'ember is sparkling',
  'embers are sparkling',
  'embers are glowing',
  'embers are wandering',
  'embers are drifting',
  'embers are awake',
  'embers are out tonight',
  'embers are searching',
  'embers are burning',
  'embers are waiting',
];

async function refreshCount() {
  try {
    const res  = await fetch('/count');
    const data = await res.json();
    const n    = data.count || 0;
    const phrase = n === 1 ? EMBER_PHRASES[0] : EMBER_PHRASES[Math.floor(Math.random() * (EMBER_PHRASES.length - 1)) + 1];
    document.getElementById('user-count').textContent = n + ' ' + phrase;
  } catch(e) {}
}

refreshCount();
setInterval(() => {
  if (document.visibilityState !== 'visible') return;
  // Only poll while the user is on the entry screen — during a match
  // or while waiting, the live count isn't shown and isn't useful.
  // section-entry.style.display is '' on first load (visible) or 'flex' when
  // explicitly shown; 'none' only when we've navigated away.
  if (document.getElementById('section-entry').style.display === 'none') return;
  refreshCount();
}, 60000);

// ── Theme toggle ──────────────────────────────────────────────────────────────
// Theme defaults to dark on every page load. Toggle persists only for the
// current session — no localStorage, no cookie, no tracking of preference.

(function initTheme() {
  document.documentElement.setAttribute('data-theme', 'dark');
  updateThemeBtn('dark');
})();

function updateThemeBtn(theme) {
  const btn = document.getElementById('btn-theme');
  if (!btn) return;
  btn.textContent = theme === 'dark' ? '☀' : '☾';
  btn.title = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
}

document.getElementById('btn-theme').addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next    = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  updateThemeBtn(next);
});

// ── Wire up all button event listeners (no inline onclick handlers) ───────────

document.getElementById('tag-field').addEventListener('click', () =>
  document.getElementById('keyword-input').focus()
);
document.getElementById('btn-enter').addEventListener('click', enterKeyword);
document.getElementById('btn-cancel').addEventListener('click', cancelSearch);
document.getElementById('btn-send').addEventListener('click', sendMessage);
document.getElementById('btn-leave').addEventListener('click', leaveChat);
document.getElementById('btn-report').addEventListener('click', openReport);
document.getElementById('btn-next').addEventListener('click', nextConversation);
document.getElementById('btn-report-cancel').addEventListener('click', closeReport);
document.getElementById('btn-report-submit').addEventListener('click', submitReport);
document.getElementById('chat-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && (e.shiftKey || e.altKey)) {
    e.preventDefault();
    const ta = document.getElementById('chat-input');
    if (ta.classList.contains('at-height-limit')) return;
    const start = ta.selectionStart;
    const end   = ta.selectionEnd;
    ta.value = ta.value.slice(0, start) + '\n' + ta.value.slice(end);
    ta.selectionStart = ta.selectionEnd = start + 1;
    ta.dispatchEvent(new Event('input'));
    return;
  }
  if (e.key === 'Enter' && !e.shiftKey && !e.altKey) { e.preventDefault(); sendMessage(); }
});

document.getElementById('chat-input').addEventListener('input', () => {
  const ta = document.getElementById('chat-input');
  sendTypingEvent();
  // Auto-grow up to max-height
  ta.style.height = 'auto';
  ta.style.height = ta.scrollHeight + 'px';
  // Height limit feedback
  const atLimit = ta.scrollHeight > 200;
  ta.classList.toggle('at-height-limit', atLimit);
  // Character counter
  const counter = document.getElementById('chat-char-count');
  if (!counter) return;
  const len = ta.value.length;
  const max = parseInt(ta.getAttribute('maxlength'), 10) || 300;
  const pct = len / max;
  if (pct >= 0.75) {
    counter.textContent = len + ' / ' + max;
    counter.classList.add('visible');
    counter.classList.toggle('urgent', pct >= 0.9);
  } else {
    counter.textContent = '';
    counter.classList.remove('visible', 'urgent');
  }
});



// Notify partner if user closes the tab or navigates away mid-conversation.
// navigator.sendBeacon isn't suitable here (HTTP only); a synchronous WS send
// on beforeunload works in most browsers for small frames.
window.addEventListener('beforeunload', () => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    wsSend({ type: 'leave' });
  }
});

// No pre-loaded tags — user starts with an empty field

// ── Pre-warm: deferred until first user interaction ──────────────────────────
// Crawlers, link-preview unfurls, and tabs closed immediately after load no
// longer consume a /challenge token or server CPU. First focus OR first
// keydown on the keyword input kicks off the keypair + PoW solve in the
// background. By the time the user has typed a tag and clicked Find, both
// are ready. If somehow the user clicks Find without any interaction,
// enterKeyword() generates the keypair on demand and getPow() solves fresh.

let _prewarmed = false;
function triggerPrewarm() {
  if (_prewarmed) return;
  _prewarmed = true;
  myKeyPair = nacl.box.keyPair();
  prewarmChallenge();
}
const _kwInput = document.getElementById('keyword-input');
_kwInput.addEventListener('focus',   triggerPrewarm, { once: true });
_kwInput.addEventListener('keydown', triggerPrewarm, { once: true });
