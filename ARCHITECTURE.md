# Emberline — Project Instructions

> Anonymous keyword-based chat · Node.js + WebSocket · E2EE (NaCl) · Swiss jurisdiction
>
> **Design priorities, in order: User Experience → Privacy → Security → Simplicity**

---

## 1. Project Identity

Emberline is an ephemeral, anonymous chat platform that matches strangers on shared keywords. No accounts, no message storage, no identity. Every session is disposable.

**Aesthetic:** deep-evening warm-dark. `#1c1713` paper, `#c87941` amber accent, Unbounded for headings, Inter for body.

**The rule above all rules:** prefer the lean solution. If a problem can be solved with one line, do not write ten. Every layer of complexity is a future bug.

---

## 2. Architecture

```
User → emberline.ch → Swiss VPS (Caddy TLS, logs disabled) → WireGuard tunnel → Raspberry Pi 4 (Docker)

Browser
  │  WebSocket (wss://)                HTTP REST
  │  E2EE via NaCl box                /challenge  /count  /report
  ▼
server.js  (Node.js · Express + ws, inside Docker container)
  ├── waitingPool   Map<keyword, Set<ws>>
  ├── rooms         Map<roomId, {a, b}>
  ├── challenges    Map<token, {prefix, expiresAt}>
  └── rate maps     (all ephemeral, never written to disk)

app.js     (browser — single JS file, no framework)

Persistent files (append-only, no message content):
  reports.log   reason + server timestamp only (no IPs)
  abuse.log     event type + timestamp + IP  (for Fail2Ban)
```

**No database. No sessions. No persistence beyond the two log files.**

**Infrastructure:**
- **VPS:** Plan-les-Ouates CH. Runs Caddy (TLS reverse proxy, access logs discarded) and WireGuard.
- **Pi:** Raspberry Pi 4, 4GB RAM, passive heatsink, USB boot (SanDisk), wired Ethernet. Runs OpenMediaVault 7 + Docker.
- **Domain:** `emberline.ch` Domain Privacy enabled.
- **Email:** `contactall@emberline.ch`

---

## 3. File Structure

```
/
├── index.html          — Single-page frontend (CSS inline, JS via src)
├── app.js              — All client-side logic (~680 lines)
├── server.js           — Node.js WebSocket + HTTP server (~815 lines)
├── package.json        — Dependencies: express ^4, ws ^8
├── setup-assets.js     — One-time asset downloader (fonts + NaCl)
├── manifest.json       — PWA manifest
├── sw.js               — Service worker (caches app shell)
├── reports.log         — Abuse reports (auto-created)
├── abuse.log           — Fail2Ban feed (auto-created)
├── icons/
│   ├── icon-192.png    — PWA icon (ember flame)
│   └── icon-512.png    — PWA icon large
├── fonts/
│   ├── fonts.css
│   └── *.woff2         — Unbounded + Inter (self-hosted)
└── vendor/
    ├── nacl-fast.min.js
    └── nacl-util.min.js
```

---

## 4. Matching — How It Works

The matching algorithm is O(keywords × pool_size) and runs synchronously in the `join` handler. It is fast enough for single-instance deploys. Do not over-engineer it.

### Pre-warming

Pre-warming is **deferred until the first user interaction** with the keyword input (first `focus` or first `keydown`, whichever comes first). On that first interaction:
1. A keypair is generated: `myKeyPair = nacl.box.keyPair()`
2. A PoW challenge is fetched and solved in the background via `prewarmChallenge()`

Crawlers, link-preview unfurls, and quick-bounce visitors never consume a `/challenge` slot or waste server CPU. By the time the user has typed a tag and clicked "Find my match", both the keypair and a solved PoW are cached. If somehow the user clicks Find without any prior interaction, `enterKeyword()` generates the keypair on demand and `getPow()` falls through to a fresh solve — the critical path still works, just slightly slower.

### First match (`enterKeyword`)

1. User clicks → `connect()` opens the WebSocket
2. `join` is sent with keywords + pre-solved PoW token + pre-generated public key
3. Server matches immediately if a partner is waiting, otherwise registers client in pool
4. After 10s with no keyword match, client sends a second `join` for `__random__`

### Next → (`nextConversation`)

- The existing WebSocket is **kept open** — no disconnect, no reconnect
- `leave` is sent to clean up the current room server-side
- A fresh E2EE keypair is generated client-side
- `join` is sent immediately on the same verified connection
- No new PoW solve needed — `ws._verified` persists for the connection lifetime
- This is why Next → is instant: zero reconnect overhead, zero re-verification

### The lesson

When Next → broke, successive fixes (Worker threads, pre-warming, parallel solvers) added complexity and introduced new bugs each time. The right answer was one architectural insight — reuse the connection — not more code. When something breaks, question the assumption before adding a layer.

---

## 5. Security

### 5.1 Bot & Abuse Defences

| Layer | Mechanism | Config constant |
|---|---|---|
| Proof-of-Work | SHA-256 hash prefix, 4 leading zeros | `POW_DIFFICULTY = 4` |
| Timing | Reject `join` < 200ms after connect | `MIN_JOIN_DELAY_MS = 200` |
| Honeypot keyword | `__honeypot__` → flag + block IP for 24h | `HONEYPOT_KEYWORD` |
| WS connection rate | Max 20 new connections/min/IP | `MAX_WS_CONNECTS_PER_MIN` |
| Concurrent WS cap | Max 20 open sockets/IP | `MAX_CONNS_PER_IP` |
| HTTP API rate | Max 60 req/min/IP (API routes only) | `MAX_HTTP_API_RPM` |
| HTTP static rate | Max 300 req/min/IP (assets only) | `MAX_HTTP_STATIC_RPM` |
| Challenge rate | Max 60 tokens/hour/IP | `MAX_CHALLENGES_PER_IP` |
| Report rate | Max 10 reports/hour/IP | `MAX_REPORTS_PER_IP` |
| Memory ceilings | Hard caps on all Maps | `MAX_WAITING_POOL_KEYS` etc. |

**Connection cap and VPN users:** `MAX_CONNS_PER_IP` was raised from 5 to 20 to accommodate VPN users who share exit IPs. When the cap is hit, the server closes the connection with custom WebSocket code `4429`. The client detects this and shows an alert explaining the issue with a privacy reassurance: "Emberline is end-to-end encrypted and does not log IP addresses — your privacy is protected without a VPN."

**Rate limiting uses two separate budgets** — static assets (fonts, JS) and API routes — so a page load never consumes the user's matching budget.

**PoW difficulty:** each +1 roughly doubles client solve time. At difficulty 4, expect 50–200ms. At 5, ~300ms. Do not exceed 6 without measuring UX impact. PoW is the primary bot defence; timing check is supplementary.

### 5.2 Input Validation

All WebSocket frames are hard-capped at **4096 bytes** at the `ws` library level (`maxPayload: 4096`) before Node.js sees them. Then:

- Keywords: `toLowerCase().replace(/[^a-z0-9_]/g, '')`, max 10 keywords, 20 chars each, sliced to `MAX_KEYWORD_POOLS` (11, including `__random__`)
- `pubKey`: string, max 64 chars
- `ciphertext`: max 800 chars
- `nonce`: max 50 chars
- Report `reason`: allowlist — `csam`, `harassment`, `illegal`, `spam`
- Report `details`: `replace(/[<>]/g, '').trim().slice(0, 500)`

Never relax these caps without a documented reason.

### 5.3 Security Headers

Every HTTP response carries:

```
Content-Security-Policy:
  default-src 'none'
  script-src 'self'
  style-src 'self' 'unsafe-inline'   ← required for inline <style> in index.html
  font-src 'self'
  img-src 'self'
  connect-src 'self' ws: wss:
  manifest-src 'self'
  worker-src 'self'
  frame-ancestors 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
```

All JavaScript lives in `app.js` (external file), so `script-src 'self'` is fully effective.

### 5.4 E2EE

A keypair is **generated on first user interaction** with the keyword input (see §4 Pre-warming for why). Each **Next →** also generates a fresh keypair and discards the old shared secret. Public keys are exchanged in the `matched` event. Both peers derive `sharedSecret = nacl.box.before(partnerPub, mySecretKey)`.

Messages use `nacl.box.after(plaintext, nonce, sharedSecret)` with `nonce = nacl.randomBytes(24)`. Nonces are never reused.

The server is a **blind relay** — it forwards `{ ciphertext, nonce }` only. The plaintext relay path was removed intentionally and must not be restored.

### 5.5 XSS Prevention

No `innerHTML` is used with any user-controlled or server-supplied data. All dynamic DOM writes use `createElement` / `textContent`. No inline `onclick` attributes — all handlers are wired via `addEventListener` in `app.js`.

### 5.6 Room IDs

Room IDs are generated with `crypto.randomBytes(8).toString('hex')` — 64-bit cryptographically random. `Math.random()` is never used for security-relevant values.

### 5.7 Fail2Ban Integration

`abuse.log` is written at every rejection point:
```
2026-03-28T12:00:00Z [pow_fail] ip=1.2.3.4
```

Rejection labels: `pow_fail` `too_fast` `honeypot` `conn_cap` `ws_rate` `flagged_ip` `http_flood`

**Filter** (`/etc/fail2ban/filter.d/emberline.conf`):
```ini
[Definition]
failregex = ^.+ \[pow_fail\] ip=<HOST>$
            ^.+ \[too_fast\] ip=<HOST>$
            ^.+ \[honeypot\] ip=<HOST>$
            ^.+ \[conn_cap\] ip=<HOST>$
            ^.+ \[ws_rate\] ip=<HOST>$
ignoreregex =
```

**Jail** (`/etc/fail2ban/jail.d/emberline.conf`):
```ini
[emberline]
enabled  = true
filter   = emberline
logpath  = /home/ember/abuse.log
maxretry = 5
findtime = 600
bantime  = 3600
action   = ufw
```

---

## 6. Privacy

### 6.1 What Is Stored

| Data | Where | Duration |
|---|---|---|
| Keywords | RAM only | Until match or session ends |
| Public keys | RAM only (ws object) | Until session ends |
| Challenge tokens | RAM | Max 60s (`CHALLENGE_TTL_MS`) |
| IP connection counts | RAM only | Until all connections from IP close |
| Flagged IPs | RAM (TTL Map) | 24h, then auto-evicted hourly |
| All rate maps | RAM only | Evicted hourly |
| Report entries | `reports.log` | 90 days max (Privacy Policy) |
| Abuse events | `abuse.log` | Rotate at 90 days |
| Chat messages | **Never stored** | — |

IPs appear only in RAM maps and `abuse.log`. They are **never** in `reports.log`.

**The IP tradeoff, stated honestly.** `abuse.log` persists IP addresses for up to 90 days. This is the single deliberate deviation from a "no logs" posture and it needs to be defended, not hidden. An unauthenticated anonymous chat service has no other line of defense against abuse — without IP-based rate limiting and Fail2Ban, the service dies within hours of launch to a trivial spam script. The design minimizes the scope: IPs in `abuse.log` are never cross-referenced against reports, conversations, or keywords (none of which are stored against IP), the log rotates at 90 days, and nothing else on the stack persists IP information. The deployed `/privacy` page states this tradeoff openly. Any future contribution that would log IPs in a new context must update both this document and the deployed policy in lockstep.

### 6.2 Zero External Requests

Fonts and NaCl libraries are downloaded once via `setup-assets.js` and served from the project directory. The browser makes **no external requests**. Verify this whenever adding anything new.

### 6.3 No Cookies, No Analytics, No Client-Side Storage

No `Set-Cookie`, no tracking pixels, no third-party scripts. No `localStorage`, no `sessionStorage`, no IndexedDB — no client-side persistence of any kind. The theme toggle (dark/light) is in-session only and resets to dark on every page load.

Do not add analytics or any form of client-side state persistence without updating the Privacy Policy and documenting it here.

---

## 7. WebSocket Protocol

All frames are JSON, max 4096 bytes.

### Client → Server

```jsonc
// First join — PoW required on new connection
{ "type": "join", "keywords": ["word"], "pubKey": "<base64>", "token": "<hex>", "nonce": 12345 }

// Re-join after Next → — same verified connection, no PoW
{ "type": "join", "keywords": ["word"], "pubKey": "<base64>" }

// Send encrypted message
{ "type": "message", "ciphertext": "<base64>", "nonce": "<base64>" }

// Typing indicator (throttled to 1 per 2 seconds client-side)
{ "type": "typing" }

// Leave room or cancel search
{ "type": "leave" }
```

### Server → Client

```jsonc
{ "type": "waiting",      "keywords": ["word"] }
{ "type": "matched",      "roomId": "<hex>", "keyword": "word", "partnerPubKey": "<base64>" }
{ "type": "message",      "ciphertext": "<base64>", "nonce": "<base64>" }
{ "type": "typing" }
{ "type": "partner_left" }
{ "type": "error",        "code": "challenge_expired" }
{ "type": "error",        "code": "server_busy" }
```

**Typing indicator:** The server blindly relays `{ type: "typing" }` to the partner. No content, no logging. Client-side throttle ensures at most one event per 2 seconds. The receiving client shows "typing..." which auto-hides after 3 seconds of no events, or immediately when a message arrives or the partner leaves.

---

## 8. REST API

| Method | Path | Purpose | Rate limit |
|---|---|---|---|
| `GET` | `/challenge` | Issue PoW token | 60/hour/IP |
| `GET` | `/count` | Live user count | API budget |
| `POST` | `/report` | Submit abuse report | 10/hour/IP |
| `GET` | `/privacy` | Privacy policy page | API budget |
| `GET` | `/terms` | Terms of service page | API budget |
| `GET` | `/*` | Static files (incl. `.json`) | Static budget |

`/count` returns the real number of connected WebSocket clients, no inflation or social-proof adjustment. The client polls this endpoint only while the user is on the entry screen (not while waiting or chatting).

---

## 9. Design System

### 9.1 Typography

| Element | Font | Weight | Size | Extras |
|---|---|---|---|---|
| Logo, headings, system messages | Unbounded | 500–600 | varies | `letter-spacing: -0.03em`, `line-height: 1.15` |
| Body, messages, inputs, buttons, tag pills | Inter | 400–600 | varies | — |

All spacing follows a **4-point grid** (4, 8, 12, 16, 20, 24, 32px).

### 9.2 Colors (dark mode)

| Token | Value | Usage |
|---|---|---|
| `--paper` | `#1c1713` | Body background |
| `--ink` | `#e8ddd0` | Primary text |
| `--accent` | `#c87941` | CTAs, highlights, sent messages |
| `--accent-light` | `#3a2415` | Accent tint (tag pills) |
| `--muted` | `#7a6e65` | Secondary text, placeholders |
| `--border` | `#2e2620` | Subtle borders |
| `--msg-them-fg` | `#d4c0a0` | Received message text |

### 9.3 Chat Layout

Messages are displayed in a **shared left-aligned column** (max-width 640px, centered). Both speakers are left-aligned. Color distinguishes voices:
- **Received messages:** `#d4c0a0` (warm cream, ~6.8:1 contrast)
- **Sent messages:** `#c87941` (amber, ~4.3:1 contrast — lower contrast is acceptable because users already know what they typed)

Speaker changes get **16px** vertical gap. Consecutive same-speaker messages get **4px** gap. This is handled by CSS sibling selectors (`.msg.me + .msg.me`, `.msg.them + .msg.them`).

No bubbles, no borders, no backgrounds on messages. Pure text.

System messages use Unbounded font, centered, in `--muted` color.

### 9.4 Header and Footer

Both constrained to `max-width: 640px` with `margin: 0 auto`, matching the chat column width. This creates a single vertical axis from logo through messages through input.

### 9.5 Chat Input

Transparent background, underline border (`1px solid var(--border)`), same font size as messages. Turns amber on focus. "send" is a plain text button in amber — no pill, no background. Leave/report/next are lowercase text buttons below.

### 9.6 Message Height Cap

Messages have `max-height: 200px` with hidden scrollbar overflow. The textarea input also caps at 200px. When the height limit is reached, the textarea's underline turns amber and Shift+Enter is blocked (no new lines allowed).

### 9.7 Typing Indicator

"typing..." text appears inside the chat flow (appended to chat-box DOM) right below the last message. Muted italic, gently fading in and out via CSS animation. Auto-removed after 3 seconds or when a message arrives.

---

## 10. PWA

Emberline is installable as a Progressive Web App via `manifest.json` and `sw.js`.

- **manifest.json:** Defines app name, theme color (`#1c1713`), icons (192px + 512px ember flame).
- **sw.js:** A **template**, not valid JS on its own. `CACHE_NAME` and `SHELL` are placeholders (`__CACHE_VERSION__`, `__SHELL_LIST__`) that `server.js` fills in at request time. The cache name is an 8-char SHA-256 prefix over the contents of every shell file — so the cache invalidates exactly when cached files actually change, with no manual version bumps. The shell list is enumerated from disk at server startup (includes all `/fonts/*.woff2` files found, filters out anything missing so dev environments install cleanly). Never caches `/challenge`, `/count`, `/report`, `/sw.js` itself, or WebSocket connections. HTML uses network-first; static assets use cache-first.
- **index.html:** Includes `<link rel="manifest">`, Apple meta tags (`apple-mobile-web-app-capable`, etc.), and service worker registration script.
- **Icons:** Three-layer ember flame (amber outer, orange middle, gold core). Generated via `generate-icons.html`.

The `/sw.js` handler in `server.js` must be registered **before** `express.static`, otherwise the raw template (with unreplaced placeholders) gets served and the service worker fails to install. Startup logs `SW → cache=<8hex> files=N` for deploy verification — the hash should change after any deploy that touches a cached file.

PWA install works in Chrome/Edge (desktop), Chrome (Android), Safari (iOS). Firefox desktop does not support PWA installation but the service worker still caches assets.

---

## 11. Adding Features — Decision Framework

Before writing any code, answer these in order:

1. **Is there a simpler way?** A one-line fix beats a new abstraction every time.
2. **Does it store new data?** Update the Privacy Policy and this document.
3. **Does it break E2EE?** The server must stay a blind relay. No plaintext ever.
4. **Does it log IPs in a new context?** IPs live in two places today: transient RAM maps (rate limiting) and `abuse.log` (Fail2Ban feed, 90-day rotation). Any new IP-logging path — particularly one that associates IPs with user actions, content, or reports — must be rejected or justified in writing, with the deployed `/privacy` page updated in lockstep.
5. **Does it weaken a bot-defence layer?** Either compensate or justify removal.
6. **Does it hurt UX?** A security measure that makes the app unusable is not a good security measure.

---

*Last updated: 17 April 2026 · Jurisdiction: Switzerland · Contact: contactall@emberline.ch*
