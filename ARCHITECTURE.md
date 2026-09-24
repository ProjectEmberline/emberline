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
  reports.log   reason + optional reporter-written details + server timestamp (no IPs)
  abuse.log     event type + timestamp + IP  (audit trail of abuse events and bans)
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
├── server.js           — Node.js WebSocket + HTTP server
├── package.json        — Dependencies: express ^4, ws ^8
├── setup-assets.js     — One-time asset downloader (fonts + NaCl)
├── reports.log         — Abuse reports (auto-created in LOG_DIR)
├── abuse.log           — Abuse events + bans (auto-created in LOG_DIR)
└── public/             — The ONLY directory served over HTTP
    ├── index.html      — Single-page frontend (CSS inline, JS via src)
    ├── app.js          — All client-side logic
    ├── manifest.json   — PWA manifest
    ├── sitemap.xml
    ├── icons/
    │   ├── icon-192.png — PWA icon (ember flame)
    │   └── icon-512.png — PWA icon large
    ├── fonts/
    │   ├── fonts.css
    │   └── *.woff2     — Unbounded + Inter (self-hosted)
    └── vendor/
        ├── nacl-fast.min.js
        └── nacl-util.min.js
```

`express.static` is rooted at `public/` with dotfiles denied. Server source, `node_modules/`, `.git/`, `BUILD_VERSION` and the log files are never reachable by URL. Logs default to the project root and can be moved with `LOG_DIR`; the server refuses to start if `LOG_DIR` points inside `public/`.

**Client IP.** `getIP()` does not trust the leftmost `X-Forwarded-For` entry — clients can set that header themselves. It walks back `TRUST_PROXY` hops (default `1`) from the socket address, matching the number of reverse proxies that append to the header. The canonical deployment has exactly one (Caddy on the VPS).

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
| Honeypot keyword | `__honeypot__` → ban IP for 24h | `HONEYPOT_KEYWORD` |
| Auto-ban | 20 abuse events in 10 min → ban IP for 24h (in memory) | `STRIKE_LIMIT`, `BAN_DURATION_MS` |
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
  style-src 'self' 'sha256-…'        ← one hash per inline <style> block
  font-src 'self'
  img-src 'self'
  connect-src 'self' <ws/wss form of ALLOWED_WS_ORIGINS>
  manifest-src 'self'
  base-uri 'none'
  form-action 'none'
  frame-ancestors 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Strict-Transport-Security: max-age=31536000
```

All JavaScript lives in `app.js` (external file), so `script-src 'self'` is fully effective.

There is no `'unsafe-inline'` for styles. Pages must not use `style=""` attributes — put rules in the page's `<style>` block instead. `server.js` hashes every `<style>` block at startup (`allowStyleBlocks()`) and lists the hashes in the CSP, so editing a block needs no manual hash update. Setting styles from JavaScript via `el.style.x = …` is unaffected.

### 5.4 E2EE

A keypair is **generated on first user interaction** with the keyword input (see §4 Pre-warming for why). Each **Next →** also generates a fresh keypair and discards the old shared secret. Public keys are exchanged in the `matched` event. Both peers derive `sharedSecret = nacl.box.before(partnerPub, mySecretKey)`.

Messages use `nacl.box.after(plaintext, nonce, sharedSecret)` with `nonce = nacl.randomBytes(24)`. Nonces are never reused.

The server is a **blind relay** — it forwards `{ ciphertext, nonce }` only. The plaintext relay path was removed intentionally and must not be restored.

### 5.5 XSS Prevention

No `innerHTML` is used with any user-controlled or server-supplied data. All dynamic DOM writes use `createElement` / `textContent`. No inline `onclick` attributes — all handlers are wired via `addEventListener` in `app.js`.

### 5.6 Room IDs

Room IDs are generated with `crypto.randomBytes(8).toString('hex')` — 64-bit cryptographically random. `Math.random()` is never used for security-relevant values.

### 5.7 Automatic bans

`abuse.log` is written at every rejection point:
```
2026-03-28T12:00:00Z [pow_fail] ip=1.2.3.4
```

Rejection labels: `pow_fail` `pow_ip_mismatch` `honeypot` `conn_cap` `ws_rate` `ws_origin` `http_flood`, plus `banned` when an IP gets banned.

Every rejection is also a **strike** against the client IP. 20 strikes within 10 minutes (or one honeypot hit) bans the IP for 24 hours: all HTTP requests get `403` and WebSocket upgrades are refused, without writing further log lines. Bans live in memory and are cleared on restart. `BAN_ALLOWLIST` (comma-separated IPs) exempts addresses such as the operator's own.

Bans are enforced in the app rather than a host firewall on purpose. Behind a reverse proxy or tunnel, the app host only ever sees the proxy's address, so a firewall there cannot match client IPs; the app sees the real IP via `X-Forwarded-For` (see `TRUST_PROXY`). A firewall-level ban (Fail2Ban) is only effective on the machine that receives the client's TCP connection — in the canonical deployment, the VPS. A Fail2Ban setup for that case:

**Filter** (`/etc/fail2ban/filter.d/emberline.conf`):
```ini
[Definition]
failregex = ^.+ \[banned\] ip=<HOST>$
ignoreregex =
```

**Jail** (`/etc/fail2ban/jail.d/emberline.conf`):
```ini
[emberline]
enabled  = true
filter   = emberline
logpath  = /path/to/abuse.log   # must be readable on the host that runs the jail
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

Fonts are downloaded once via `setup-assets.js`; the NaCl libraries are npm dependencies (integrity-pinned in `package-lock.json`) that `setup-assets.js` copies into `public/vendor/`. Both are served from `public/`. The browser makes **no external requests**. Verify this whenever adding anything new.

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

Emberline is installable as a Progressive Web App via `manifest.json`. There is deliberately **no service worker**: it would store the app's files in the browser's Cache Storage, which conflicts with the privacy policy's promise of no persistent client-side storage. Current Chromium browsers and iOS Safari install web apps without one.

- **manifest.json:** Defines app name, theme color (`#1c1713`), icons (192px + 512px ember flame).
- **index.html:** Includes `<link rel="manifest">` and Apple meta tags (`apple-mobile-web-app-capable`, etc.).
- **app.js:** Shows the footer "install" link where the browser supports it (`beforeinstallprompt` on Chromium, an instructions modal on iOS).
- **Icons:** Three-layer ember flame (amber outer, orange middle, gold core). Generated via `generate-icons.html`.

---

## 11. Adding Features — Decision Framework

Before writing any code, answer these in order:

1. **Is there a simpler way?** A one-line fix beats a new abstraction every time.
2. **Does it store new data?** Update the Privacy Policy and this document.
3. **Does it break E2EE?** The server must stay a blind relay. No plaintext ever.
4. **Does it log IPs in a new context?** IPs live in two places today: transient RAM maps (rate limiting, bans) and `abuse.log` (abuse audit trail, 90-day rotation). Any new IP-logging path — particularly one that associates IPs with user actions, content, or reports — must be rejected or justified in writing, with the deployed `/privacy` page updated in lockstep.
5. **Does it weaken a bot-defence layer?** Either compensate or justify removal.
6. **Does it hurt UX?** A security measure that makes the app unusable is not a good security measure.

---

*Last updated: 17 April 2026 · Jurisdiction: Switzerland · Contact: contactall@emberline.ch*
