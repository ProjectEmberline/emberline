# Emberline profiles — server and client spec (beta)

Status: implemented on the `profiles-beta` branch, 27 September 2026. This file
describes what `server.js`, `public/app.js` and `public/index.html` do; where the
code and this file disagree, fix one of them. Everything here is in-memory only, like today: nothing is written to disk
except the existing abuse and report logs.

---

## 0. Open, and settled design calls

Nothing open for the beta. Settled on 27 September 2026:

- **Profiles replace Just Chat completely.** Random keyword matching, the
  waiting screen and the "Just Chat" entry page are removed; the only way to
  chat is profile → request → accept.
- **The AI chat becomes a premium feature** for paying subscribers later
  (§11). **For the beta it is free for everyone**: any profile can start one AI
  chat at a time from Discover, clearly labeled as AI.

Also settled on 27 September 2026:

1. **Newest tab wins, without storage.** A new tab asks over a
   `BroadcastChannel` (in-memory messaging between tabs of the same browser,
   no storage) whether a session is open; the old tab hands over its resume
   token and key pair and shows "continued in another tab". Works in the same
   browser while the old tab is still open; another browser or device is a new
   profile.
2. **Grace only for unclean drops.** A clean close (page unload, tab closed,
   log off) deletes the profile immediately, so a reload never leaves a ghost
   profile or blocks the name. The 300 s grace applies only when the connection
   drops without a clean close (network loss, phone asleep).
3. **Reports on encrypted requests.** The reporter may attach the decrypted
   request message (opt-in checkbox); it's logged as "provided by reporter,
   unverified", because NaCl box is deniable and the server can't check it.
4. **Profiles per IP.** 5 concurrent, as the env var `MAX_PROFILES_PER_IP`, so
   it can be raised without a release if shared networks (CGNAT, universities)
   run into it.
5. **Interest spelling.** Letters of any language and digits, plus `-`;
   lowercased, NFC-normalised, 2–24 chars. Entry works as on the live site:
   Enter, Space or comma turns the typed word into a pill, so an interest has
   no spaces ("board-games"); Backspace on an empty field removes the last one;
   phone keyboards and pasted lists are split on separators.
7. **Gender.** woman, man, trans woman (MtF), trans man (FtM), non-binary,
   genderfluid, don't show. Optional; the profile notice and privacy policy
   say it's visible to everyone online and may be sensitive personal data.

---

## 1. Decided values

All limits are constants at the top of `server.js`; those marked *env* can be
overridden like `MAX_CONNS_PER_IP` today.

| Name | Value | Notes |
|---|---|---|
| `MAX_OUTGOING_REQUESTS` | 20 | open (unanswered) requests a profile has sent |
| `MAX_INCOMING_REQUESTS` | 30 | open requests a profile can receive; the 31st sender gets `busy` |
| `REQUEST_TTL_MS` | 600 000 | 10 min; decline is silent and looks identical to expiry |
| `REQUEST_RATE` | 5 / min | per profile, token bucket |
| `REQUEST_MSG_MIN` / `MAX` | 10 / 200 chars | plaintext length, checked in the client; server checks ciphertext size |
| `MAX_ACTIVE_CHATS` | 20 | per profile; ended or closed chats don't count |
| `SEARCH_RESULTS` | 20 | random sample of matches; refresh draws again |
| `IDLE_LOGOFF_MS` | 1 800 000 | 30 min without user activity; warning at 28 min |
| `RECONNECT_GRACE_MS` | 300 000 | 5 min, unclean disconnects only (see §0, 2) |
| `MAX_PROFILES_PER_IP` *env* | 5 | concurrent; no limit on how many are created over time |
| `COUNTS_TICK_MS` | 5 000 | push interval for interest counts |
| Count buckets | 1–4, 5–9, 10+, 25+, 50+ | nothing hidden, small interests included |
| Interests | 1–10 per profile | `[\p{L}\p{N}-]`, 2–24 chars; treated literally: "football" ≠ "soccer" ≠ "footballs" |
| Username | 3–20 chars `[A-Za-z0-9_.-]` | unique among online profiles, case-insensitive |
| Reserved names | file, see §6 | any name *containing* a reserved word |
| Word filter | file, see §6 | empty at launch |

Also decided: requests are end-to-end encrypted; links and phone numbers are
allowed in them; requests between people with no shared interest are allowed; a
profile can't be edited while online; someone who let your request expire can't
be asked again this session; after a chat ends a new request is allowed unless
either side blocked; the only alert is a count in the page title (no sound);
page reload logs off; no automatic action on reports.

---

## 2. Data model (server memory)

```js
profiles:   Map<profileId, Profile>
byName:     Map<lowercased name, profileId>
byInterest: Map<interest, Set<profileId>>      // also the source of the counts
perIp:      Map<ip, number>                    // concurrent profiles
requests:   Map<requestId, Request>
chats:      Map<chatId, Chat>

Profile = {
  id, name, gender, interests[],           // public
  pubKey,                                  // NaCl box public key, public
  ws, ip, resumeToken,                     // private; token rotates on each resume
  createdAt, lastActiveAt, accepting,      // accepting = "take new requests" switch
  outgoing: Set<requestId>, incoming: Set<requestId>,
  chats: Set<chatId>,
  blocked: Set<profileId>,                 // either direction hides both ways
  noAnswer: Set<profileId>,                // they let my request expire: don't ask again
  graceTimer, idleTimer,
}
Request = { id, from, to, ciphertext, nonce, createdAt, timer }
Chat    = { id, a, b, open: Set<profileId> }   // a side leaves `open` when it ends or closes the chat
```

A chat is removed from memory once `open` is empty. Ending a chat only removes
*your* side; the partner keeps theirs, read-only, until they close it (§4).

---

## 3. Protocol

Removed: `join` / `join_ai` (keyword matching and the old AI entry), the
waiting pool, `waiting`/`matched` for human pairs, `leave`/`partner_left` for
humans and the `__random__` pool. Bots keep exactly the frames they had
(`bot_ready`, `matched`, `message`, `typing`, `leave`, `partner_left`), so the
`bots/` code is unchanged; a person starts an AI chat with `ai_start`.

Same transport as today: JSON frames over the existing WebSocket, 4 KB max
frame, proof of work on the first frame, and the existing flood, frame and message
buckets. All `ciphertext`/`nonce` fields use the existing `CIPHERTEXT_RE` and
`NONCE_RE`. `id`s are random 16-byte base64url strings. Unknown types are
ignored, as today.

### Client → server

| type | fields | effect / errors |
|---|---|---|
| `profile_create` | `name, gender, interests[], pubKey, token, nonce` | PoW on the socket's first profile. → `profile_ok {id, name, gender, interests, pubKey, accepting, resumeToken}`. Errors: `name_taken`, `name_reserved`, `name_invalid`, `interests_invalid`, `gender_invalid`, `invalid_key`, `too_many_profiles`, `server_busy`, `slow_down {retryMs}` (paced after validation, 5 then 1 per 3 s) |
| `resume` | `resumeToken` | within the grace period, or a tab handover. → `profile_ok` + `state` snapshot; the previous socket gets `replaced` and is closed |
| `counts_watch` | `interests[]` (≤ 40), `on` | subscribe to buckets for these interests plus the top 50; `on:false` pauses while the tab is hidden |
| `search` | `interest` | → `results {interest, bucket, people[≤20]}`; each person: `id, name, gender, interests, pubKey, accepting, askedBefore`. Random sample; excludes self and blocks both ways. Rate: 10, then 1 per 3 s (shared with `interests_all`). With `auto: true` (the page refreshing its open results by itself) it does not count as user action for the idle timer |
| `browse` | `exclude[]` (≤ 40 ids) | → `browse_results {people[≤20]}`: a random sample of everyone online (not you, not the excluded, no blocks either way), shown below the interest results. Shares the search rate limit |
| `interests_all` | – | → `interests_all {list: [[interest, bucket]] ≤ 200}` for "show all" |
| `request_send` | `to, ciphertext, nonce` | → `request_sent {requestId, to, expiresIn}`. Errors (each with `to`): `offline` (also when blocked, deliberately), `message_rejected` (over 200 chars), `already_chatting`, `already_pending`, `asked_before`, `not_accepting`, `outgoing_full`, `chats_full`, `busy` (recipient has 30), `rate_limited {retryMs}`, `server_busy` |
| `request_withdraw` | `requestId` | recipient gets `request_gone` |
| `request_answer` | `requestId, accept` | accept → `chat_open` to both. Decline → recipient's copy removed; **sender hears nothing** until expiry |
| `set_accepting` | `on` | toggles the switch; → `accepting {on}`; existing incoming requests stay |
| `chat_message` | `chatId, ref?, ciphertext, nonce` | → `chat_ack {chatId, ref, queued}`. If the partner is reconnecting, the message waits (encrypted, ≤ 50 per chat) and is delivered on their `resume`, else dropped with their profile. Errors carry `ref`: `chat_closed`, `partner_away` (queue full), `rate_limited`, `message_rejected` |
| `chat_typing` | `chatId` | relayed |
| `chat_end` | `chatId` | your side closes; partner gets `chat_ended {chatId, reason:'ended'}` and keeps a read-only copy |
| `block` | `profileId` | ends shared chats (partner sees `chat_ended {reason:'ended'}`, not "blocked"), drops requests both ways, hides both from each other's search |
| `report` | `profileId, name, reason, details?, requestText?` | → `report_ok`. Appended to `reports.log` as `{ts, reason, details, reported, requestTextUnverified?}`; no reporter data. `name` is used if the person already logged off |
| `ai_start` | – | one AI chat at a time → `chat_open {chatId, ai:true, partner:{name, pubKey}}`; the bot gets `matched {ai, keywords: interests, name, gender, partnerPubKey}` (`gender` is `''` when not shown). Errors: `ai_unavailable`, `ai_already_open`, `chats_full`, `slow_down` |
| `still_here` | – | answers `idle_warning` (any other user action also counts) |
| `logoff` | – | deletes everything now (§5); socket may stay open for a new profile |

### Server → client

`profile_ok`, `state`, `counts {buckets:{interest:bucket}, top[]}` (sent only when something changed; on your own interests the bucket counts the others, not you),
`results`, `interests_all`, `request_in {requestId, from:{id,name,gender,interests,pubKey,accepting}, ciphertext, nonce, expiresIn}`,
`request_sent`, `request_gone {requestId}`, `request_expired {requestId}` (sender,
at 10 min, identical for decline and no answer), `chat_open {chatId, partner}`,
`chat_message`, `chat_typing`, `chat_ended {chatId, reason:'ended'|'logged_off'}`,
`partner_reconnecting {chatId}` / `partner_back {chatId}`, `idle_warning {secondsLeft}`,
`logged_off {reason:'logoff'|'idle'|'timeout'}`, `replaced`, `accepting`, `report_ok`, `error {code, re, to?|chatId?}` (`re` is the type of the frame the error answers).
Times are relative (`expiresIn`, `secondsLeft`), so the browser's clock doesn't matter.

### Encryption

Each profile has one NaCl box key pair, created in the browser and kept only in
memory (and handed to a new tab per §0, 1). Requests and chat messages are
`nacl.box(plaintext, nonce, recipientPubKey, senderSecretKey)`, the same as today's
chat. The server sees only ciphertext length and routing. Public profile fields
(name, gender, interests) are plaintext by nature.

---

## 4. Lifecycles

**Request:** `request_send` → pending (10 min timer) → one of:
accepted → `chat_open`; declined → recipient side gone, sender still "waiting" →
`request_expired` at 10 min; withdrawn → `request_gone`; either side logs off or
blocks → gone. On expiry (or decline + expiry) the recipient is added to the
sender's `noAnswer` set: no new request to them this session.

**Chat:** `chat_open` → active → one side `chat_end`, blocks, or logs off → the
other side gets `chat_ended` and a read-only copy it can close. A new request
between the two is allowed afterwards unless a block exists.

**Connection:**
- `logoff` (the page sends it on `pagehide`, so closing or reloading counts) → delete immediately
- any socket close without a `logoff` (§0, 2) → `partner_reconnecting` to chat partners, profile stays listed
  and holds its name for 300 s → `resume` restores it, or it's deleted
- 28 min without user action → `idle_warning`; 30 min → `logged_off {reason:'idle'}` and deleted
- "user action" = any frame except typing and heartbeats: search, request,
  message, answer, `still_here`. The client sends `still_here` when the tab
  becomes visible again.

---

## 5. What "log off" deletes

Immediately, from memory: the profile and its name, interest memberships (counts
update on the next tick), all its outgoing and incoming requests (other side gets
`request_gone`), its side of every chat (partners get `chat_ended {reason:'logged_off'}`
and keep their read-only copy), its blocks and `noAnswer` sets, the per-IP slot.
The IP stays in the rate-limit maps for up to 2 h, exactly as the privacy policy
already says.

---

## 6. Filters, easy to extend

Two plain-text files in `LOG_DIR` (next to the logs), one entry per line, `#`
for comments, loaded at start and re-read within 10 s when they change
(`fs.watchFile`, which works with bind mounts). On the Pi, put them in
`~/docker/appdata/emberline/data/` and bind-mount them like the logs:

- `reserved-names.txt`: default `admin, emberline, moderator, support, system, official`.
  A name is refused if its lowercase form *contains* an entry.
- `blocked-words.txt`: empty at launch. When filled, applied to usernames and
  interests (lowercase, contains). Not applied to messages, which the server can't read.

Error codes stay generic (`name_reserved`, `interests_invalid`) so the lists
can't be probed word by word.

---

## 7. Client (public/app.js + index.html)

- Removed: the Just Chat entry page, keyword matching, waiting screen with sparks, "next", and the AI offer.
- New views, as in the `beta.html` prototype: profile entry, Discover / Requests / Messages tabs, chat, deleted.
- Discover shows a labeled AI card while a bot is free (`/count` → `ai`).
  - Requests tab: the "accepting new requests" switch, requests for you, and the requests you sent (with withdraw).
  - Messages tab: chats only. A newly accepted chat is marked "new" and counts in the tab badge.
- No pop-ups or toasts: feedback goes into a status line in the page flow below the tabs (and one in the chat view), so nothing covers the tabs.
- Page title: `(N) Emberline` with N = open incoming requests. No sound, no notifications API.
- Request dialog states "at least 10 characters" before typing and shows a live counter ("7 more characters needed" → "ready to send").
- Interest input: the live `addTag` / `splitTypedTags` logic, with the profile character rules (§0, 5).
- `beforeunload` while online → the browser's "Leave site?" dialog (its wording can't be set; many phone browsers skip it).
- `pagehide` → send `logoff` (a clean close deletes immediately).
- The entry page explains in a "good to know · everything here is temporary" list what gets deleted and when.
- `visibilitychange` → `counts_watch {on:false}` when hidden; `still_here` when visible.
- `BroadcastChannel('emberline')` tab handover per §0, 1.
- Request message box: required, 10–200 chars, counter.
- Still no cookies, localStorage, sessionStorage or IndexedDB.

---

## 8. Load on the Pi

At 2 000 profiles online: profiles ~2 MB, requests (≤ 20 out each, ~1 KB)
worst case ~40 MB, chats a few MB. Counts: one diff per tick, sent only to
visible tabs, ≤ 400 small frames/s. Search: a set intersection plus a random
sample of 20, cheap. Comfortably inside the Pi 4's RAM and CPU; the tunnel and
VPS bandwidth remain the limit, as today.

---

## 9. Privacy policy and terms

Must change before launch:
- Remove the Just Chat wording (random matching, keywords discarded after a
  match) and the "Optional AI chat" section; the AI returns with premium (§11).
- Profiles: what's visible (name, gender, interests), to whom (anyone online),
  for how long (until log off, idle 30 min, or 5 min after a lost connection);
  gender as optional, possibly sensitive data.
- Requests: end-to-end encrypted, stored in memory up to 10 min.
- "Nothing stored" now reads "nothing stored on disk; your profile is held in
  memory while you're online".
- Blocks, reports, and that a reporter may attach a request message (§0, 3).
- Terms: rules for usernames and interests, and an 18+ rule that applies to profiles too.
- Re-check the VÜPF revision status (derived communication services) before launch.

---

## 10. Tests (test/server.test.js)

Name uniqueness (case), reserved names, per-IP cap, request limits (20 out,
30 in, 5/min), decline indistinguishable from expiry for the sender (same frames,
same timing), `asked_before`, block hides both ways and is reported as
`unavailable`, chat end leaves the partner's copy, 20-chat cap, idle warning and
log off, clean close deletes immediately, grace + resume, `replaced` on handover,
and a memory check that every map empties after all profiles log off.

---

## 11. Later: premium AI chat (not in the beta)

Decided: chatting with a bot is for paying subscribers only. How is open.
Questions to settle before building it:

1. **Fit with the association.** `verein/Statuten.md` Art. 2.3: the Verein is
   non-profit and has no commercial purpose. A subscription that only covers
   running costs (hardware, power, hosting) is likely compatible; profit is
   not, and could affect a tax exemption. Options: a paid subscription run by
   the Verein at cost, or premium as a supporter/membership contribution
   (Art. 6 lets the general assembly set a membership fee). Check with a
   fiduciary before taking money.
2. **Paying without an account.** Emberline promises no accounts and no
   stored identities. Workable patterns, from most to least private:
   - *Anonymous access code* (as Mullvad does): payment gives a random code;
     the user types it in to unlock the AI for the paid period. The server
     stores only code → expiry date, never who paid. The payment provider
     knows the payer, but not which code they got if codes are issued after
     payment without linking them.
   - *Blind-signed tokens* (Privacy Pass style): the server signs tokens it
     can't later link to the payment. Strongest privacy, most work.
   - *Account with email*: simplest, but breaks the "no accounts" promise.
3. **Storage.** Any of these needs a small persistent store (code → expiry),
   the first thing Emberline keeps on disk besides logs; the privacy policy
   has to say so.
4. **Payment provider.** TWINT, card via Stripe or a Swiss provider (e.g.
   Datatrans, Payrexx), or crypto. Each has fees and its own data processing
   to disclose. Recurring billing is harder with anonymous codes; prepaid
   periods (1, 3, 12 months) fit better.
5. **Consumer and tax rules.** Terms for a paid service, what happens on
   downtime, refunds, and VAT (registration is only needed above CHF 100 000
   yearly turnover).
6. **Capacity.** The bot runs on Emberline's own hardware; decide how many
   concurrent AI chats it can serve and what premium users see when it's full.

Protocol when it's built: `premium_unlock {code}` → `premium {until}` for the
session only (the code is not stored in the browser, per the no-storage rule),
then the existing `join_ai` flow, presented as a clearly labelled AI entry in
Discover.
