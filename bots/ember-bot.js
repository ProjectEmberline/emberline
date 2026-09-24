#!/usr/bin/env node
/**
 * Emberline — AI chat bot
 * ───────────────────────
 * Connects to an Emberline server as an authenticated bot and chats with
 * people who explicitly chose "Chat with an AI". Replies come from a local
 * llama.cpp server (OpenAI-compatible API).
 *
 * Transparency is enforced by the server, not by this script: bots can only be
 * matched with humans who opted in, and every such chat is labeled as AI.
 *
 * Privacy: this process sees decrypted messages (it is the chat partner). It
 * keeps a conversation in memory only while it lasts and never logs content —
 * console output is limited to start/end events and counts.
 *
 * Run:  node bots/ember-bot.js
 * Config (environment variables):
 *   EMBERLINE_URL  WebSocket URL of the server   (default wss://emberline.ch)
 *   BOT_TOKEN      shared secret; or put it in bots/.bot-token (git-ignored)
 *   LLM_URL        llama.cpp server               (default http://127.0.0.1:9093)
 *   RULES_FILE     conversation rules             (default bots/rules.txt)
 *   CONCURRENCY    parallel conversations         (default 1 — match llama -np)
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const WS   = require('ws');
const nacl = require('tweetnacl');

const EMBERLINE_URL = process.env.EMBERLINE_URL || 'wss://emberline.ch';
const LLM_URL       = (process.env.LLM_URL || 'http://127.0.0.1:9093').replace(/\/$/, '');
const RULES_FILE    = process.env.RULES_FILE || path.join(__dirname, 'rules.txt');
const CONCURRENCY   = Math.max(1, parseInt(process.env.CONCURRENCY || '1', 10) || 1);

const MAX_REPLY_CHARS   = 280;   // server limit is 300; leave room
const MAX_USER_TURNS    = 40;    // then the bot ends the chat politely
const HISTORY_MESSAGES  = 20;    // context sent to the model
const LLM_TIMEOUT_MS    = 60_000;
const TYPING_EVERY_MS   = 2_000;

// ── Safety rules that always apply, whatever rules.txt says ─────────────────
const CORE_RULES = `Non-negotiable rules — these override everything else:
- You are an AI language model run by Emberline. Never claim or pretend to be human. If asked, say plainly that you are an AI.
- Everyone on Emberline must be 18 or older. Never produce sexual content, sexual or romantic roleplay, or flirting.
- Never ask for or encourage sharing personal information: real names, addresses, phone numbers, social media accounts, photos, or meeting in person.
- Do not help with anything illegal or dangerous.
- If someone seems to be in crisis or mentions self-harm or suicide, respond with care and point them to help: in Switzerland call 143 (Die Dargebotene Hand) or 144 in an emergency; elsewhere, local emergency services.
- Reply in plain text only: at most two or three short sentences, under ${MAX_REPLY_CHARS} characters.`;

const ADULTS_ONLY_GOODBYE =
  "Emberline is for adults (18+) only, so I'm ending this chat here. Take care!";
const TURN_LIMIT_GOODBYE =
  "We've been chatting for a while, so I'll end this conversation here. Thanks for the chat! Press next to meet someone new.";
const TECHNICAL_GOODBYE =
  "Sorry, I'm having a technical problem and have to end this chat. Press next to find a person.";

// ── Guards (exported for tests) ─────────────────────────────────────────────

// Statements of being under 18, in the languages Emberline users write in.
// Deliberately broad: a false positive only ends an AI chat early.
const NOT_AGE = String.raw`(?!\s*(%|percent|min|mins|minutes|hours?|hrs?|km|kg|cm|ft|feet|foot|\$|dollars?|euros?|chf|francs?|times|days?|weeks?|months?))`;
const U18 = String.raw`(1[0-7]|[5-9])`;
const MINOR_PATTERNS = [
  new RegExp(String.raw`\b(i['’]?m|i am|im)\s+(only\s+|just\s+)?${U18}\b${NOT_AGE}`, 'i'),
  new RegExp(String.raw`\b${U18}\s*(years?|yrs?)\s*old\b`, 'i'),
  new RegExp(String.raw`\b${U18}\s*(y/?o|yo)\b`, 'i'),
  new RegExp(String.raw`\b(1[0-7])\s*[/,]?\s*[mf]\b`, 'i'),                        // "15 f", "16/m"
  /\b(i['’]?m|i am|im)\s+(a\s+)?(minor|underage|under\s*18)\b/i,
  /\b(i['’]?m|i am|im)\s+in\s+(middle|high|elementary|primary|secondary)\s+school\b/i,
  /\b(i['’]?m|i am|im)\s+in\s+(\d{1,2})(st|nd|rd|th)\s+grade\b/i,
  new RegExp(String.raw`\bich\s+bin\s+(erst\s+|nur\s+)?${U18}\b${NOT_AGE}`, 'i'),   // de
  new RegExp(String.raw`\b${U18}\s*(jahre|jährig|ans|anni|años)\b`, 'i'),          // de/fr/it/es
  new RegExp(String.raw`\bj['’]?ai\s+${U18}\s*ans\b`, 'i'),                         // fr
  new RegExp(String.raw`\bho\s+${U18}\s*anni\b`, 'i'),                              // it
];

function mentionsBeingMinor(text) {
  return MINOR_PATTERNS.some(re => re.test(text));
}

// Keep replies short, plain and within the server's message limit.
function sanitizeReply(text) {
  let s = String(text || '')
    .replace(/<think>[\s\S]*?<\/think>/gi, '')   // stray reasoning blocks
    .replace(/[*_`#>]+/g, '')                    // markdown
    .replace(/\s+/g, ' ')
    .trim();
  if (s.length > MAX_REPLY_CHARS) {
    const cut = s.slice(0, MAX_REPLY_CHARS);
    const end = Math.max(cut.lastIndexOf('. '), cut.lastIndexOf('! '), cut.lastIndexOf('? '));
    s = end > 80 ? cut.slice(0, end + 1) : cut.replace(/\s+\S*$/, '') + '…';
  }
  return s;
}

function loadRules(topics) {
  let rules = '';
  try {
    rules = fs.readFileSync(RULES_FILE, 'utf8')
      .split(/\r?\n/).filter(l => !l.trimStart().startsWith('#')).join('\n').trim();
  } catch (err) {
    console.error(`[bot] could not read rules file ${RULES_FILE}: ${err.message}`);
  }
  const kw = topics.length ? topics.join(', ') : 'none';
  return `${rules.replace(/\{keywords\}/g, kw)}\n\n${CORE_RULES}`;
}

// ── LLM ─────────────────────────────────────────────────────────────────────

async function llmHealthy() {
  try { return (await fetch(LLM_URL + '/health', { signal: AbortSignal.timeout(5000) })).ok; }
  catch { return false; }
}

async function complete(messages) {
  const res = await fetch(LLM_URL + '/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messages, max_tokens: 160, temperature: 0.8 }),
    signal: AbortSignal.timeout(LLM_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`LLM HTTP ${res.status}`);
  const data = await res.json();
  return sanitizeReply(data.choices?.[0]?.message?.content);
}

// ── One bot connection = one conversation at a time ─────────────────────────

const b64   = u8 => Buffer.from(u8).toString('base64');
const unb64 = s  => new Uint8Array(Buffer.from(s, 'base64'));
const sleep = ms => new Promise(r => setTimeout(r, ms));

function readToken() {
  if (process.env.BOT_TOKEN) return process.env.BOT_TOKEN.trim();
  try { return fs.readFileSync(path.join(__dirname, '.bot-token'), 'utf8').trim(); }
  catch { return ''; }
}

class BotSession {
  constructor(id, token) {
    this.id = id;
    this.token = token;
    this.backoff = 1000;
    this.convo = null;
    this.connect();
  }

  log(msg) { console.log(`[bot ${this.id}] ${msg}`); }

  connect() {
    this.ws = new WS(EMBERLINE_URL, { headers: { Authorization: `Bearer ${this.token}` } });
    this.ws.on('open', () => { this.backoff = 1000; this.log('connected'); this.offer(); });
    this.ws.on('message', raw => {
      let msg; try { msg = JSON.parse(raw); } catch { return; }
      this.onMessage(msg).catch(err => this.log(`error: ${err.message}`));
    });
    this.ws.on('close', () => {
      clearInterval(this.idleCheck);
      this.convo = null;
      this.log(`disconnected, retrying in ${this.backoff / 1000}s`);
      setTimeout(() => this.connect(), this.backoff);
      this.backoff = Math.min(this.backoff * 2, 60_000);
    });
    this.ws.on('error', err => this.log(`socket error: ${err.message}`));
  }

  send(obj) { if (this.ws.readyState === WS.OPEN) this.ws.send(JSON.stringify(obj)); }

  // Offer ourselves for a new conversation — only while the model is up, so
  // people are never offered an AI that can't answer.
  async offer() {
    clearInterval(this.idleCheck);
    while (this.ws.readyState === WS.OPEN && !(await llmHealthy())) {
      this.log(`LLM at ${LLM_URL} not reachable, waiting…`);
      await sleep(15_000);
    }
    if (this.ws.readyState !== WS.OPEN) return;
    this.keys = nacl.box.keyPair();
    this.send({ type: 'bot_ready', pubKey: b64(this.keys.publicKey) });

    // While idle, withdraw the offer if the model goes down ('leave' takes an
    // idle bot out of the pool), and offer again once it is back.
    this.idleCheck = setInterval(async () => {
      if (this.convo || this.ws.readyState !== WS.OPEN) return clearInterval(this.idleCheck);
      if (!(await llmHealthy()) && !this.convo) {
        this.log('LLM went down — withdrawing AI offer');
        this.send({ type: 'leave' });
        this.offer();
      }
    }, 30_000);
  }

  async onMessage(msg) {
    switch (msg.type) {
      case 'matched': {
        clearInterval(this.idleCheck);
        const topics = Array.isArray(msg.keywords) ? msg.keywords.filter(k => typeof k === 'string') : [];
        this.convo = {
          shared: nacl.box.before(unb64(msg.partnerPubKey), this.keys.secretKey),
          system: loadRules(topics),
          history: [],
          userTurns: 0,
          busy: false,
          unanswered: false,
        };
        this.log(`conversation started (${topics.length} keyword${topics.length === 1 ? '' : 's'})`);
        await this.reply(this.convo, true);
        break;
      }
      case 'message': {
        const c = this.convo;
        if (!c) return;
        const text = this.decrypt(c, msg);
        if (text === null) return;
        c.userTurns++;
        if (mentionsBeingMinor(text)) return this.end(c, ADULTS_ONLY_GOODBYE, 'adults-only');
        if (c.userTurns > MAX_USER_TURNS) return this.end(c, TURN_LIMIT_GOODBYE, 'turn limit');
        c.history.push({ role: 'user', content: text });
        c.unanswered = true;
        if (!c.busy) await this.reply(c);
        break;
      }
      case 'partner_left':
        if (this.convo) this.log(`conversation ended by partner (${this.convo.userTurns} messages)`);
        this.convo = null;
        await this.offer();
        break;
      case 'error':
        if (msg.code !== 'rate_limited') this.log(`server error: ${msg.code}`);
        break;
    }
  }

  decrypt(c, msg) {
    try {
      const out = nacl.box.open.after(unb64(msg.ciphertext), unb64(msg.nonce), c.shared);
      return out ? Buffer.from(out).toString('utf8') : null;
    } catch { return null; }
  }

  sendText(c, text) {
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const ct = nacl.box.after(Buffer.from(text, 'utf8'), nonce, c.shared);
    this.send({ type: 'message', ciphertext: b64(ct), nonce: b64(nonce) });
  }

  // Generate and send one reply; loops if more messages arrived meanwhile.
  async reply(c, opening = false) {
    c.busy = true;
    const typing = setInterval(() => this.send({ type: 'typing' }), TYPING_EVERY_MS);
    this.send({ type: 'typing' });
    try {
      do {
        c.unanswered = false;
        const messages = [{ role: 'system', content: c.system }];
        if (opening) {
          messages.push({ role: 'user', content: '(The person has just connected. Greet them in one short sentence, mention that you are an AI, and ask an opening question about their keywords.)' });
          opening = false;
        } else {
          messages.push(...c.history.slice(-HISTORY_MESSAGES));
        }
        const text = await complete(messages);
        if (this.convo !== c) return;               // chat ended while generating
        if (!text) continue;
        c.history.push({ role: 'assistant', content: text });
        this.sendText(c, text);
      } while (c.unanswered && this.convo === c);
    } catch (err) {
      this.log(`LLM failed: ${err.message}`);
      if (this.convo === c) this.end(c, TECHNICAL_GOODBYE, 'llm error');
    } finally {
      clearInterval(typing);
      c.busy = false;
    }
  }

  // Send a last message, then leave the room and offer ourselves again.
  async end(c, goodbye, reason) {
    if (this.convo !== c) return;
    this.sendText(c, goodbye);
    this.convo = null;
    this.log(`conversation ended by bot: ${reason} (${c.userTurns} messages)`);
    await sleep(500);
    this.send({ type: 'leave' });
    await this.offer();
  }
}

function main() {
  const token = readToken();
  if (!token) {
    console.error('No bot token. Set BOT_TOKEN or put it in bots/.bot-token');
    process.exit(1);
  }
  console.log(`Emberline AI bot → ${EMBERLINE_URL}, LLM ${LLM_URL}, rules ${RULES_FILE}, ${CONCURRENCY} session(s)`);
  for (let i = 1; i <= CONCURRENCY; i++) new BotSession(i, token);
}

if (require.main === module) main();

module.exports = { mentionsBeingMinor, sanitizeReply, loadRules, CORE_RULES };
