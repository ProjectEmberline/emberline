# Privacy Policy

> This document mirrors the Privacy Policy served at [emberline.ch/privacy](https://emberline.ch/privacy). If the two ever diverge, the served version is canonical. The repository copy exists for audit, offline reference, and version history.

**Effective date:** 27 September 2026 · **Jurisdiction:** Switzerland

Emberline is an ephemeral chat platform with temporary profiles. This policy describes what data we collect, what we do not collect, and your rights under Swiss law (nFADP).

## What we do not collect

We do not collect email addresses, phone numbers, real names, or any other identifying information. There is no registration and no account. We do not store chat messages — messages are relayed in real time using end-to-end encryption and are never written to disk. If the other person's connection drops for a moment, your messages wait for them in server memory, still encrypted, for up to 5 minutes; if they don't come back, the messages are discarded. We have no ability to retrieve or reconstruct past conversations.

## Your profile

To go online you create a temporary profile: a username, optionally a gender, and up to ten interests. Your profile is visible to anyone who is online at the same time: it can appear in their random list of people online, and in their searches for one of your interests. It is held only in the server's memory, never written to disk, and deleted when you log off, when you close or reload the page, after 30 minutes without activity, 5 minutes after your connection drops, or when the server restarts.

Other people can see, remember or copy what your profile shows while you are online; we cannot delete what they saw. Gender is optional. It, and your interests, can reveal sensitive information about you (for example that you are transgender, or your religion, health or orientation). Only add what you are comfortable showing to strangers, and nothing that identifies you.

The server refuses usernames containing certain reserved words (such as "admin" or "emberline") and may refuse words on a block list in usernames and interests. These checks run in memory when you create a profile; nothing is logged.

## Requests and chats

Nobody can write to you until you accept their request. A request carries a short message, which is end-to-end encrypted like chat messages: the server holds it, encrypted, for up to 10 minutes until it is accepted, declined or expires, and cannot read it. A declined request looks to the sender exactly like one that wasn't answered.

For the rest of your session the server also keeps, in memory: whether you accept requests, who you blocked, and who did not answer your requests (you can't ask them again that session). All of it is deleted with your profile.

When a chat ends, it is removed from your list; the other person keeps their copy on their screen until they close it.

## Reports

When you report someone, we record the report timestamp, the reason category, the reported person's username, and — only if you choose to write it — up to 500 characters of free-text details. If you choose to attach the request message that person sent you, it is recorded too, marked as unverified: because of the encryption, we cannot check that it is what they actually sent. No chat messages are attached, and no IP address or information about you is recorded with the report. Please do not include personal information in the details. Reports are retained for a maximum of 90 days.

## IP addresses

We do not log IP addresses in association with chat content, profiles, reports, or any durable user record. An IP-based abuse defense runs at the connection layer: when a client trips a rate limit, floods the server with messages, fails a proof-of-work check, hits a honeypot, or tries to connect from another website, an entry is written to an abuse log containing only a timestamp, the triggered rule, and the source IP. The same log records when an IP is banned. Separately, to enforce rate limits and the limit of five profiles per network at a time, the server keeps IP addresses in memory while you are connected and for up to two hours afterwards (24 hours for a banned IP); this is never written to disk. The abuse log feeds a ban system that temporarily blocks repeat offenders and is rotated after 90 days. It is never cross-referenced against reports, profiles, or conversations — and cannot be, because none of those are stored. This is the minimum defense a fully anonymous service requires to remain functional.

## Hosting

Emberline is reached through a virtual server we rent from a hosting provider in Switzerland. It terminates the HTTPS connection and forwards the traffic through an encrypted tunnel to the server that runs Emberline, also in Switzerland. Because it sits in the connection path, the provider's infrastructure necessarily handles your IP address and the traffic passing through — for chat messages and requests, only end-to-end encrypted data. Access logging is disabled on this server. The provider only supplies the infrastructure; we share no data with it for any other purpose. Both servers are located in Switzerland.

## End-to-end encryption

Requests and chat messages are encrypted on your device using the NaCl box construction (Curve25519 + XSalsa20 + Poly1305). Only the two participants can decrypt them. The server relays encrypted data it cannot read. In an AI chat, the AI is the other participant (see below).

## AI chat

You can choose to chat with an AI instead of a person. This only happens if you start it, and an AI chat is labeled as such for its entire duration. The AI is a language model running on hardware operated by Emberline. It is the other participant in the conversation, so to reply it decrypts your messages and receives your profile: your username, your gender if you chose to show one, and your interests as conversation topics. AI conversations are held in memory only while the chat lasts; they are not stored, logged, or used to train models. The AI can be wrong or say strange things — do not rely on it for advice, and do not share personal information with it.

## Cookies, tracking, and storage

We use no cookies, no analytics, no tracking pixels, and no third-party services in your browser. We do not use localStorage, sessionStorage, or any other form of persistent client-side storage: your profile, requests and chats exist only in the open page. If you open Emberline in a second tab of the same browser, that tab can take over your session; the two tabs hand it over directly in memory, and nothing is stored. All fonts and cryptography libraries are self-hosted — no external requests are made by your browser.

## Illegal content

Use of Emberline to share, solicit, or facilitate illegal content — including CSAM, harassment, or content illegal under Swiss law — is strictly prohibited. We cooperate with Swiss law enforcement under the Swiss Criminal Code.

## Your rights under nFADP

You have the right to request access to any personal data we hold about you and to request its deletion. Your profile, requests and session data are deleted automatically when you log off, and we store no messages and no session history, so there is typically nothing to disclose or delete. Reports contain the username of the person reported, which is no longer linked to anyone once their profile is gone. The one category of data that could constitute personal data about you under nFADP is the IP entries in the abuse log described above; these can be removed on request if you provide the IP and an approximate time window. Contact: [contactall@emberline.ch](mailto:contactall@emberline.ch).

## Changes

We may update this policy as the platform evolves. The effective date above reflects the most recent revision.
