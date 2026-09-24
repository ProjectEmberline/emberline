# Privacy Policy

> This document mirrors the Privacy Policy served at [emberline.ch/privacy](https://emberline.ch/privacy). If the two ever diverge, the served version is canonical. The repository copy exists for audit, offline reference, and version history.

**Effective date:** 24 September 2026 · **Jurisdiction:** Switzerland

Emberline is an anonymous, ephemeral chat platform. This policy describes what data we collect, what we do not collect, and your rights under Swiss law (nFADP).

## What we do not collect

We do not collect names, email addresses, phone numbers, or any other identifying information. We do not require registration. We do not store chat messages — messages are relayed in real time using end-to-end encryption and are never written to disk. We have no ability to retrieve or reconstruct past conversations.

## What we do collect

When a user submits an abuse report, we record the report timestamp, the reason category, and — only if the reporter chooses to write them — up to 500 characters of free-text details. No chat messages are attached, and no IP address or user identity is recorded with the report. Please do not include personal information in the details. Reports are retained for a maximum of 90 days.

## IP addresses

We do not log IP addresses in association with chat content, reports, keywords, or any durable user record. An IP-based abuse defense runs at the connection layer: when a client trips a rate limit, fails a proof-of-work check, or hits a honeypot, an entry is written to an abuse log containing only a timestamp, the triggered rule, and the source IP. This log feeds a ban system that temporarily blocks repeat offenders and is rotated after 90 days. It is never cross-referenced against reports, conversations, or keywords — and cannot be, because none of those are stored. This is the minimum defense a fully anonymous service requires to remain functional.

## End-to-end encryption

All messages are encrypted on your device using the NaCl box construction (Curve25519 + XSalsa20 + Poly1305). Only the two participants can decrypt messages. The server relays encrypted data it cannot read. In an optional AI chat, the AI is the other participant (see below).

## Optional AI chat

If no one matches your keywords right away, the waiting screen may offer to let you chat with an AI instead. This only happens if you click that button, and an AI chat is labeled as such for its entire duration. The AI is a language model running on hardware operated by Emberline. It is the other participant in the conversation, so to reply it decrypts your messages and receives the keywords you entered. AI conversations are held in memory only while the chat lasts; they are not stored, logged, or used to train models. The AI can be wrong or say strange things — do not rely on it for advice, and do not share personal information with it.

## Keywords

Keywords are held temporarily in server memory during matching and discarded immediately after a match is made or the session ends. If you choose an AI chat, your keywords are passed to the AI as conversation topics and discarded when the chat ends.

## Cookies, tracking, and storage

We use no cookies, no analytics, no tracking pixels, and no third-party services. We do not use localStorage, sessionStorage, or any other form of persistent client-side storage. All fonts and cryptography libraries are self-hosted — no external requests are made by your browser.

## Illegal content

Use of Emberline to share, solicit, or facilitate illegal content — including CSAM, harassment, or content illegal under Swiss law — is strictly prohibited. We cooperate with Swiss law enforcement under the Swiss Criminal Code.

## Your rights under nFADP

You have the right to request access to any personal data we hold about you and to request its deletion. Because we store no user identities, no messages, and no session history, there is typically nothing to disclose or delete. The one category of data that could constitute personal data under nFADP is the IP entries in the abuse log described above; these can be removed on request if you provide the IP and an approximate time window. Contact: [contactall@emberline.ch](mailto:contactall@emberline.ch).

## Changes

We may update this policy as the platform evolves. The effective date above reflects the most recent revision.
