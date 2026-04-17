# Privacy Policy

> This document mirrors the Privacy Policy served at [emberline.ch/privacy](https://emberline.ch/privacy). If the two ever diverge, the served version is canonical. The repository copy exists for audit, offline reference, and version history.

**Effective date:** 17 April 2026 · **Jurisdiction:** Switzerland

Emberline is an anonymous, ephemeral chat platform. This policy describes what data we collect, what we do not collect, and your rights under Swiss law (nFADP).

## What we do not collect

We do not collect names, email addresses, phone numbers, or any other identifying information. We do not require registration. We do not store chat messages — messages are relayed in real time using end-to-end encryption and are never written to disk. We have no ability to retrieve or reconstruct past conversations.

## What we do collect

When a user submits an abuse report, we record the report timestamp and reason category only. No message content, IP address, or user identity is included. This information is retained for a maximum of 90 days.

## IP addresses

We do not log IP addresses in association with chat content, reports, keywords, or any durable user record. An IP-based abuse defense runs at the connection layer: when a client trips a rate limit, fails a proof-of-work check, or hits a honeypot, an entry is written to an abuse log containing only a timestamp, the triggered rule, and the source IP. This log feeds a ban system that temporarily blocks repeat offenders and is rotated after 90 days. It is never cross-referenced against reports, conversations, or keywords — and cannot be, because none of those are stored. This is the minimum defense a fully anonymous service requires to remain functional.

## End-to-end encryption

All messages are encrypted on your device using the NaCl box construction (Curve25519 + XSalsa20 + Poly1305). Only the two participants can decrypt messages. The server relays encrypted data it cannot read.

## Keywords

Keywords are held temporarily in server memory during matching and discarded immediately after a match is made or the session ends.

## Cookies, tracking, and storage

We use no cookies, no analytics, no tracking pixels, and no third-party services. We do not use localStorage, sessionStorage, or any other form of persistent client-side storage. All fonts and cryptography libraries are self-hosted — no external requests are made by your browser.

## Illegal content

Use of Emberline to share, solicit, or facilitate illegal content — including CSAM, harassment, or content illegal under Swiss law — is strictly prohibited. We cooperate with Swiss law enforcement under the Swiss Criminal Code.

## Your rights under nFADP

You have the right to request access to any personal data we hold about you and to request its deletion. Because we store no user identities, no messages, and no session history, there is typically nothing to disclose or delete. The one category of data that could constitute personal data under nFADP is the IP entries in the abuse log described above; these can be removed on request if you provide the IP and an approximate time window. Contact: [contactall@emberline.ch](mailto:contactall@emberline.ch).

## Changes

We may update this policy as the platform evolves. The effective date above reflects the most recent revision.
