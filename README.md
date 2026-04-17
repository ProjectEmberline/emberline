# Emberline

> Anonymous, ephemeral, end-to-end encrypted chat. No accounts. No message storage. Swiss jurisdiction.

**Live:** [emberline.ch](https://emberline.ch) · **License:** AGPL-3.0 · **Source:** you are here

---

## What it is

Emberline connects two strangers on shared keywords. You type a word or a few, and get matched with someone who typed the same thing. You chat. The session ends. Nothing is stored.

All messages are end-to-end encrypted using NaCl box (Curve25519 + XSalsa20 + Poly1305). The server is a blind relay — it forwards ciphertext and nonce, and cannot read what passes through it. No database. No accounts. No persistent session state.

## Why it exists

Federal Constitution of the Swiss Confederation
Art. 13 Right to privacy
1 Every person has the right to privacy in their private and family life and in their home, and in relation to their mail and telecommunications.
2 Every person has the right to be protected against the misuse of their personal data.

We believe in your right to privacy.
---

## How it works

A Node.js process handles WebSocket connections and a small HTTP surface (`/challenge`, `/count`, `/report`, plus static files and the policy pages). Clients connect, solve a proof-of-work challenge, send keywords, and are matched with another client in the same keyword pool. Once matched, peers exchange public keys through the server — which cannot decrypt what follows — derive a shared secret client-side, and relay encrypted messages. The server keeps in-memory Maps for the waiting pool and active rooms, and writes nothing durable except abuse-prevention logs.

The stack is intentionally small: Node.js, Express, `ws`, TweetNaCl on the client. No framework, no database, no build step. The entire client is one HTML file, one JavaScript file, and a service worker.

The canonical production deployment runs on a Raspberry Pi at home, reached via a Swiss VPS that terminates TLS and forwards over a WireGuard tunnel. The VPS logs nothing and the Pi's real IP is never exposed. This topology is not required to run Emberline — a single Linux host is sufficient — but it is how the public instance is operated.

For the full architecture, see [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Self-hosting

### Requirements

- Node.js 18 or later
- An HTTPS-terminating reverse proxy (Caddy, nginx, or similar)
- A domain

### Quick start

```bash
git clone https://github.com/ProjectEmberline/emberline.git
cd emberline
npm install
node setup-assets.js   # downloads fonts + NaCl libraries for self-hosted serving
node server.js
```

The server listens on port 3000. Put HTTPS in front of it, update `ALLOWED_WS_ORIGINS` in `server.js` to your domain, and you are running.

Production considerations — TLS termination, WireGuard, Fail2Ban integration, log rotation, security headers — are documented in [ARCHITECTURE.md §11](./ARCHITECTURE.md). Deployment artifacts for the canonical instance (Dockerfile, compose configuration) are not published in this repository; a plain Node setup on any Linux host is sufficient to run the project.

---

## Verifying what you are running

Every page served by the canonical instance includes a commit hash footer linking back to this repository. If you are using the public site and want to verify that the JavaScript your browser received matches the published source, you can:

1. Note the commit hash displayed in the page footer.
2. Clone this repository and `git checkout` that commit.
3. Diff the files served to your browser against the repository.

This does not cryptographically prevent a compromised server from lying about its commit hash; it is a good-faith signal, not a guarantee. The point is that any diligent user can detect discrepancies, and the possibility of detection is the deterrent. See [SECURITY.md](./SECURITY.md) for the full trust model.

---

## Honest limitations

Emberline is built around a specific threat model — casual privacy from third parties, with honesty about what the design does not protect against. The following are known structural limitations, not bugs. We do not claim to solve them.

**Browser-delivered JavaScript is a fresh trust decision on every page load.** The server could in principle serve a modified client that exfiltrates plaintext. This is a structural weakness of all web-based end-to-end encryption, and the usual countermeasure (signed native binaries) does not translate to the browser. The commit hash footer is a partial mitigation, not a solution.

**Server-mediated key exchange means the operator could MITM users.** Public keys are exchanged through the server at match time. A compromised server could substitute its own keypair for both peers and relay decrypted messages between them. Out-of-band verification (short authentication strings, phrase matching) would close this gap but is incompatible with the zero-friction design goal. This is an open problem.

**Single-operator trust.** The canonical instance is operated by the maintainers. There is no cryptographic way to prove the server running is exactly the code in this repository. The commit hash footer and the fact that the source is fully open are the best we can offer. If this trust model does not work for your threat model, self-host.

**Metadata.** Even with nothing logged on the server, the network path inherently leaks connection timing and packet sizes. A global passive adversary watching both endpoints can infer that two IP addresses exchanged traffic, even without content.

**IP-based abuse defense.** An unauthenticated, anonymous chat service without any IP-based rate limiting does not survive its first day online. Emberline logs IP addresses to a Fail2Ban feed (90-day rotation) solely for rate limiting and temporary bans. This is the single deliberate deviation from a "no logs" posture. It is documented in [the privacy policy](https://emberline.ch/privacy) and is never cross-referenced against reports, conversations, or keywords — because none of those are stored.

---

## Repository contents

```
├── server.js              Node.js WebSocket + HTTP server
├── app.js                 Client-side logic, no framework
├── sw.js                  Service worker template (see ARCHITECTURE.md §10)
├── setup-assets.js        One-time font + crypto library downloader
├── index.html             Single-page frontend
├── manifest.json          PWA manifest
├── package.json
├── ARCHITECTURE.md        Full technical architecture and decision framework
├── SECURITY.md            Threat model and responsible disclosure
├── PRIVACY.md             Privacy policy (mirror of /privacy endpoint)
├── TERMS.md               Terms of service (mirror of /terms endpoint)
└── LICENSE                AGPL-3.0
```

Generated files (`fonts/*.woff2`, `vendor/*.min.js`) are fetched by `setup-assets.js` at install time and are not committed to the repository.

---

## Contributing

We do not accept feature, bugfix, or documentation pull requests. This is a deliberate choice to keep the project's design direction tight. Security reports are welcome and valued — see [SECURITY.md](./SECURITY.md). For questions, feedback, or design discussions, use [GitHub Discussions](https://github.com/ProjectEmberline/emberline/discussions).

Forking is explicitly permitted by the AGPL-3.0 license. If you want Emberline with different design decisions, self-host your own version. The license requires that public-facing modified deployments publish their source.

---

## License

Licensed under AGPL-3.0. See [LICENSE](./LICENSE) for the full text.

The AGPL applies to network use. If you run a modified version of Emberline as a public-facing service, you are required to publish the source of your modifications. This is intentional and specifically chosen for a network service. Self-hosting an unmodified deployment carries no additional obligations.

---

## Contact

`contactall@emberline.ch` — general inquiries, privacy requests under nFADP, legal notices. For security reports, see [SECURITY.md](./SECURITY.md).
