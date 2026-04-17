# Security Policy

This document describes how to report security vulnerabilities in Emberline, what the project commits to in response, and the explicit threat model that scopes what counts as a vulnerability.

If you have found what you believe to be a security issue, skip directly to **Reporting a vulnerability** below.

---

## Reporting a vulnerability

Send a description of the issue to `contactall@emberline.ch`.

Useful information to include, in rough priority order:

- A clear statement of the issue and its impact
- Reproduction steps, if the issue is reproducible
- The affected endpoint, code path, or file and line reference
- Whether you have publicly disclosed the issue elsewhere
- Your preferred name or handle for acknowledgment, or a request to remain anonymous

Plain email is sufficient. We do not currently publish a PGP key. If your report contains technical details you would prefer not to send in cleartext, let us know and we can arrange an alternative channel.

Please do not open public GitHub issues for security vulnerabilities. Public issues are appropriate for bugs, design feedback, or already-disclosed problems — not for unpatched security issues.

---

## What to expect after reporting

We will acknowledge receipt of a security report within 72 hours. If you do not receive an acknowledgment, resend — email delivery is generally reliable but not guaranteed.

After acknowledgment, we will:

1. Triage the report and confirm or reject the finding within 7 days.
2. If confirmed: share our understanding of the issue, propose a fix timeline, and keep you informed of progress.
3. On resolution: deploy the fix and, unless you request anonymity, publicly acknowledge your contribution.

We do not operate a bug bounty program. Emberline is run by an unfunded group and we cannot offer monetary rewards. We take reports seriously and will credit reporters publicly with permission.

---

## Disclosure timeline

We aim to fix and disclose verified issues within 90 days of the initial report. For serious issues with straightforward fixes, this will typically be much faster. For issues requiring architectural changes, it may take the full window or require coordination.

If you intend to publish your own analysis after our fix, please coordinate with us on timing. If we have been unresponsive for longer than 90 days after your initial report, you are under no obligation to continue waiting — publish as you see fit.

---

## Scope

**In scope:**

- The canonical production instance at `emberline.ch` and its endpoints
- Source code published in this repository on the default branch
- The server-side matching logic, proof-of-work verification, rate limiting, and end-to-end encryption handshake
- Client-side cryptographic operations and message handling
- The `/privacy`, `/terms`, `/challenge`, `/count`, and `/report` endpoints

**Out of scope:**

- Self-hosted forks or third-party deployments. Report those to their maintainers.
- Vulnerabilities in upstream dependencies (Node.js, Express, `ws`, TweetNaCl). Report upstream; we will update our dependency version once a fix is released.
- Brute-force of the proof-of-work challenge. Difficulty tuning is a documented tradeoff (see ARCHITECTURE.md §5.1).
- Denial-of-service through sheer traffic volume. Rate limiting and Fail2Ban are best-effort defenses; large-scale network-layer DDoS is a separate threat model we do not attempt to solve in application code.
- Social engineering of the maintainers or other users.
- Physical access to the hardware running the canonical instance.
- Anything listed as a known structural limitation in the [README](./README.md#honest-limitations).

---

## Threat model

Emberline is designed to defend against a specific set of threats. Stating them openly lets reporters calibrate whether their finding is a security issue or a design characteristic.

### What we defend against

- **Passive network observation** between a client and the TLS-terminating proxy (via TLS 1.3).
- **The operator reading message content.** The server forwards ciphertext and nonce only; it holds no private key material for any session and cannot decrypt.
- **Post-session message recovery.** No database, no message persistence, session keys discarded on disconnect or Next →.
- **Cross-session user identification.** No accounts, ephemeral per-session keypairs, no tracking cookies or client-side storage.
- **Casual automation and spam.** Proof-of-work challenges, IP-based rate limiting, honeypot keyword detection, Fail2Ban integration.
- **Third-party tracking.** No analytics, no third-party scripts, no externally-loaded fonts, no requests beyond the Emberline server.
- **IP leakage into user-facing logs.** Abuse reports contain no IP addresses, only a timestamp and a category.

### What we do not defend against

- **A compromised server silently serving modified client code.** Web-delivered JavaScript is a fresh trust decision on every load. The commit hash footer is a partial mitigation, not a solution.
- **Operator-mediated MITM of the key exchange.** Public keys are exchanged through the server. A compromised or malicious server can substitute keys. Out-of-band verification (SAS codes, phrase matching) would close this gap but is incompatible with the zero-friction design goal.
- **Traffic analysis by a global passive adversary.** Connection timing and packet sizes are inherent to the network path. An adversary with visibility at both endpoints can infer that two parties exchanged traffic, even without content.
- **Legal compulsion of the canonical operator.** Swiss jurisdiction is a procedural choice, not a cryptographic property. It does not prevent lawful process; it changes what process applies.
- **Abuse that does not manifest as network-layer signal.** If two users agree to harass or defraud each other, there is no technical mechanism available to prevent it.

The full framing of each structural limitation is in the [README](./README.md#honest-limitations). Reports that describe known limitations as vulnerabilities will be politely redirected.

---

## A note on self-hosted instances

The AGPL-3.0 license permits anyone to self-host Emberline, including with modifications. A self-hosted instance's security properties depend entirely on its operator. Vulnerabilities specific to a self-hosted instance — modified client code, altered server behavior, custom deployment infrastructure — are the responsibility of that operator, not of this project.

If you are a user of a third-party Emberline instance and have a security concern, contact that instance's operator directly.

---

## Public acknowledgments

Security researchers who have reported valid issues and consented to attribution are listed here.

- *(none yet)*

---

## Contact

`contactall@emberline.ch`
