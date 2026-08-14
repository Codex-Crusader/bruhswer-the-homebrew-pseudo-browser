# Security Policy

bruhswer is a security tool, so it should be held to the standard it asks of others.
This document says how to report a problem, what is in scope, and - just as
importantly - what bruhswer already knows it cannot do.

## Reporting a vulnerability

**Please report privately, not in a public issue.**

Use GitHub's private vulnerability reporting on this repository:

> **Security** tab → **Report a vulnerability**

That opens a private advisory visible only to the maintainers. It is the only
supported reporting channel - there is deliberately no email address here, so nothing
in this repository has to carry a personal contact detail forever.

If private reporting is not enabled or not available to you, open a public issue
containing **only** the words "security report, please enable private advisories" and
no technical detail. A maintainer will enable it and follow up.

### Testing bruhswer

If you are actively researching rather than reporting something you stumbled on, read
**[docs/SECURITY-TESTING.md](docs/SECURITY-TESTING.md)** first. It has the trust
boundary map, the list of places untrusted input enters, how to set up a test
environment, a safe-harbour statement, a report template, and - importantly - a table
of what is **already known** so you do not spend a weekend rediscovering a documented
platform limitation.

### What to include

- What you did, in enough detail to reproduce it
- What you expected, and what happened instead
- Why you believe it is a security problem rather than a bug
- The bruhswer version, your Windows version, and your Edge version
- Any proof-of-concept you are comfortable sharing

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 7 days |
| Initial assessment | 30 days |
| Fix or documented decision | best effort - see below |

bruhswer is maintained by volunteers. These are honest targets, not a contractual
SLA, and pretending otherwise would be exactly the kind of unearned assurance this
project refuses to give elsewhere.

### Disclosure

Please give a reasonable window before public disclosure - 90 days is the usual
convention, and is what this project asks for. If a fix is not possible in that time,
the limitation gets documented publicly rather than left quiet. Reporters are credited
in the advisory unless they ask not to be.

## Supported versions

| Version | Supported |
|---|---|
| 0.9.x (current pre-1.0) | Yes |
| earlier | No |

bruhswer is pre-1.0. Only the latest release receives fixes.

## Scope

### In scope

- A website reaching something bruhswer claims to block
- Escaping the download quarantine, or getting a downloaded file executed
- Command, argument or path injection through a URL, filename or download name
- Anything that causes bruhswer to launch the browser with a weakened configuration
- A local privilege escalation caused by bruhswer's own code, scripts or installer
- Host Guard applying a change without consent, or failing to roll one back
- Data written outside `%LOCALAPPDATA%\BRUHWSER` without the user asking
- **A false security claim.** If bruhswer reports something as verified, blocked or
  enforced when it is not, that is treated as a vulnerability in its own right, not as
  a documentation bug. It is the defect class this project cares about most.

### Out of scope

These are not bugs in bruhswer. They are properties of the platform it runs on, and
they are documented rather than hidden:

- **Anything reachable over localhost.** Windows Firewall does not filter loopback.
  Measured, repeatedly, across IPv4, IPv6, alternate loopback addresses, decimal and
  hex address forms, the host's own LAN address, and via page-driven `fetch`, `POST`
  and WebSocket. bruhswer reports this as `NOT ENFORCEABLE` everywhere a user can see
  it, and a regression test fails if it is ever described as anything else. See
  [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).
- Vulnerabilities in Microsoft Edge or Chromium - report those to Microsoft.
- Vulnerabilities in Windows itself - report those to Microsoft.
- Anything requiring Administrator access you already have.
- Anything requiring physical access to an unlocked machine.
- A fully compromised host. bruhswer runs as an ordinary user process; it cannot
  defend a machine that is already owned.
- Browser fingerprinting. bruhswer reduces collection surfaces. It does not claim
  anonymity and never will.
- Social engineering of the user, including persuading them to export a quarantined
  file and run it.

## What bruhswer does not protect against

Stated plainly, because a security policy that only lists strengths is marketing:

- It is **not** a virtual machine and provides no VM isolation.
- It does **not** sandbox the browser process itself. Chromium's sandbox contains
  renderers; the browser process runs on an ordinary user token.
- It does **not** provide a VPN, and reports `UNSUPPORTED` rather than implying one.
- It **cannot** confirm whether your DNS queries leave the machine encrypted, and
  reports `UNKNOWN` rather than guessing.
- It does **not** detect malware. Quarantine means a file was not let out. It does not
  mean the file is safe. bruhswer reads a downloaded file's first bytes and will tell
  you when the *content* is a program and the *filename* claims otherwise - that is a
  format observation, not a safety verdict, and "nothing recognised" is not "clean".
- It **cannot** prove the IPv6 firewall rule stops the browser. The rule is verified as
  present and correctly formed; its *effect* was never measured, unlike the IPv4 rule.
  Reported as `RULE SET, EFFECT NOT MEASURED`, never as `BLOCKED`.
- The file manifest is **drift detection, not tamper protection**. It catches damage,
  partial installs and untargeted modification. It does not resist an attacker, who
  could regenerate the manifest and edit the checker alongside the code.
- Overwriting a disposable profile before deleting it does **not** establish physical
  erasure. On an SSD, wear levelling means the rewrite usually lands on a different
  physical page and the original survives until the drive garbage-collects it; NTFS
  also journals metadata. bruhswer cannot observe any of that and does not claim it.
- The panic key is a **global Windows hotkey**, so another application can own it. When
  that happens bruhswer says `UNAVAILABLE` rather than substituting a weaker key.
- Address sanitising refuses invisible, direction-reversing and credential-hiding URLs.
  It does **not** detect homoglyphs - a domain spelled with a Cyrillic lookalike is
  ordinary visible text and passes. Refusing all non-ASCII hosts would break legitimate
  internationalised domains, and a partial lookalike table would be a false claim.
- Release artifacts are **unsigned**. See the release notes.

## Security design

Details of the model, what was measured, and what remains unverified:

- [docs/SECURITY-TESTING.md](docs/SECURITY-TESTING.md) - for researchers: boundaries, setup, what is already known
- [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/NETWORK-PRIVACY.md](docs/NETWORK-PRIVACY.md)
- [docs/PRIVACY.md](docs/PRIVACY.md)
- [docs/DATA-INVENTORY.md](docs/DATA-INVENTORY.md) - what is stored, and the encryption decision
- [docs/CODEX-REVIEW-0.9.0.md](docs/CODEX-REVIEW-0.9.0.md) - the last independent review, with verdicts
- [docs/ROADMAP.md](docs/ROADMAP.md) - what is planned, and what is deliberately refused

## No certifications

bruhswer holds no security certification, has had no third-party audit, and claims
neither. It has been reviewed by its authors and by automated analysis. That is all,
and it is stated here so nobody has to infer it.
