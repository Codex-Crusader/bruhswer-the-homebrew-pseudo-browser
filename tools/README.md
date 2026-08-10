# Research tooling - not part of the application

**Nothing in this directory ships, runs at launch, or is part of the trusted computing
base.** These are the one-off probes that produced the measurements in
[`../docs/research/`](../docs/research/). They are kept because the evidence is worth
keeping, not because they are maintained.

| Directory | What it measured | Outcome |
|---|---|---|
| `stage2/` | Hyper-V firewall apply and revert | Backend rejected |
| `stage25/` | AppContainer network isolation, firewall program scope (B16), Authenticode timestamps (B17) | QEMU rejected on supply chain; B16 became a current guarantee |
| `stage4/` | Firewall enforcement, DNS and DoH behaviour, token decoding, headless probes | The measurements the current design rests on |

Several are written against environments that no longer exist. Do not run them
expecting current results, and do not read them as documentation of how bruhswer works
today - that is [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

## Where the real tools are

The scripts that are part of the product live in
[`../bruhswer/tools/`](../bruhswer/tools/): the network policy and Host Guard PowerShell
scripts, and `real_world_walkthrough.py`, which is run before every release.

## The trusted computing base

For a reviewer deciding what is worth reading, the security-critical code is small and
none of it is here:

| | |
|---|---|
| `app/security/verifier.py` | The single decision point on whether the browser may launch |
| `app/security/browser_guard.py` | Profile confinement, ACLs, command-line inspection |
| `app/network/network_guard.py` | Firewall policy verification |
| `app/sysquery.py` | The only place an external program is ever run |
| `app/browser/edge.py`, `urls.py` | Launch argv construction and URL refusal |
| `app/sessions/session_manager.py` | Session destruction, including reparse-point handling |
| `app/downloads/quarantine.py` | Quarantine paths and export |
| `app/config.py`, `app/verdict.py` | Constants and verdict semantics |

That is **1,789 lines of the application's 4,620**. Everything else is UI, orchestration
or presentation.
