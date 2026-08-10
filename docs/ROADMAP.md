# Roadmap

What is planned, in rough priority order. Nothing here is promised, and nothing here is
a claim about the current release - if it is on this page, **it does not exist yet**.

Current release: **v0.9.0**, pre-1.0. What it actually does and does not do is in
[`RELEASE-CANDIDATE.md`](RELEASE-CANDIDATE.md) and the
[README](../README.md).

---

## Why 1.0 has not happened

1.0 would mean "the security model is settled and independently checked". Four things
stand in the way, and three of them are on this list:

| Blocker | Status |
|---|---|
| Release artifacts are unsigned | Planned, see below |
| No reproducible build, so nobody can verify the installer matches the source | Planned, see below |
| No independent security review by a person | Open |
| Localhost remains reachable | **Will not be fixed.** Platform limitation, documented, test-enforced |

---

## Planned

### 1. Signed installer

The single most user-visible gap. Today SmartScreen warns about an unrecognised
publisher and that warning is correct.

- Obtain a code-signing certificate. OV is the realistic option; EV buys immediate
  SmartScreen reputation but costs considerably more.
- Sign the installer and the uninstaller.
- Publish the certificate thumbprint alongside the release so it can be checked.
- **The unsigned-artifact language stays** until signing actually ships. A publisher
  string in an installer is a label anyone can type; it is not authentication, and the
  docs will keep saying so.

Explicitly rejected: self-signing and describing it as trusted publisher
authentication.

### 2. Clean install / uninstall verification

Partly done. `v0.9.0` was install-tested on a real machine, including a junction
planted in the install tree to prove the uninstaller does not follow reparse points.

What is missing is doing it on a machine that is not the development machine:

- A genuinely clean Windows image with no Python, no Edge, no prior install.
- Confirm the prerequisite refusals actually fire and read sensibly.
- Confirm the uninstaller leaves nothing behind, and leaves user data alone unless
  asked.
- Automate it, so it is not a manual ritual before every release.

### 3. Upgrade path

Not designed yet, and it needs designing before there is a second release with a
persistent profile people care about.

Questions to answer: what happens to an existing profile across versions; what happens
to quarantined files; what happens if the privacy-settings list changes; whether an
upgrade should re-verify the profile ACL; and whether a downgrade is supported at all
(likely: no, stated plainly).

### 4. Reproducible builds

So that anyone can rebuild the installer from the tagged source and get a
byte-identical artifact, and therefore verify the published binary corresponds to the
published code.

- Pin the Inno Setup version and record it in the release.
- Eliminate build-time nondeterminism (timestamps, file ordering, compression).
- Publish the exact build command and environment.
- Have CI rebuild and compare against the released hash.

This matters more than signing does for a security tool: signing says who built it,
reproducibility says what they built.

### 5. CI security regression tests

CI today runs the honest subset: unit tests, the AST scans, the no-listener proof,
repository hygiene, and an installer compile. It cannot run the firewall, Host Guard,
download or localhost suites, and it
[says so explicitly](../.github/workflows/ci.yml) rather than implying coverage it
does not have.

Wanted:

- A self-hosted or throwaway Windows runner with Edge, so the integration suites run
  automatically rather than by hand.
- Dependency and supply-chain checks on the GitHub Actions themselves (they are the
  only third-party code in the pipeline).
- Keep CodeQL, and treat any alert as a build failure rather than a dashboard entry.
- **Never** let CI report coverage it cannot actually perform. That rule is not
  negotiable and predates this list.

### 6. Edge version compatibility testing

bruhswer depends on measured Edge behaviour, and Edge updates roughly monthly. Several
current facts are build-dependent and could change without warning:

- renderer processes running at UNTRUSTED integrity in an AppContainer
- which preferences Chromium reverts as tracked preferences
- whether `--disable-sync` keeps working
- whether handing a URL to a running instance keeps opening a tab rather than a window

Wanted: a compatibility suite pinned against known Edge versions, and a documented
policy for what happens when a measurement stops holding. The current design already
fails closed and re-measures the sandbox live, which is the right default.

### 7. Crash and recovery testing

Partly covered - orphaned disposable profiles and quarantines are swept at startup, and
that path has a regression test. Not covered:

- power loss mid-download
- Edge killed while bruhswer is hosting its window
- bruhswer killed while Edge is running
- a profile left locked by a process that will not exit
- disk full during quarantine writes
- corrupted `Preferences`, corrupted Host Guard rollback record

The principle stays: **never report a successful cleanup that did not happen.**

### 8. Threat model, kept current

[`THREAT-MODEL.md`](THREAT-MODEL.md) exists and is detailed, but predates some of what
has been measured since. It needs a pass to fold in the localhost matrix, the Edge
sign-in limitation, and the installer as part of the security boundary. Ongoing, not a
one-off.

### 9. Release checklist

Exists, at the end of [`RELEASE-CANDIDATE.md`](RELEASE-CANDIDATE.md). Wanted: lift it
into a standalone document that is filled in per release and committed, so each release
has its own signed-off record instead of one file being overwritten.

### 10. Security disclosure process

Largely in place: [`SECURITY.md`](../SECURITY.md) has scope, timelines and channel,
private vulnerability reporting is enabled, and
[`SECURITY-TESTING.md`](SECURITY-TESTING.md) tells researchers where the boundaries are
and what is already known.

Remaining: publish advisories through GitHub's advisory database when a fix ships, and
keep a public record of findings that were accepted and declined, with reasons.

---

## Not planned

Saying no is part of the design, and these have all been considered and rejected:

| | Why not |
|---|---|
| A VM or hypervisor backend | Tried. WSL2 failed its gates, QEMU was rejected on supply chain. See [`PROJECT-HISTORY.md`](PROJECT-HISTORY.md). |
| A built-in VPN | Would be a new party seeing all traffic, plus a kill switch this project has not demonstrated. Reports `UNSUPPORTED` instead. |
| A custom Chromium build | Enormous ongoing security liability and a new trust root. Edge is in-box and Microsoft-signed. |
| Fingerprint spoofing | Makes the browser rarer, and rarity is what fingerprinting feeds on. Measured, rejected. |
| Any third-party Python dependency | Every package added is a package the user must trust. CI fails if a `requirements.txt` appears. |
| Blocking localhost | Not possible. Windows Firewall does not filter loopback. Documented rather than pretended. |
| Machine-wide Edge policy | Would change every Edge profile on the PC, including ordinary browsing. Far broader than bruhswer is permitted to be - which is also why the Edge sign-in limitation stands. |
| A telemetry or crash-reporting endpoint | There is no network client in bruhswer's own code, and there is not going to be one. |

---

## Contributing to any of this

Issues and pull requests welcome. Two rules, both non-negotiable:

1. **No unverified claim.** New control, new test. If the platform will not let you
   prove it, it reads `NOT ENFORCEABLE` or `UNKNOWN`, and that is a perfectly good
   outcome.
2. **No new dependencies** without a very strong case.

Security findings go through the private channel, not a public issue. See
[`SECURITY.md`](../SECURITY.md).
