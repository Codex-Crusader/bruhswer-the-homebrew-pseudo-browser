# Roadmap

What is planned, in rough priority order. Nothing here is promised, and nothing here is
a claim about the current release - if it is on this page, **it does not exist yet**.

Current release: **v0.12.0**, pre-1.0. What it actually does and does not do is in
[`RELEASE-CANDIDATE.md`](RELEASE-CANDIDATE.md) (the original 0.9.0 publication pass;
see `docs/releases/CHECKLIST-0.11.0.md` for what changed since) and the
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

Mostly done as of 0.11.0. `tools/verify_install.py` now runs the checks that used to be
manual and reported **26/26** for the 0.11.0 release: install-time file-manifest
verification against a built installer, silent uninstall, uninstall leaving nothing
behind (install dir, registration, shortcut), and - the one that actually mattered -
uninstall leaving USER DATA alone. That last check exists because its first run
discovered the opposite: a silent uninstall deleting a real 110 MB browsing profile
while reporting that it had not (`docs/releases/CHECKLIST-0.11.0.md`).

Still open:

- A genuinely clean Windows image with no Python, no Edge, no prior install. The
  prerequisite refusals have not been re-verified since 0.9.1 - `verify_install.py`
  cannot run them, because it refuses to run while bruhswer is already installed.
- Launching from the Start Menu / Desktop shortcut. The shortcut is created and removed
  correctly; nothing has actually clicked it.

### 3. Upgrade path

Still not designed. Four releases (0.9.1 through 0.11.0) have shipped over an existing
persistent profile without incident, but "nothing has broken yet" is not a design, and
this stays open until it is one.

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

**Partly addressed as of 0.12.0, and the boundary matters.** CI now generates a
signed SLSA build-provenance attestation for the installer and verifies it in the
same run. Anyone can check which commit and which workflow produced a given binary:

```
gh attestation verify bruhswer-0.12.0-setup.exe \n  --repo Codex-Crusader/bruhswer-the-homebrew-pseudo-browser
```

That sits between the two claims above: stronger than signing, because it binds the
artifact to a specific source commit and build, and weaker than reproducibility,
because you still cannot rebuild the tagged source yourself and confirm you get the
same bytes. You are trusting GitHub's runner rather than checking its work. The four
items above remain open and this item is NOT done.

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

#### Adversarial vectors the firewall suites do not yet cover

The firewall is the main enforced boundary, and it is scoped to an executable identity.
Everything that changes which process is sending traffic is therefore worth attacking,
and none of these is currently a test:

| Vector | The question |
|---|---|
| Process tree | Do Edge's child and helper processes inherit the rule, or does a helper send from an image the rule does not name? |
| Executable replacement | What happens if the named `msedge.exe` path is replaced or shadowed? |
| Edge update | An update rewrites the binary. Does the rule still bind after it, and does bruhswer notice if it does not? |
| DNS separately from destination IP | The suites block destination addresses. The browser to resolver to private-destination path is a different question and deserves its own model |
| IPv6 | Link-local, ULA, IPv4-mapped IPv6, dual-stack fallback, and DNS resolving to a private IPv6 address |

`test_localhost_surface.py` already probes IPv6 loopback and several address encodings,
so the machinery exists. These would extend it rather than start from nothing.

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

### 8. Threat model, kept current - DONE for 0.9.0

[`SECURITY-MODEL.md`](SECURITY-MODEL.md) is the current threat model, guarantees and
verdict semantics, with [`LIMITATIONS.md`](LIMITATIONS.md) carrying the measured
boundaries. The Stage-1 threat model that used to sit here described the rejected WSL2
design and is now clearly filed under [`research/`](research/).

Remaining: this is upkeep, not a task. Every measurement that stops holding - an Edge
change, a new gate result - has to land here, not only in a release note.

### 9. Release checklist - DONE

[`RELEASE-CHECKLIST.md`](RELEASE-CHECKLIST.md) is a standalone template, filled in and
committed per release, so each release keeps its own signed-off record instead of one
file being overwritten.

### 10. Security disclosure process

Largely in place: [`SECURITY.md`](../SECURITY.md) has scope, timelines and channel,
private vulnerability reporting is enabled, and
[`SECURITY-TESTING.md`](SECURITY-TESTING.md) tells researchers where the boundaries are
and what is already known.

Remaining: publish advisories through GitHub's advisory database when a fix ships, and
keep a public record of findings that were accepted and declined, with reasons.

### 11. A recorded demo

The README has four screenshots. What it does not have is the thing that makes the
project legible in thirty seconds: a recording of the controls actually holding, and
one of them visibly not holding.

It has to be a **real screen capture of a real session**. A rendered terminal animation
of text nobody measured would be a fabricated verdict on the front page of a project
whose entire argument is that verdicts must be measured, so that option is closed.

Shot list, in order, roughly 30 seconds:

| | Shot | What it has to show |
|---|---|---|
| 1 | Launch | The curtain, then verification running |
| 2 | `BRUH CHECK` panel | Real verdicts, scrolled slowly enough to read |
| 3 | Navigate to the router address | Blocked, from the browser's own error page |
| 4 | Download a file | It appears in the quarantine panel, not in Downloads |
| 5 | Close a disposable session | The deletion warning, then the profile gone |
| 6 | The localhost row | `NOT ENFORCEABLE`, held on screen long enough to read |

Shot 6 is the point of the whole recording. A demo that shows only the green lights
would be the marketing page this project exists to argue against.

Capture with Xbox Game Bar (`Win`+`Alt`+`R`) or any recorder, check the frames for
personal data - real SSID, hostname, account name, favourites - before publishing, and
put it in `docs/assets/`.

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
