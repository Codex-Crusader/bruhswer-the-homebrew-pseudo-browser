# Security testing guide

For security researchers looking at bruhswer.

This document exists so you can spend your time on the interesting parts instead of
rediscovering things that are already known, already measured, or already documented
as unfixable. It tells you where the trust boundaries actually are, what has already
been tried, how to set up a test environment, and how to report what you find without
either of us getting it wrong.

**Please read [Already known](#already-known) before reporting.** Several of the most
obvious findings here are documented platform limitations, and re-reporting them costs
you effort and tells us nothing new.

Reporting channel and scope: [`SECURITY.md`](../SECURITY.md).

---

## 1. Safe harbour

If you are researching in good faith under this document, this project will not pursue
or support legal action against you, and will treat your report as a contribution.

Good faith means:

- You test against **your own machine and your own installation**. Not someone else's.
- You do not access, modify, exfiltrate or destroy data belonging to anyone else.
- You do not degrade service for anyone else. There is no server to attack; bruhswer
  runs entirely on the user's own PC, so this mostly means "do not attack the GitHub
  repository or its infrastructure".
- You give a reasonable disclosure window (see `SECURITY.md`; 90 days is what this
  project asks for).
- You report through the private channel rather than publishing first.

This is a volunteer project with no bug bounty and no money. What is on offer is a
credited advisory, a fix, and a straight answer about whether you are right.

If you are unsure whether something is in scope, ask first, privately. "Is this worth
reporting?" is a perfectly good message to send.

---

## 2. Where the trust boundaries actually are

bruhswer is a Python process that launches and hosts Microsoft Edge. It has **no
network listener of any kind**. That shapes what is worth attacking.

```
   a hostile website
          |
          v
   +---------------+   Edge's own renderer sandbox (AppContainer, UNTRUSTED)
   |   renderer    |   NOT bruhswer's boundary. Report Chromium bugs to Microsoft.
   +---------------+
          |
          v
   +---------------+   The Edge BROWSER process. Ordinary user token, NOT sandboxed.
   |    broker     |   bruhswer does not claim to contain this. Measured, Stage 4 A4.
   +---------------+
          |
          | <-- THE INTERESTING BOUNDARY: what can a compromised browser process,
          |     running as the user, do to or through bruhswer?
          v
   +---------------+   bruhswer: Python, unelevated, no listener, no IPC.
   |   bruhswer    |   Reaches the OS only through a fixed set of constant
   +---------------+   PowerShell queries and icacls, always with an argv list.
          |
          | <-- and: can anything reach Administrator from here?
          v
   +---------------+   The elevated one-shots in bruhswer/tools/*.ps1.
   | elevated PS1  |   Run knowingly by the user, with a confirmation word.
   +---------------+
```

### Where untrusted input enters

This is the list worth auditing. Everything else is bruhswer's own constants.

| Input | Enters at | Handling |
|---|---|---|
| Address-bar text | `app/browser/urls.py::normalise` | Must become an `http(s)` URL or be refused. Anything else - `file:`, `javascript:`, `data:`, `vbscript:`, `blob:`, `chrome:`, `edge:`, `view-source:`, `ftp:`, `ws:`, `wss:`, UNC paths, drive letters, control characters - is refused, not escaped. |
| Downloaded filename | `app/downloads/quarantine.py::safe_export_name` | Treated as hostile text. The name is rebuilt from scratch; separators, drive letters, ADS, traversal, reserved device names and leading dots are removed as a class rather than filtered case by case. |
| Export destination | `app/ui/browser_window.py::_export` | Comes from the user's own folder picker. Never from a page, a download, or any external source. |
| Downloaded file content | Never parsed | bruhswer never opens, executes, scans or inspects a downloaded file. It moves and lists them. |
| Firewall rule readback | `app/sysquery.py::bruhswer_rules` | Parsed as JSON, compared against expected constants. A rule under bruhswer's prefix that it did not author is a launch blocker. |
| Profile `Preferences` | `app/privacy/privacy_guard.py` | Read back to verify settings stuck. Chromium owns this file and rewrites it, so it is treated as untrusted JSON. |
| Window titles | `app/browser/embed.py::window_title` | Displayed, truncated. Never used for a decision or a path. |

### Invariants worth trying to break

If you can break one of these, it is a finding:

1. **No browser-controlled value ever reaches a path, an argv element, or a PowerShell
   string.** `app/sysquery.py` is the only place an external program runs, every script
   in it is a module constant, and the only interpolated values are bruhswer's own
   constants or integers it validated.
2. **bruhswer opens no listening socket, named pipe or debugging port.** Enforced by an
   AST test, not just by intent.
3. **The browser cannot launch with a security-weakening flag.** `edge.build_command`
   refuses `DANGEROUS_FLAGS` rather than filtering them.
4. **A recursive delete cannot leave its root.** Both in the app and the uninstaller,
   including via directory junctions.
5. **A critical check that is not `PASS` blocks launch.** There is no override, no
   "continue anyway", and no environment variable that disables verification.
6. **Nothing is written outside `%LOCALAPPDATA%\BRUHWSER`** except the installer's
   ordinary per-user registrations.
7. **A claim shown to the user is true.** See below - this is the one we care about most.

### The defect class this project treats most seriously

**A false security claim is a vulnerability here**, not a documentation bug.

If bruhswer tells the user something is verified, blocked, enforced or applied, and it
is not, that is the finding - even if nothing is otherwise exploitable. Every
user-visible defect this project has found in itself was of that shape:

- downloads reported as quarantined while landing in the real Downloads folder
- a disposable session reported "destroyed and verified gone" while leaving every
  downloaded file on disk
- a renderer-sandbox check that was a hardcoded `PASS` quoting an old measurement
- a privacy panel showing intended settings as confirmed state

So: compare what the UI says against what the system actually does. That is the most
productive thing you can do with this codebase.

---

## 3. Setting up a test environment

### What you need

- Windows 10 or 11
- Python 3.11+
- Microsoft Edge
- Optional but recommended: a VM or a spare account. bruhswer is unelevated and writes
  only under `%LOCALAPPDATA%\BRUHWSER`, but the firewall step below is a real change to
  the machine.

### Get it running

```powershell
git clone https://github.com/Codex-Crusader/bruhswer-the-homebrew-pseudo-browser
cd bruhswer-the-homebrew-pseudo-browser\bruhswer
python bruhswer.py --check      # no browser, no changes, prints every verdict
```

`--check` is the safest entry point and the best starting place: it runs the whole
verification and changes nothing.

### Apply network policy (needed for most network testing)

This creates two Windows Firewall rules scoped to `msedge.exe`. It needs Administrator
and it is reversible:

```powershell
# Administrator PowerShell
.\tools\bruhswer-netpolicy.ps1 -Action apply
.\tools\bruhswer-netpolicy.ps1 -Action status
.\tools\bruhswer-netpolicy.ps1 -Action remove     # undo, completely
```

**Remember to remove them when you are done.** They will keep blocking Edge from your
router after you delete the repository, which is why `python bruhswer.py --uninstall`
exists and prints the removal command.

### Run the suites

```powershell
python tests\run_all.py                    # everything, one verdict
python tests\test_security.py              # unit + static analysis, no browser needed
python tests\test_localhost_surface.py     # the localhost attack matrix
python tools\real_world_walkthrough.py     # drives the real GUI
```

Suites that need the firewall policy report **SKIPPED** rather than passing quietly. If
you see SKIPPED, the result is not a pass.

### Reset between tests

```powershell
python bruhswer.py --uninstall    # lists everything, asks twice, then removes
```

---

## 4. Already known

Please do not report these as new. They are measured, documented, and either unfixable
within the project's scope or deliberately accepted. If you can show one is **worse
than documented**, that absolutely is a finding.

| Known issue | Status | Where it is documented |
|---|---|---|
| **Localhost is fully reachable** from page content: `127.0.0.1`, `127.0.0.2`, `localhost`, decimal `2130706433`, hex `0x7f000001`, IPv6 `[::1]`, the host's own LAN IP, by navigation and by `fetch`/`POST`/WebSocket. 19 paths measured, all reached. | NOT ENFORCEABLE. Windows Firewall does not filter loopback. No configuration fixes it. | `tests/test_localhost_surface.py`, `THREAT-MODEL.md` |
| **Edge auto-signs profiles into the Windows Microsoft account**, including disposable ones, and syncs favourites. `--disable-sync` stops the sync; nothing on the command line stops the sign-in. | NOT ENFORCEABLE without machine-wide Edge policy, which is out of scope. | `PRIVACY.md` §7, `privacy_guard.verify_account_signin` |
| **The Edge browser process is not sandboxed.** Chromium's sandbox contains renderers. | By design, stated everywhere. | `THREAT-MODEL.md` |
| **DNS encryption cannot be confirmed.** | UNKNOWN, deliberately not guessed. | `NETWORK-PRIVACY.md` |
| **IPv6 is only partly verified.** | Stated as such. | `RELEASE-CANDIDATE.md` |
| **No defence against same-user malware or a compromised PC.** bruhswer runs on the user's token. | Out of scope, stated. | `SECURITY.md` |
| **Release artifacts are unsigned.** | No certificate exists. Self-signing and calling it trusted was refused. | `RELEASE-NOTES-0.9.0.md` |
| **TOCTOU in the deletion guards.** The path could in principle be swapped between the check and `rmtree`. | Accepted. Needs handle-based APIs Python does not expose on Windows; an attacker who can win it already runs as the user. | `session_manager._safe_to_delete` |
| **No encryption at rest added by bruhswer.** | A documented trade-off, with the reasoning and a correction to an earlier overclaim. | `DATA-INVENTORY.md` §4 |
| CGNAT `100.64.0.0/10` is deliberately **not** blocked. | Intentional: it carries some users' only route to the internet. | `config.BLOCKED_IPV4` |

### Things previously tried that did not work

Recorded so you do not repeat them:

- `--download-directory=` is **not a real Chromium switch**. Edge ignores it silently.
  The quarantine path is a profile preference, verified by readback.
- `credentials_enable_service` and `session.restore_on_startup` are **tracked
  preferences**; Chromium reverts externally written values. Measured across three
  consecutive launches.
- `icacls /inheritance:r` with `/T` makes the profile unreadable while returning exit
  code 0.
- `Path.is_symlink()` returns **False** for a Windows directory junction. A guard
  written with it is inert.
- `shutil.rmtree(junction, ignore_errors=True)` does not delete through the junction;
  it refuses and the error is swallowed.

---

## 5. Writing a report we can act on

Send it privately: **Security tab → Report a vulnerability**.

A good report for this project answers four questions:

1. **What claim is broken, or what boundary is crossed?** Quote the exact UI text, doc
   line or check ID if a claim is involved.
2. **How do I reproduce it?** Exact steps from a clean install. A script is ideal.
3. **What did you observe, and how did you observe it?** Server-side log, `icacls`
   output, Process Monitor trace, profile JSON - whatever you actually looked at.
   "It should be possible" is not an observation.
4. **What is the impact, and under what preconditions?** Be explicit about whether you
   already needed Administrator, physical access, or code execution as the user.

### Template

```
SUMMARY
One sentence. What is broken.

AFFECTED
File and function, or the exact UI element / document line.
Version or commit tested.

ENVIRONMENT
Windows version, Python version, Edge version.
Was network policy applied? (tools\bruhswer-netpolicy.ps1 -Action status)

PRECONDITIONS
What access does the attacker need before this works?

REPRODUCTION
1.
2.
3.

OBSERVED
What actually happened, and the evidence you collected.

EXPECTED
What bruhswer says or implies should happen, quoted.

IMPACT
Who is harmed and how. Say if you think it is low.

SUGGESTED FIX
Optional. Happy to receive it, happy to disagree with it.
```

### What happens next

1. Acknowledgement, target 7 days.
2. Reproduction attempt. If it cannot be reproduced you will be told exactly what was
   tried, rather than being quietly closed.
3. Assessment against the scope in `SECURITY.md`, target 30 days.
4. If confirmed: a fix **and a regression test named after the defect**. Every accepted
   finding in this project has become a test, so it cannot come back silently.
5. If it cannot be fixed within the project's scope: it gets documented as a limitation,
   publicly, in the same honest language as the localhost limitation. It does not get
   quietly dropped.
6. Advisory published, crediting you unless you ask otherwise.

### Reports that will be declined, politely

- Automated scanner output with no analysis, and no demonstration that it applies here.
- Anything from the [Already known](#already-known) table, unless you show it is worse
  than documented.
- Chromium, Edge or Windows vulnerabilities. Report those to Microsoft.
- Anything requiring privileges the attacker would already have.
- "You should add feature X." That is an issue or a discussion, not a vulnerability.

---

## 6. If you want to go deeper

The most valuable contributions, roughly in order:

1. **A claim that is not true.** Anywhere in the UI or the docs.
2. **A way for page content to influence a path, an argv element or a PowerShell
   string.** This is the injection surface, and it is deliberately small.
3. **A download-quarantine escape**, or getting bruhswer to execute or open a
   downloaded file.
4. **A privilege escalation** through the elevated one-shots, or a way to make a
   normally-unelevated flow elevate.
5. **A firewall-policy bypass** that does not depend on already having Administrator.
6. **Host Guard applying or failing to roll back a change** without consent.
7. **An installer or uninstaller defect** - it is part of the security boundary and gets
   the same review as the application.

The threat model, with attacker capabilities and what is explicitly not defended,
is in [`THREAT-MODEL.md`](THREAT-MODEL.md). The record of the last independent review,
including findings that were accepted, corrected and one whose severity was reduced
after measurement, is in [`CODEX-REVIEW-0.9.0.md`](CODEX-REVIEW-0.9.0.md).

Thank you for looking. Honest findings are the point of the project.
