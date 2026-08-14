# bruhswer 0.10.0

**The first feature release since 0.9.0, and a correction release at the same time.**

0.9.1 and 0.9.2 were fixes. This one adds five controls and removes three claims that
0.9.2 was making without having measured them.

The three removed claims matter more than the five features, so they come first.

---

## Three indicators that were lying in 0.9.2

This project's rule is that a security indicator nobody measured is a vulnerability in
its own right. Each of these shipped in 0.9.2, and each was found by a review that went
looking for exactly that class of defect.

### 1. The renderer sandbox reported PASS for processes it never measured

`summarise_renderers` dropped renderer processes whose token could not be read, then
compared the survivors against each other. Measured directly, by patching one of three
renderers to be unreadable:

```
3 renderers, 1 token unreadable   ->   PASS
                                       "All 2 renderer process(es) run at
                                        UNTRUSTED integrity"
```

A third renderer was hosting web content with its containment completely unknown, and
it was counted as a process that passed. Now the unreadable count is part of the answer
and any non-zero value forces UNKNOWN.

### 2. An unreadable profile reported "no Microsoft account is signed in"

`verify_account_signin` returned the same `(False, ...)` shape for "read the file, found
no account" and "could not parse the file at all". The caller turned everything that was
not signed-in into a PASS, so a `Preferences` file that was locked, truncated mid-write
by Chromium, or corrupt produced a green privacy light asserting a fact nobody had
established. Unreadable is now UNKNOWN.

### 3. IPv6 was reported BLOCKED with the same confidence as IPv4

The IPv4 rows rest on gate A16, which measured the effect empirically: the router went
REACHED to BLOCKED to REACHED as the rule was applied and removed. **No equivalent IPv6
measurement was ever taken.** The Network panel now reads `RULE SET, EFFECT NOT MEASURED`
for the IPv6 row, and a new check reports the gap explicitly.

bruhswer also cannot close that gap from inside itself: the rules are scoped to
`msedge.exe`, so a probe from bruhswer's own process would prove nothing about the
browser. That is the identical mistake that made the original localhost claim wrong.

---

## What is new

| Control | What it does | What it does NOT do |
|---|---|---|
| **Runtime re-verification** | Re-runs every check on a background thread once a minute. A control that stops holding downgrades its own light and says so. | It warns; it does not close your session for you. |
| **Panic key** (`Ctrl+Shift+End`) | Terminates this session's browser immediately, scoped by profile. | Never touches your own Edge. Says UNAVAILABLE if another app owns the hotkey. |
| **File manifest** | SHA-256s bruhswer's own source at startup against the list it shipped with. | Drift detection, not tamper protection. See below. |
| **Download content sniffing** | Reads a download's first bytes and flags a file whose content is a program while its name claims otherwise. | Not malware detection. "Nothing recognised" is not "clean". |
| **Address sanitising** | Refuses invisible, direction-reversing and credential-hiding URLs. | Does not detect homoglyphs. See below. |
| **Disposable overwrite** | Overwrites every file in a disposable profile with random bytes before deleting it. | Does not establish physical erasure. See below. |

The status bar gained a seventh light, `PANIC`, which is green only while the hotkey is
actually registered with Windows.

---

## New limits, stated as plainly as the features

**The file manifest is drift detection, not tamper protection.** The manifest sits in
the same folder as the code, and the code that checks it sits next to both. Anyone who
can edit `verifier.py` can edit the manifest and the checker in the same motion. It
catches a damaged download, a partial upgrade, and untargeted malware. It does not
resist an attacker. The check is non-critical and is titled *"Installed files match
their manifest"* rather than anything containing the word integrity or tamper.

**Overwriting a disposable profile does not establish physical erasure.** On an SSD,
wear levelling means the rewrite usually lands on a different physical page and the
original survives until the drive garbage-collects it. NTFS also journals metadata.
bruhswer cannot observe any of that and does not claim it. Files over 8 MB are skipped
for speed, and the count of what was skipped is reported rather than hidden.

**Address sanitising does not detect homoglyphs.** A domain spelled with a Cyrillic
lookalike is ordinary visible text and passes. Refusing all non-ASCII hosts would break
legitimate internationalised domains, and a partial lookalike table would itself be a
false claim of protection.

**The panic key can be taken by another application.** It is a global Windows hotkey, so
exactly one program can hold it. When bruhswer cannot have it, the PANIC light is red
and reads UNAVAILABLE, permanently, for as long as that is true. There is deliberately
no fallback to a key that only works while bruhswer has focus.

---

## Defects fixed during this work

Several were found only by driving the real GUI, not by the unit suites:

- **The panic key was completely inert.** It refused every process it was asked to stop.
  The two Windows sources for a process creation time have different precision -
  `GetProcessTimes` gives 100ns, `Win32_Process.CreationDate` truncates to microseconds -
  so an exact-equality identity check could essentially never match. Measured difference:
  8 ticks. The unit test missed it by reading both sides from the same API.
- **The Network panel crashed entirely** (`KeyError`) the moment the IPv6 state changed,
  because two separate hard-coded colour maps had to be kept in step by hand. Policy
  states are now a typed enum with one shared map.
- **Re-verification died permanently** after a session was closed and reopened, leaving
  the lights frozen on a stale result while presenting it as current.
- **A failed renderer query reported "no browser session is running"** while the browser
  was visibly on screen, and raised a red warning curtain that nothing could clear.
- **The panic path reported success it had not verified.** It now says explicitly when it
  could not confirm the browser stopped.
- A queued Tk callback fired against a destroyed interpreter on teardown.
- **The file manifest would have failed on every fresh clone.** This repository has
  `core.autocrlf` set and no `.gitattributes`, so git stores LF and checks CRLF out
  (`git ls-files --eol` reports `i/lf w/crlf`). A manifest generated on one working copy
  recorded different bytes from the ones a clone produces. Caught before release by
  copying the tree, converting all 61 source files to CRLF and re-running the check.
  Hashes are now taken over content with line endings normalised, so the result does not
  depend on how a copy was checked out.

---

## Verification

```
full regression suite      13 / 13 suites PASS, none skipped
real-world GUI walkthrough 37 / 37 OK
static analysis            0 findings
type checking              0 errors, 0 unresolved references
non-stdlib imports in app/ 0
```

Still unverified, and unchanged from 0.9.2:

- **Prerequisite refusals** need a Windows image with no Python and no Edge.
- **The install-time manifest check** has never executed against a built installer.
- **Edge signs even a disposable profile into your Microsoft account.** bruhswer now
  gives you a one-click route to Edge's sign-out page, but it cannot prevent the
  sign-in, and it does not claim to have signed you out.

---

## Upgrading

Nothing to migrate. Existing profiles and quarantine folders are untouched.
