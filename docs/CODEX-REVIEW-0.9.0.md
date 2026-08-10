# Independent review record - 0.9.0 publication pass

Two engineering perspectives were used on this pass, as the brief requires: Claude
implemented, Codex (`gpt-5`, read-only, no file modification) reviewed the changed
repository independently and produced findings only.

**Nothing was accepted on assertion.** Every finding below was checked against the
actual code and, where behaviour was in question, measured. Two of Codex's findings
turned out to be partly wrong when tested, and that is recorded here rather than
quietly dropped - the measurement is the tie-breaker, not the reviewer's confidence
or mine.

---

## Findings

### C1 - Recursive delete could follow a directory junction
- **Severity claimed:** High · **Severity after measurement:** Medium
- **Affected:** `app/sessions/session_manager.py` (`sweep_orphans` profile loop),
  `bruhswer.py` (`--uninstall`)
- **Finding:** The profile-sweep loop called `shutil.rmtree` on any 16-hex directory
  without checking for a reparse point. `Path.is_dir()` follows a junction, so a
  junction planted under the disposable root by anything running as the user would
  look like an orphaned profile.
- **Evidence gathered:** Junction created with `mklink /J`, then
  `shutil.rmtree(link, ignore_errors=True)` on Python 3.11.9 / Windows 11.
  **Result: the target's contents survived.** `rmtree` refuses to recurse through the
  junction and the error is swallowed by `ignore_errors=True`.
- **Verdict: ACCEPTED, with the severity corrected.** The escape Codex described does
  not occur on this platform - the un-guarded code was a silent no-op, not a
  delete-anything primitive. It was still fixed, because relying on an undocumented
  `rmtree` behaviour staying true in a future Python is not a control, and because
  `destroy()` and the quarantine sweep already had the guard while this path did not.
- **Bonus defect found while testing:** the first version of the fix used
  `Path.is_symlink()`, which **returns `False` for a Windows directory junction** -
  the check looked right and was completely inert. Replaced with the
  `FILE_ATTRIBUTE_REPARSE_POINT` file-attribute test, the same idiom `quarantine.py`
  already used. This was only caught by measuring the guard rather than trusting it.
- **Test:** `test_security.py::TestDisposableLeavesNothingBehind::test_sweep_refuses_to_delete_through_a_junction`
  - plants a real junction and asserts the target survives. Skips loudly if the OS
  refuses to create one, rather than passing vacuously.

### C2 - Installer uninstall followed reparse points
- **Severity: High. Confirmed exploitable.**
- **Affected:** `installer/bruhswer.iss` - `RemovePycacheDirs`, and the data-deletion
  `DelTree` calls
- **Finding:** The recursive `__pycache__` sweep tested `FILE_ATTRIBUTE_DIRECTORY` but
  not `FILE_ATTRIBUTE_REPARSE_POINT`, so a junction below the install folder would
  redirect `DelTree` outside the install tree. The procedure's own comment claiming it
  stayed "beneath the install folder" was therefore false.
- **Evidence:** Installed, planted a junction at
  `…\Programs\bruhswer\bruhswer\app\__pycache__` pointing at a directory outside the
  install tree containing a marker file, ran the uninstaller.
  **Before the fix this was a real escape; after the fix the marker file survived and
  the install folder was still fully removed.**
- **Verdict: ACCEPTED and fixed.** Reparse points are now skipped in the recursion,
  and data-folder deletion goes through `DeleteDataFolder`, which refuses a reparse
  point. `GetFileAttributesW` is imported from `kernel32` because Inno has no built-in
  attribute helper.

### C3 - Installer permitted elevation while claiming it never asks
- **Severity: Medium. Confirmed.**
- **Affected:** `installer/bruhswer.iss`
- **Finding:** `PrivilegesRequired=lowest` was paired with
  `PrivilegesRequiredOverridesAllowed=dialog`, which offers an elevated install mode -
  contradicting the installer's own stated guarantee.
- **Verdict: ACCEPTED and fixed.** The override line is removed. An installer that
  says it does not elevate must not carry the switch that lets it.

### C4 - Python 3.11+ was never actually checked
- **Severity: Medium. Confirmed.**
- **Affected:** `installer/bruhswer.iss` - `FindPython`, `InitializeSetup`
- **Finding:** The prerequisite check only proved a launcher *existed*. The `py`
  launcher's default could be 3.9, and bruhswer uses 3.11+ syntax, so the install
  would succeed and the shortcut would fail with a `SyntaxError` on first click.
- **Verdict: ACCEPTED and fixed.** `PythonVersionIsSupported()` now executes the
  interpreter with `sys.version_info >= (3, 11)` and refuses on a non-zero exit or if
  it cannot be run at all.

### C5 - The encryption-at-rest reasoning overclaimed
- **Severity: Medium. Confirmed - this one was a genuine error of mine.**
- **Affected:** `docs/DATA-INVENTORY.md` §4, `README.md`
- **Finding:** The document argued that application-level encryption "would defend
  against nothing", and that against offline disk theft "the key would be on the same
  disk". The second claim is false: a DPAPI master key is protected by material
  derived from the user's Windows credentials, so an offline attacker without the
  password is in a materially different position.
- **Verdict: ACCEPTED and corrected.** The conclusion (bruhswer adds no encryption)
  stands, but it is now presented as a **trade-off with stated reasons** - Edge needs
  its profile live and writable, Edge already DPAPI-protects the sensitive fields, and
  BitLocker is the correct control for disk theft - rather than as "encryption would
  be useless". The correction is documented in place, because dismissing a real
  protection is the same class of error as overstating one.

### C6 - "No registry keys" and "no credentials" were true of the app, not the product
- **Severity: Medium. Confirmed.**
- **Affected:** `docs/DATA-INVENTORY.md`, `README.md`
- **Finding:** Both said everything lives under `%LOCALAPPDATA%\BRUHWSER` with no
  registry keys. The installer necessarily creates an uninstall registration and
  shortcuts. Separately, "No credentials. No tokens." sat awkwardly beside a retained
  Edge profile that can hold cookies and saved passwords.
- **Verdict: ACCEPTED and corrected.** Both documents now separate what *bruhswer's
  code* stores from what *the profile it manages* can contain, and list the
  installer's registrations explicitly.

### C7 - `REPLACE-ME` placeholder repository URL
- **Severity: Publication blocker. Confirmed.**
- **Affected:** `README.md`, `installer/bruhswer.iss`
- **Verdict: ACCEPTED, not fixable here.** The real repository URL is not known to
  this pass. Rather than invent one, a CI hygiene job now **fails the build** while
  any `REPLACE-ME` remains, so it cannot be published by accident.

---

## Findings raised by Claude, confirmed by Codex

| # | Finding | Codex verdict |
|---|---|---|
| 1 | Disposable sessions left every downloaded file on disk forever; `sweep_orphans` swept profiles only; the quarantine panel only lists the current session, so the files were unreachable from the UI but readable on disk | Confirmed |
| 2 | `config.py` reserved a named-pipe control channel that was never implemented | Confirmed; no listener, pipe, DevTools flag or control channel found anywhere in `app/` |
| 3 | Printing the moai crashed with `UnicodeEncodeError` whenever stdout was a pipe, killing every text mode and the whole suite under CI | Confirmed |
| 4 | The uninstaller left 21 `.pyc` files in 10 `__pycache__` directories | Confirmed, with the reparse-point caveat now fixed as C2 |

## Found by Claude, missed by Codex

**`.gitignore` would have published a broken repository.** The pattern `downloads/`
was unanchored, and Git matches such a pattern at *any* depth - including
`bruhswer/app/downloads/`, a source package containing `quarantine.py`. The published
repository would have been missing the entire download-quarantine module and would not
have imported.

Codex explicitly examined `.gitignore` and reported that it "does not currently hide a
listed source file", which was incorrect. The defect was found by testing the file
against a real `git check-ignore` in a scratch repository rather than by reading it.
Every runtime-data pattern is now anchored with a leading `/`, and the reasoning is
recorded in the file itself.

This is the clearest argument on this pass for measuring rather than reviewing: two
models read that file and neither spotted it; thirty seconds of `git check-ignore`
did.

## Areas Codex examined and found clean

- No URL or download-name route to shell or PowerShell injection. Browser URLs travel
  as separate argv elements; PowerShell substitutions are constants or validated
  integers; `shell=False` throughout.
- No listener, named pipe, DevTools endpoint or local control channel in `app/`.
- No real credentials, personal developer paths or email addresses in the tree. The
  only `C:\Users\…` match is a synthetic path-traversal test case.

## Accepted risks

- **Time-of-check/time-of-use** in the deletion guards. Closing it needs handle-based
  APIs Python does not expose on Windows. An attacker able to win that race is already
  running as the user, which the threat model states is not defended against.
  Documented in `_safe_to_delete`.
- **Loopback remains reachable.** Unchanged, unfixable, measured 19 ways, reported as
  `NOT ENFORCEABLE` everywhere and enforced by a regression test.
- **Release artifacts are unsigned.** No code-signing certificate exists for this
  project, and self-signing while describing it as trusted publisher authentication
  was explicitly refused.
