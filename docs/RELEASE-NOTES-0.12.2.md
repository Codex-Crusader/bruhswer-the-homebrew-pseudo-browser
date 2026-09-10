# bruhswer 0.12.2

**Three ways a security check could crash or lie instead of saying "I could not look",
and the GUI harness that had stopped looking at all.**

Every defect here is the same shape, and it is the shape this project keeps finding in
itself: a check that cannot complete must report UNKNOWN, not a verdict, and not an
exception. Two of these were reachable from an ordinary launch.

---

## Fixed

### A Preferences file that parses but is not an object crashed four readers

`privacy_guard` parsed Chromium's `Preferences` with `json.loads` and then indexed the
result as a mapping. A file containing `[]`, `null` or `"x"` parses fine and is none of
those things, so all four readers raised `AttributeError` instead of returning the
"could not read it" sentinel the callers already know how to render as UNKNOWN.

Two of the four - `apply_to_profile` and `apply_download_directory` - run inside
`Controller.start()`, which has no handler.

A fifth case was quieter and worse: `account_info` holding an object rather than a list
did not raise. It read as **"No Microsoft account is signed into this profile."** - a
green privacy light over a file bruhswer had not understood.

All five now route through one `_read_prefs()` derivation that treats a non-object as
unreadable, plus shape guards on `download` and `account_info`. A missing key is still a
genuine FAIL, because that is a real finding; only a wrong *shape* becomes UNKNOWN.

Measured against real files on disk, not a patched `read_text`.

### `check_tree()` raised out of startup verification, despite promising not to

`integrity.check_tree` catches `OSError` around `manifest_path.read_text()`.
`UnicodeDecodeError` is not an `OSError`, so a `MANIFEST.sha256` holding non-UTF-8 bytes
threw straight through a function whose docstring says *"Never raises."*

### A damaged manifest was reported as a missing one

A blank, corrupt or unreadable manifest produced a report byte-identical to no manifest
at all, so the security panel said:

> No file manifest shipped beside this copy of bruhswer, so its files were not compared
> against anything. **This is normal when running from a source checkout.**

That sentence is true for an absent manifest and false for a ruined one inside a real
install - which is the difference between "nothing to check" and "the thing that does
the checking is damaged". The report now carries `manifest_unreadable` alongside
`manifest_present`, and `verify()` reports `UnknownReason.UNREADABLE` with wording that
tells the user to reinstall. `hash_manifest.py --check` stopped printing "NO MANIFEST"
about a file that is sitting right there.

### The GUI walkthrough had been passing on a step it could not pass, and hanging on the next

`tools/real_world_walkthrough.py` is the check this project trusts most for `ui/`
changes - it has found defects that hundreds of assertions did not. It was broken, in
two linked ways, and had been since `open_security_panel()` became asynchronous:

- **Step 6 could never pass.** It called the opener, pumped Tk exactly once, and
  asserted a window had appeared. The panel runs a 5.5s verification off-thread first,
  so the assertion ran about five seconds too early, every time.
- **The panel it leaked then hung the run.** Arriving late, the Toplevel was still
  parented to the root when step 14's dialog driver went looking for "the first
  Toplevel" to dismiss. It destroyed the stray panel instead of the confirmation
  dialog, and the modal wait never returned. **Steps 14 through 33 - including the
  entire panic path - had silently stopped executing.**
- **Step 27's BRUH row was a hardcoded `True`.** It reported "panel renders with the new
  checks" without ever checking that one had rendered.

Panels are now opened through a helper that waits for the window and closes it again,
and the dialog driver matches the dialog **by title** so nothing else can be driven in
its place. The run goes 37 OK, 0 problems, with steps 6 and 27 finally measuring
something.

### One latent trap removed

`quarantine.sniff_kind` read a literal 8 bytes, which happens to equal the longest
signature in `_MAGIC`. Adding a longer signature would have left it permanently
unmatchable, with the file reported as "nothing recognised". Now derived from the table.

---

## Also in this release: the comment cull

The source carried 26% prose. Long narrative blocks recording how a defect was found had
outlived the defect, and a file that is mostly commentary is harder to read, not easier.

**614 lines of prose removed, no executable code changed.** Every measured fact,
platform gotcha and honest limitation was kept - compressed to the sentence that
carries it. Every `# noqa` and `# lint: allow` marker survives.

That claim is mechanical, not a promise: each file's AST was compared against its
pre-edit form with all docstrings stripped, and the source was checked for newly
introduced non-ASCII characters. The second check exists because the first cannot see
it - rewriting a unicode escape in `urls.py`'s bidi-character class as the character it
denotes leaves the string *value* identical while putting an invisible,
direction-reversing character into the source, which is precisely what that file exists
to refuse. It caught exactly that mistake once.

---

## Verifying this release

```
gh attestation verify bruhswer-0.12.2-setup.exe \
  --repo Codex-Crusader/bruhswer-the-homebrew-pseudo-browser
```

The SHA-256 in `SHA256SUMS.txt` is published and still worth checking. Provenance
answers a different question: not *"is this the file the author meant to publish"* but
*"was this built by this repository's CI, from source anyone can read"*.

Unchanged, and still true: this is **not a reproducible build** - Inno Setup embeds
build-time state, so rebuilding the tagged source gives different bytes. It is **not
code signed**, and SmartScreen will warn about an unrecognised publisher. **v0.12.0 has
no attestation** and returns 404; that artifact has deliberately not been replaced.

## Tests

329 assertions across 17 suites, 0 failures, run twice with the same result. GUI
walkthrough 37 OK / 0 problems. Network policy was applied, so no suite was SKIPPED.

The seven new assertions are regression tests, and each was confirmed to **fail against
the pre-fix code** - 8 errors and 1 failure in `test_overclaim_regressions.py`, 5 errors
in `test_integrity.py`. A regression test that would have passed before the fix
documents nothing.

## Changes

| | |
|---|---|
| `app/privacy/privacy_guard.py` | One `_read_prefs()` derivation; a Preferences file that is not a JSON object is unreadable, not a crash and not a clean read |
| `app/security/integrity.py` | `UnicodeDecodeError` caught; new `manifest_unreadable`, and a `verify()` branch that does not explain a damaged manifest away as a missing one |
| `app/downloads/quarantine.py` | Signature read length derived from the table rather than a literal |
| `tools/real_world_walkthrough.py` | Waits for asynchronous panels; matches the dialog by title; step 27 measures instead of asserting `True` |
| `tools/hash_manifest.py` | Distinguishes an unreadable manifest from an absent one |
| `tests/` | 7 new regression assertions, all verified to fail pre-fix |
| everywhere | 614 lines of prose removed, AST-verified to have moved no code |
