# bruhswer 0.12.0

**A line-by-line audit of every shipping file, and the README stops burying the point.**

0.11.0 made every verdict declare its evidence. This release goes looking for the places
where the code did not live up to that, reading `bruhswer.py` and all 43 files under
`app/` one at a time rather than waiting for a test to fail.

Fourteen defects, each reproduced before it was fixed. Two of them were security
indicators that were wrong in the direction this project cares about most: one rendered
a control green while its neighbour rendered the same fact red, and one made ten
different privacy settings display as the same line of text.

No behaviour was changed that a user asked for. The suite is 322 assertions across 17
suites, passing before and after.

---

## Fixed: a status light that contradicted the one next to it

`browser.sandbox.flags` was a hardcoded `Verdict.PASS` with the detail text *"bruhswer
never passes --no-sandbox or any flag that weakens the renderer sandbox"*.

It never looked at anything. With such a flag actually present in the command line,
`browser.cmdline` immediately above it goes FAIL and names the flag, while this row sat
underneath it, green, asserting the opposite. Two rows, same argv, contradictory claims,
and the green one was a constant.

It is now derived from the same `argv` scan that feeds `browser.cmdline`.

## Fixed: ten privacy settings rendered as the same line

The Privacy panel lists each preference key with its own verdict. The label column was
`width=34` characters, and Tk clips a `Label` at its declared width rather than growing
it, so every key longer than that was cut - from the tail.

Chromium preference keys differ only at the end. Measured across the 23 keys bruhswer
writes:

```
distinct keys                          23
distinct as rendered before this fix   13
```

`profile.default_content_setting_values.media_stream_camera` and
`...media_stream_mic` both displayed as `profile.default_content_setting_va`, each with
its own independently-computed verdict beside it. A user reading the panel could not
tell which setting a CONFIRMED or NOT APPLIED belonged to.

The privacy panel now uses a column wide enough for the real keys, and `chrome.line`
gained an elision that shortens from the **middle**, keeping both ends - because cutting
the tail is what caused this, and a naive ellipsis would have reintroduced it. Nothing
elides at the current width; it is a guard against a longer key added later.

## Fixed: the Network panel hid its own evidence column

`docs/assets/shot-network.png` in the previous release shows it: `RULE SET, EFFECT NOT
MEASUR`, `(historical evic`. The panel is 640px with a vertical scrollbar only, so every
evidence note ran off the right edge and there was no way to scroll to it. The evidence
column is the entire point of 0.11.0 and it was the part being cut off.

Panels now open at 900x660. The first attempt at this fix changed the default on
`chrome.scroll_panel` and did nothing at all, because `BrowserWindow._panel` declares its
own `width=640` and passes it explicitly.

## Fixed: the uninstaller's junction guard was the one check known not to work

`run_uninstall()` refuses to delete through a link before it calls `shutil.rmtree` on
four directories. It used `Path.is_symlink()`.

This project measured, in Stage 4, that `is_symlink()` returns **False** for a directory
junction created with `mklink /J` - which is why `config.FILE_ATTRIBUTE_REPARSE_POINT`
exists, and why `session_manager._safe_to_delete` and `quarantine.export` both use the
attribute test and carry comments saying exactly this. The uninstall path used the check
the project had already proven inert, behind a comment claiming it stopped junctions.

Reproduced against a real `mklink /J` junction before fixing:

```
is_symlink   : False    <- the guard bruhswer.py used
reparse attr : True     <- the guard everywhere else uses
```

## Fixed: an unwritable profile crashed the launch instead of failing closed

`privacy_guard.apply_to_profile` and `apply_download_directory` both wrote Preferences
with no exception handling. Both are called from `Controller.start()`, which has no
handler either, so an `OSError` - a locked file, a full disk, an ACL - propagated out of
the launch path and reached Tk as an unhandled exception.

Both now return a failure and let the existing read-back checks report it. The download
check is critical, so a write that did not land still blocks the launch. Fail-closed is
unchanged; the crash is gone.

## Fixed: a duplicated `--disable-features` switch

In maximum privacy mode bruhswer emitted the switch twice:

```
--disable-features=EdgeShoppingAssistant,EdgeCollections,MsaAutoSignIn
--disable-features=InterestCohort,PrivacySandboxSettings4
```

Chromium keeps a single value per switch name, so one of those sets was being discarded.
Which one is Chromium's business; the defect is that bruhswer emitted an ambiguous
command line at all, and the set at risk contained `MsaAutoSignIn` - the measured
suppression behind the account-sign-in reporting.

`edge.build_command` now merges every `--disable-features` occurrence into one switch,
after the `DANGEROUS_FLAGS` scan and before the URL is appended, so both of those
invariants are untouched.

## Fixed: the panic key could stay dead for the rest of the run

`PanicHotkey.start()` early-returned on `self._thread is not None`. A previous fix
cleared that handle when *registration* failed, but the listener can also die inside its
message loop, and that path left the handle set - so every later `start()` returned the
stale "unavailable" without trying again.

`start()` now checks `is_alive()`, which covers both exits and let the earlier
special-case and its comment be deleted.

## Fixed: `--panel` mode ignored the theme entirely

The standalone control panel never called `apply_high_contrast()` or `apply_light()`, and
built its verdict colours into module-level tuples at import, so it could not have
followed a theme switch even if it had. It also drew one glyph for all three verdicts,
putting the whole meaning in hue - the thing `chrome.SHAPE` exists to prevent, and which
the browser window already did correctly.

The same defect was present in the browser window's own status lights: `chrome.COLOUR` is
a module-level snapshot taken at import, and `config.apply_high_contrast()` rebinds the
palette afterwards, so under high contrast the lights kept the dark theme's `#3FB950`
green - which config's own comment records as failing WCAG AA on black. The user the mode
exists for got the unreadable palette.

## Smaller fixes

| Defect | Where |
|---|---|
| `about:` was documented as refused but reached a search instead | `browser/urls.py` |
| A DNS probe failure was reported as "0 encrypted-DNS templates known to Windows" - a count from a read that never happened | `security/verifier.py` |
| `authenticode()` interpolated a caller-supplied path into a PowerShell string with no quote guard, while the equivalent in `embed.py` had one | `sysquery.py` |
| A stale request could outlive the session it described and be verified against a deleted profile | `ui/verify_worker.py` |
| `host.sharing.*` check ids were derived two different ways, one per code path | `host/host_guard.py` |
| Export filename collisions compounded: `a.txt` to `a_1.txt` to `a_1_2.txt` | `downloads/quarantine.py` |
| The source reparse check followed the link before reading its attributes | `downloads/quarantine.py` |
| `SystemParametersInfoW` and `GetSystemMetrics` were the only two undeclared prototypes in a file whose comment requires declaring every one | `browser/embed.py` |
| Three dead module-level aliases that ruff does not flag | `ui/verification_ui.py`, `ui/browser_window.py` |
| A duplicated `.replace()` call, a duplicated literal `25`, three function-local stdlib imports | various |

## Documentation

The README was 557 lines. It is 238.

Almost nothing was deleted: the detail was already in `docs/`, and the README had grown a
second copy of it. Five screen-height limitation blockquotes are now four bullets and a
link to `LIMITATIONS.md`, which already held all five. What genuinely only existed in the
README moved rather than going away:

- the manifest's drift-detection-not-tamper-protection boundary, and the panic key's
  registration limit, are now `LIMITATIONS.md` sections 12 and 13
- four self-found defects joined the ones already in `TESTING.md`
- contribution rules, dev setup and style became `CONTRIBUTING.md`
- `config.py`'s constant-by-constant rationale moved into `ARCHITECTURE.md`, which is
  what let that file drop from 422 lines to 276

**Screenshots retaken** against this build. The previous set predated the status-light
row, the account banner, the per-verdict shapes and the evidence notes. Two redactions:
a profile avatar and the machine's DNS resolver addresses.

## Known gaps, unchanged

Nothing in this release closes a 1.0 blocker. Releases are still unsigned, builds are
still not reproducible, and every measurement here was taken by the author with no
third-party audit. `docs/ROADMAP.md` tracks each one.

The `--panel` UI's layout has not been re-verified visually since its theme fix.
`tools/stage2`, `tools/stage4` and `tools/stage25` are captured research spikes,
excluded from lint, and were not part of this audit.
