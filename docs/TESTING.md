# Testing

**312 assertions across 17 suites, 0 failures.**

Counts are read from the run output, never carried forward from a previous release -
this number has drifted before when it was retyped from memory.

More usefully: what the tests actually establish, and what they deliberately do not.

> ### One known flaky suite
>
> `test_browser_ui.py` **failed once inside `run_all.py` and then passed 29/29 standalone
> minutes later, with no code change in between.** It is the only suite that has done
> this, and the cause is not yet known.
>
> This page previously said "no known flaky tests". That is why it no longer does.
> A flaky suite is a defect by this project's own release checklist, and pretending
> otherwise would be the same failure the rest of this document is about.
>
> The failure also exposed a second defect, since fixed: `run_all.py` printed only
> assertion failures and **discarded the child's stderr**, so a suite that crashed
> rather than failing an assertion reported `FAIL` with no evidence at all. It now
> prints the stderr tail when a suite produces no assertion failure.

---

## The suites

| Suite | Assertions | Needs | What it establishes |
|---|---|---|---|
| `test_security.py` | 52 | nothing | AST scans for dangerous primitives, the no-local-listener proof, URL refusal, filename sanitisation, session destruction incl. junctions, config sanity |
| `test_urls_fuzz.py` | 13 | nothing | Address-bar normalisation properties: what is accepted, what is refused, and that nothing becomes a flag |
| `test_overclaim_regressions.py` | 22 | nothing | The four indicators that lied - three in 0.9.2, one found by independent audit after 0.11.0 shipped - each pinned so it cannot come back |
| `test_evidence_model.py` | 19 | nothing | Every check declares its evidence kind against a frozen table; every UNKNOWN carries a reason; probe statuses and reason codes stay in step |
| `test_accessibility.py` | 16 | nothing | Verdicts are never carried by colour alone; the high-contrast and light palettes have their WCAG ratios **computed**, not asserted |
| `test_window_surface.py` | 10 | nothing | The three-file split: every `self.X` resolves, no stub survives, the surface the UI suites drive is intact, neither mixin shadows the other |
| `test_session_races.py` | 23 | nothing | Regression to recovery, close-session racing a live pass, panic at every lifecycle point, and no stale UI crossing a session boundary |
| `test_reverification.py` | 17 | nothing | What counts as a control that stopped holding, and the worker's threading contract |
| `test_disposable_overwrite.py` | 6 | nothing | The overwrite walker: what it covers, what it skips, and that skips are counted |
| `test_integrity.py` | 16 | nothing | The file manifest: drift detection, and that an unreadable file is UNKNOWN rather than a pass |
| `test_panic_and_account.py` | 17 | nothing | Process attribution by creation time, termination reporting, and the account-settings verb |
| `test_persistent_profile.py` | 13 | firewall policy | Settings survive consecutive launches; the profile is kept and stays usable |
| `test_end_to_end.py` | 10 | firewall policy | A real disposable session, real browser, real rules: router blocked, internet reachable, profile destroyed |
| `test_network_regression.py` | 10 | firewall policy | Rule scope, and the browser's own token failing to alter its rules |
| `test_localhost_surface.py` | 18 | firewall policy | The 19-path loopback matrix, and that bruhswer's claims match what was measured |
| `test_user_path.py` | 19 | firewall policy | The full user journey including a **real download** landing in quarantine |
| `test_browser_ui.py` | 31 | firewall policy | Window, hosting, **that the hosted window actually paints**, address bar, tabs, panels, session lifecycle |

```powershell
python tests\run_all.py            # everything, one verdict
python tests\test_security.py      # the CI-safe subset, no browser needed
```

Suites needing firewall policy report **SKIPPED** rather than passing quietly. A suite
that silently does nothing is worse than one that fails, so `run_all.py` exits non-zero
on failure and reports a distinct code when anything was skipped.

---

## Static security tests

`test_security.py` parses the source with `ast` rather than grepping it. That is
deliberate: the first version of the `shell=True` check failed on the *sentence in a
docstring promising `shell=True` is never used*, and a text search cannot tell
`subprocess.run(argv)` from `subprocess.run("del *")`.

Enforced invariants:

- no `eval`, `exec`, `compile`, `__import__`, `os.system`, `os.popen`, `pickle`
- no `shell=True`, anywhere
- no `subprocess` call whose first argument is a string or an f-string
- every `subprocess` call passes `creationflags` (no console windows flashing)
- no generic execution verb (`execute_command`, `run_shell`, ...)
- **no listener**: no import of `socket`, `socketserver`, `http.server`, `asyncio`,
  `ssl`, `flask`, `fastapi`, `aiohttp`, ...; no `listen`, `create_server`,
  `CreateNamedPipe`; no socket-shaped `bind`
- no remote-debugging flag can reach the browser
- no reserved IPC surface in config
- quarantine paths cannot escape their root
- session ids validated before any deletion

Each of these corresponds to a claim made elsewhere in the documentation. If a claim
has no test, it should not be a claim.

---

## What the tests are measured against

Not mocks. The integration suites use:

- the **real** `msedge.exe` the firewall rule names, so the rule applies identically
- the **real** Windows Firewall, on the real host
- the **real** default gateway, discovered at run time - never hardcoded, because a
  hardcoded gateway made this suite "pass" while probing an address that did not exist
- **real** local services for the loopback matrix, observed **server-side**: a request
  that arrives proves reachability regardless of what CORS does to the response

Edge's exit code is never used as a signal. It returns 0 while rendering an error page,
so verdicts come from the DOM or from server-side observation.

---

## What automated tests did not catch

This is the most useful section for anyone assessing the project's testing.

The suite passed 114 assertions while the browser was **unusable**. Three defects were
found only by running it as a person:

| Defect | Why no test saw it |
|---|---|
| **You could not type in it.** Reparented windows have separate input queues; keystrokes went nowhere | Tests drive the UI programmatically. They never *typed* |
| **Startup flashed a stream of console windows**, one per PowerShell query | Tests never *watched the screen* |
| **The page rendered at the wrong scale.** Tk is DPI-unaware, Edge is per-monitor aware | Same |

And later, in this same pass:

| Defect | Found by |
|---|---|
| **Edge signs disposable profiles into the Microsoft account** and syncs favourites | Taking a screenshot for the README and reading the banner |
| **`.gitignore` would have published a repo missing `quarantine.py`** | Running `git check-ignore` over the real file list. Two model reviews read the file and called it clean |

And again in 0.9.1, which is the clearest example yet:

| Defect | Why no test saw it |
|---|---|
| **The six status lights rendered behind the taskbar.** The entire honest-verdict display was off screen on a 1080p monitor | No test knows where the window is relative to the desktop |
| **A completely blank browser passed every assertion.** The suite proved Edge's window was *parented*; nothing proved anything was *drawn* in it | "Hosted" was being read as "working" |

The second one is now covered. `test_browser_ui.py` samples the hosted window's client
area through GDI and fails if it finds fewer than 8 distinct colours - a blank surface
is one or two, a real page is over a thousand. It was validated by confirming it reads
~1,400 colours on a working build.

**It has not been validated against a genuinely blank one**, because the blank state has
never been reproduced on demand. It is a guard against a failure that was seen once and
is not understood, not a regression test for a known defect.

The principle this project takes from that:

> **Automated evidence is not the same as use.** A green suite means the things you
> thought to check are still true.

The response was not "write more unit tests". It was
`tools/real_world_walkthrough.py`, which drives the actual GUI: builds the window,
waits for Edge to be hosted, opens every panel, navigates, exercises the disposable
download confirmation **including its cancel path**, and verifies destruction. **19 OK,
0 problems.** It is run before a release, and it is the check that matters for anything
touching `ui/`.

---

## Regression discipline

Every accepted security finding becomes a test **named after the defect**, so it cannot
come back silently. Examples:

| Test | The defect it pins |
|---|---|
| `test_destroy_removes_the_sessions_quarantine` | Disposable sessions left every download on disk forever |
| `test_sweep_removes_quarantine_orphaned_by_a_crash` | The crash path left them too |
| `test_sweep_refuses_to_delete_through_a_junction` | Recursive delete could be redirected by a reparse point |
| `test_persistent_quarantine_is_never_swept` | The fix must not destroy persistent downloads |
| `test_no_reserved_ipc_surface_remains_in_config` | A control channel that was never built |
| `TestNoLocalListener` | The central "bruhswer adds no attack surface" claim |
| Section D of `test_localhost_surface.py` | The UI describing loopback as anything but NOT ENFORCEABLE |

That last one is the unusual one: it asserts that **the product's own claims match what
was just measured**. If a future change painted localhost green, the build fails - not
because the platform changed, but because the software would then be lying.

---

## Continuous integration

CI runs the subset a GitHub runner can genuinely perform, and
[says so explicitly](../.github/workflows/ci.yml):

| Runs in CI | Does not run in CI |
|---|---|
| Unit tests + AST security scans, on 3.11 / 3.12 / 3.13 | Firewall enforcement |
| Every module imports cleanly | Browser tamper resistance |
| Entry points survive a redirected stdout | The localhost matrix |
| Repository hygiene: secrets, personal data, placeholders | Download quarantine with a real browser |
| Every relative documentation link resolves | Host Guard remediation and rollback |
| Ruff lint (dead imports, bug shapes - **not** a security check) | Renderer sandbox measurement |
| Licence integrity | Installer install / uninstall on a real machine |
| The installer script compiles | |
| CodeQL (python + actions), no open alerts | |

A dedicated job exists purely to **print what CI does not cover**, so a green tick
cannot be mistaken for full security coverage. Reporting coverage a runner cannot
perform would be a false claim, and this project treats those as vulnerabilities.

---

## Running it yourself

Environment setup, teardown, and what is already known:
[`SECURITY-TESTING.md`](SECURITY-TESTING.md).
