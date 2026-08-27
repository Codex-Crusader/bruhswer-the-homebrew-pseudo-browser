# Architecture

**Status: current.** This describes the code that ships in v0.11.0.

Earlier designs (WSL2, Hyper-V, QEMU) were built, measured, and rejected. They live in
[`research/`](research/) as evidence and are not guidance. If you want the story of how
the design got here, read [`PROJECT-HISTORY.md`](PROJECT-HISTORY.md).

---

## The shape of it

bruhswer is a single unelevated Python process that launches Microsoft Edge, hosts
Edge's window inside its own frame, and verifies a fixed set of security properties
before it will let the browser start.

```
                      +---------------------------+
                      |         UI (tkinter)      |
                      |  browser_window.py        |
                      |  panels/  dialogs/        |
                      +-------------+-------------+
                                    |  direct method calls
                                    |  (one process, no IPC)
                      +-------------v-------------+
                      |        Controller         |
                      |  owns the session         |
                      |  lifecycle, closed verbs  |
                      +-------------+-------------+
                                    |
        +--------+--------+---------+--------+---------+---------+
        |        |        |         |        |         |         |
   +----v---+ +--v-----+ +v------+ +v-----+ +v------+ +v--------+
   | browser| |security| |network| |privacy| | host  | |sessions |
   |  edge  | |verifier| | guard | | guard | | guard | |downloads|
   |  embed | | browser|  ...                                    |
   +----+---+ +---+----+ +---+---+ +--+----+ +--+----+ +----+----+
        |         |          |        |         |           |
        +---------+----------+--------+---------+-----------+
                                    |
                      +-------------v-------------+
                      |   sysquery.py             |
                      |   the ONLY place an       |
                      |   external program runs   |
                      +-------------+-------------+
                                    |
                      +-------------v-------------+
                      |   Windows + Microsoft Edge |
                      +---------------------------+
```

**There is no IPC.** The UI and the Controller are objects in the same process and call
each other directly. Nothing is serialised, parsed, authenticated or authorised,
so none of that can be got wrong. This is deliberate: Stage 4 measured that a
compromised browser process can reach any local endpoint and that no firewall rule
stops it, so any control channel bruhswer opened would be reachable by the exact thing
it exists to contain. A test parses the source and fails the build if anything ever
imports `socket`, `http.server` or `asyncio`, calls `listen`, or opens a named pipe.

---

## The layers

### UI - `app/ui/`

Presentation and interaction only. It never re-implements a check, never decides
whether launch is allowed, and never manages a session itself.

| File | Responsibility |
|---|---|
| `browser_window.py` | Layout, menu actions, panel launchers. Assembles the two mixins below into one `BrowserWindow` class |
| `window_shell.py` | Declared, never instantiated. The state and cross-mixin methods `session_lifecycle.py` and `verification_ui.py` both call on `self`, so a genuine typo in either is not lost in hundreds of otherwise-unresolvable references |
| `session_lifecycle.py` | Startup, window hosting (the `SetParent` handshake), teardown - the session lifecycle as the user experiences it |
| `verification_ui.py` | Status lights, regression warnings, the account banner, the panic indicator, and the re-verification worker's lifecycle |
| `verify_worker.py` | A background thread that re-runs every check once a minute for as long as a session is open, so the lights describe the live system rather than a launch-time snapshot. Publishes results through a queue; never touches a Tk object itself |
| `panic_key.py` | Registers the global panic hotkey on its own thread and reports whether it is actually armed |
| `panels/` | One module per panel - security, network, privacy, host, quarantine. Each renders a guard's output; none computes it |
| `dialogs.py` | Modal confirmations, e.g. warning before disposable downloads are destroyed |
| `app_ui.py` | The standalone control panel (`--panel`), usable without a browser |

A status light is green only if a check returned `PASS`. `LOCALHOST` is permanently
amber and reads `NOT ENFORCEABLE`.

### Controller - `app/controller/controller.py`

Owns the session lifecycle and holds no browser-supplied state.

It exposes a **closed set of verbs** - `verify`, `status`, `start`, `stop`, `navigate`,
`new_tab`, `export_request`. There is no `execute`, no `run_shell`, no dispatcher that
maps a string to code. The attack surface is small by construction rather than by
filtering, because filtering is a thing you can get wrong.

### The guards - one concern each

| Module | Question it answers | Notable property |
|---|---|---|
| `browser/edge.py` | Is this the browser we expect, and how do we start it? | Fixed absolute paths, Authenticode checked every launch, argv list never a string, `DANGEROUS_FLAGS` refused rather than filtered |
| `browser/embed.py` | How do we host Edge's window? | Win32 reparenting, DPI awareness, shared input queues |
| `browser/tokens.py` | What are the renderer processes actually running as? | Reads live process tokens, so the sandbox claim is measured not asserted |
| `browser/urls.py` | Is this address-bar text safe to hand over? | Returns an `http(s)` URL or refuses. `file:`, `javascript:`, `data:`, UNC paths and drive letters are excluded by construction |
| `security/verifier.py` | May the browser launch? | **The single decision point.** Fail-closed: a critical check must PASS, and UNKNOWN blocks |
| `security/browser_guard.py` | Is the profile confined and the command line clean? | ACLs applied with `icacls`, then proved with a real read/write probe |
| `network/network_guard.py` | Is the firewall policy actually in place? | Verifies only. Applying needs Administrator and lives in a separate one-shot |
| `privacy/privacy_guard.py` | Did the privacy settings stick? | Writes preferences, then **reads them back**. Chromium reverts some, and that is reported |
| `host/host_guard.py` | What can other devices on this network reach on this PC? | Detects and explains. Never changes the host by itself |
| `sessions/session_manager.py` | Persistent or disposable, and is it really gone? | Deletion is verified, confined to its root, and refuses reparse points |
| `downloads/quarantine.py` | Where do downloads land, and how do they get out? | Filenames rebuilt from scratch; export destination comes only from the user's own folder picker |

### `sysquery.py` - the only external-program boundary

Every PowerShell and `icacls` invocation in the application goes through here.

- `subprocess` is always given an **explicit argument list**. `shell=True` appears
  nowhere, enforced by an AST test.
- The executable is a fixed absolute path from `config.py`, never resolved via `PATH`.
- Every script is a **module-level constant**. The only values ever interpolated are
  bruhswer's own constants or integers it validated.
- Nothing here modifies system state. Read-only queries only.

There is deliberately no generic `run(command)` function, so no caller can ask this
module to execute something arbitrary.

### `config.py` - every constant, no logic

Paths, brand colours, Edge candidate locations, blocked address ranges, browser flags,
the dangerous-flag list. Nothing in it is derived from a URL, a filename, a header, a
downloaded file, or any other browser-controlled input.

### `verdict.py` - the vocabulary

`Check`, `Verdict`, and the rule that `UNKNOWN` is not `PASS`. A check marked
`enforceable=False` renders as `NOT ENFORCEABLE`, never green, and never blocks launch
- because blocking on a platform limitation would just mean the app never starts.

Every `Check` also declares an `EvidenceKind` - `LIVE` ("measured now"), `READ_BACK`
("configuration read back; enforcement not observed"), `HISTORICAL` ("earlier
measurement, not re-run now"), or the weakest, `INFERENCE` ("reasoned, not measured").
"The check passed" and "how bruhswer knows" are different claims, and a check that
forgets to declare its kind gets the weakest one by default rather than the strongest -
a test fails the build if any shipped check is left on that default. Where a `Check`
reports `UNKNOWN`, an `UnknownReason` says which of several different situations that
is - a query that failed, an artefact nobody could read, a property no measurement has
ever established - so "could not measure" and "measured, and it was fine" can never
collapse into the same result the way they once did
(`tests/test_overclaim_regressions.py` pins the specific defects this closed).

---

## What happens at launch

```
1. ensure_dirs()            everything under %LOCALAPPDATA%\BRUHWSER, nowhere else
2. sweep_orphans()          remove disposable profiles and quarantines left by a crash
3. DPI awareness            before any window exists, or Edge renders at the wrong scale
4. Controller.verify()      every guard runs; 31 checks
        |
        +-- any critical check not PASS?  --> BRUH. NO. No browser. No override.
        |
5. session_manager.create() persistent, or a fresh disposable profile
6. browser_guard.harden()   ACLs, then a real write/read probe to prove usability
7. privacy_guard.apply()    preferences written into the profile
8. verify_all() again       including the download directory, now that it is set
9. edge.launch(argv)        explicit argv, shell=False, no dangerous flags
10. embed.host_window()     Edge's window reparented into the frame, input queues joined
11. VerifyWorker.start()    re-verification begins: every check again, once a minute,
                            for as long as the session stays open
```

Steps 4 and 8 are the reason the app exists. Everything else is plumbing around them.
Step 11 exists because they are not the only moment a control can stop holding - a
firewall rule deleted by another admin tool, or an Edge update, does not wait for the
next launch to happen. The status lights describe step 11's latest pass, not step 4's or
step 8's, for as long as a session is open.

---

## The trusted computing base

If you are reviewing this and want to know what actually matters, read these and skip
the rest. A security decision made anywhere else is a bug.

| Module | Why it is in the TCB |
|---|---|
| `security/verifier.py` | The only thing that decides whether the browser may launch |
| `security/browser_guard.py` | Profile confinement, ACLs, command-line inspection |
| `network/network_guard.py` | Firewall policy verification |
| `sysquery.py` | The only place an external program is ever run |
| `browser/edge.py`, `browser/urls.py` | Launch argv construction, URL refusal |
| `sessions/session_manager.py` | Session destruction, reparse-point handling |
| `downloads/quarantine.py` | Quarantine paths and export |
| `config.py`, `verdict.py` | Constants, and the rule that UNKNOWN is not PASS |

**3,255 lines of the application's 8,716.** The remaining 5,461 are UI, window hosting,
orchestration and presentation. They can be wrong without a security property being
wrong, which is the point of keeping the split visible.

Not in the TCB, and deliberately so: everything under `ui/` (it renders verdicts, it
never computes one), `browser/embed.py` (Win32 window reparenting), `host/host_guard.py`
(advisory only, changes nothing by itself), and everything in `/tools` at the repository
root, which is research tooling that does not ship.

---

## Trust boundaries, and which ones are ours

```
hostile page  ->  renderer        Edge's sandbox. AppContainer, UNTRUSTED integrity.
                                  NOT bruhswer's boundary. Measured, not assumed.

renderer      ->  browser process Chromium's boundary. The broker runs on an ordinary
                                  user token and is NOT sandboxed. bruhswer does not
                                  claim to contain it.

browser       ->  bruhswer        OURS. No listener, no IPC, no browser-controlled
                                  value reaching a path, an argv element or a
                                  PowerShell string.

bruhswer      ->  Administrator   OURS. The app is unelevated. Privileged changes live
                                  in tools/*.ps1, run knowingly, with a confirmation
                                  word and a recorded rollback.
```

## What this architecture does not do

It is not a virtual machine and there is no hypervisor. It does not sandbox the browser
process. It cannot filter loopback, because Windows Firewall cannot. It runs as the
user, so it cannot defend against anything else running as the user.

Those are properties of the design, stated here so they are not mistaken for gaps.
See [`LIMITATIONS.md`](LIMITATIONS.md).
