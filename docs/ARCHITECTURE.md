# Architecture

**Status: current.** This describes the code that ships in v0.9.0.

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
| `browser_window.py` | The window: layout, hosting Edge, status lights, the session lifecycle as the user experiences it |
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

---

## What happens at launch

```
1. ensure_dirs()            everything under %LOCALAPPDATA%\BRUHWSER, nowhere else
2. sweep_orphans()          remove disposable profiles and quarantines left by a crash
3. DPI awareness            before any window exists, or Edge renders at the wrong scale
4. Controller.verify()      every guard runs; ~29 checks
        |
        +-- any critical check not PASS?  --> BRUH. NO. No browser. No override.
        |
5. session_manager.create() persistent, or a fresh disposable profile
6. browser_guard.harden()   ACLs, then a real write/read probe to prove usability
7. privacy_guard.apply()    preferences written into the profile
8. verify_all() again       including the download directory, now that it is set
9. edge.launch(argv)        explicit argv, shell=False, no dangerous flags
10. embed.host_window()     Edge's window reparented into the frame, input queues joined
```

Steps 4 and 8 are the reason the app exists. Everything else is plumbing around them.

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
