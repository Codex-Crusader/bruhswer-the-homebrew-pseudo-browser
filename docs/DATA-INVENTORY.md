# Data inventory and encryption decisions

Everything bruhswer writes to disk, why it exists, who can read it, and what - if
anything - protects it.

Measured on Windows 11, not assumed. ACLs below are real `icacls` output from a live
installation, and the read/write probes are the ones `BrowserGuard` runs at every
launch.

---

## 1. Where everything lives

Every path bruhswer writes is under a single root:

```
%LOCALAPPDATA%\BRUHWSER\
├── profiles\
│   ├── persistent\          the kept browser profile
│   └── disposable\<id>\     one folder per disposable session
├── quarantine\
│   ├── persistent000000\    downloads from persistent sessions
│   └── <id>\                downloads from a disposable session
├── logs\                    bruhswer's own security log
└── state\                   Host Guard rollback record
```

`config.ensure_dirs()` creates these and nothing else. A test
(`test_security.py::TestConfigSanity::test_all_paths_are_under_one_root`) fails if a
new path escapes this root.

**The application** creates no registry key, no `ProgramData` folder, no scheduled
task, no service, and no startup entry.

**The installer does create two things outside that root**, and saying "nothing exists
outside `%LOCALAPPDATA%\BRUHWSER`" without mentioning them would be inaccurate:

| Created by the installer | Where | Removed by uninstall? |
|---|---|---|
| Uninstall registration | `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\` | Yes |
| Start Menu / Desktop shortcuts (if chosen) | The user's own shortcut folders | Yes |
| Program files | `%LOCALAPPDATA%\Programs\bruhswer` | Yes |

These are the ordinary registrations any per-user Windows application makes so that it
appears in "Installed apps" and can be removed from there. There is still no service,
no scheduled task, no startup entry and no background updater.

---

## 2. The inventory

| Item | Location | Purpose | Sensitive? | Owner | ACL | Encrypted at rest | Retention | Deletion |
|---|---|---|---|---|---|---|---|---|
| **Persistent profile** | `profiles\persistent\` | Cookies, history, cache, site data for the kept session | **Yes - high** | User | `SYSTEM:(OI)(CI)F` + `<user>:(OI)(CI)F`, **inheritance removed** | No (see §4) | Until the user deletes it | `--uninstall`, or delete the folder |
| **Disposable profile** | `profiles\disposable\<id>\` | Same, for one throwaway session | **Yes - high** | User | Inherits the hardened parent | No | Destroyed when the session closes | Automatic on close; swept at next start after a crash |
| **Persistent quarantine** | `quarantine\persistent000000\` | Files downloaded in persistent sessions | **Yes - potentially hostile** | User | Inherited: `SYSTEM`, `Administrators`, `<user>` | No | Until the user exports or deletes | Quarantine panel, or `--uninstall` |
| **Disposable quarantine** | `quarantine\<id>\` | Files downloaded in a disposable session | **Yes - potentially hostile** | User | As above | No | **Destroyed with the session** | Automatic on close, after an explicit warning; swept if orphaned by a crash |
| **Security log** | `logs\bruhswer.log` (+3 rotations, 512 KB each) | Evidence: timestamps, check IDs, verdicts, rule names, PIDs | **Low** - see §3 | User | Inherited | No | Rotating, max ~2 MB total | `--uninstall` |
| **Host Guard rollback** | `state\hostguard-rollback.json` | The host's *previous* firewall/SMB settings, so a change can be undone | **Low** | User | Inherited | No | Kept deliberately, even by `--uninstall` | Manual, after running `-Action revert` |
| **Firewall rules** | Windows Firewall (not a file) | Block the browser reaching router and LAN | No | System | Requires Administrator to change | n/a | Until removed | `bruhswer-netpolicy.ps1 -Action remove` |

### Things bruhswer does **not** store

Scope matters here, and the distinction is not a quibble: **bruhswer's own code**
stores no credentials, tokens, API keys, passwords, encryption keys, certificates with
private material, account identifiers or device identifiers. There is no telemetry,
anywhere, ever - bruhswer contains no network client at all.

**The Edge profile bruhswer manages is a different matter, and it is not empty.** A
persistent session is a real browser profile: if you sign in to a site, it holds that
site's cookies; if you let Edge save a password, it holds that too. That is what a
persistent profile *is*, and the reason disposable mode exists.

So the accurate statement is: *bruhswer does not collect or store your secrets, but
the browser profile it looks after can contain any secret your browsing puts there.*
Those live inside the persistent profile, protected by its ACL and by Chromium's own
DPAPI encryption for the sensitive fields. Disposable sessions never accumulate them,
because the whole profile is destroyed on close.

Browser credentials, if the user saves any, are stored by **Edge** inside the profile
and protected by **Edge's** mechanisms (DPAPI). bruhswer neither reads nor manages
them. It deliberately does not disable Edge's password manager, because Chromium
reverts that preference when set from outside - documented in `privacy_guard.REJECTED`
rather than claimed as working.

---

## 3. What the log contains, and what it must never contain

Logged: timestamps, event names, check IDs, verdicts, firewall rule names, process
IDs, error class names, counts.

Never logged: URLs, page content, cookies, tokens, passwords, form data, download
contents, browsing history, or filenames from downloads.

This is enforced twice. Callers are not supposed to pass such values, **and** the
formatter redacts anything matching a URL, an email address, or a
`password=`/`token=`/`secret=`/`api_key=` pattern before it is written. A logger that
leaks is worse than no logger, and "the caller should not have done that" is not a
control.

---

## 4. Encryption at rest - the decision, and the reasoning

**bruhswer adds no encryption of its own. This is a deliberate decision, not an
omission.**

The brief for this pass is explicit: implement encryption only where there is a defined
security benefit, do not write custom cryptography, do not invent a password manager,
do not hardcode keys, do not store keys beside ciphertext. Applying that honestly to
each item gives the same answer every time.

### The three questions, per item

For every sensitive item the question is: does Windows already protect it, does Edge
already protect it, or does bruhswer need to add something?

| Item | Windows already? | Edge already? | Does bruhswer need to add encryption? |
|---|---|---|---|
| Persistent profile | Yes - per-user ACL, plus BitLocker if enabled | Yes - DPAPI for cookies and saved credentials | **No** |
| Disposable profile | Yes | Yes | **No** - and it is deleted anyway |
| Quarantine | Yes - per-user ACL | n/a | **No** |
| Log | Yes | n/a | **No** - it holds nothing sensitive by construction (§3) |
| Host Guard rollback | Yes | n/a | **No** - it holds prior firewall settings, not secrets |

### Why bruhswer does not add it - stated as a trade-off, not as "it would do nothing"

An earlier draft of this document claimed that application-level encryption "would
defend against nothing" and that against offline disk theft "the key would be on the
same disk anyway". **That was wrong, and an independent review caught it.** It is
corrected here rather than quietly deleted, because getting a security claim wrong in
the direction of *dismissing* a protection is the same class of error as overstating
one.

The accurate position:

**Where DPAPI genuinely would help.** A DPAPI user master key is protected by material
derived from the user's Windows credentials, not merely stored beside the data. An
attacker who steals a powered-off, un-BitLockered disk and does **not** know the
account password therefore cannot trivially read DPAPI-protected blobs. That is a
materially different outcome from plaintext, and it is dishonest to pretend otherwise.
(It is not absolute - an offline attacker can attempt to crack the account password,
and a weak password brings the whole thing down - but "harder, and sometimes decisive"
is not "nothing".)

**Where it genuinely would not help.** Against a compromised browser process or
same-user malware, DPAPI adds nothing at all: those run with the user's token, so the
data is decrypted for them on request. This half of the original claim stands.

**Why bruhswer still does not do it.** Not because encryption is worthless, but
because of what the sensitive data actually *is*:

1. **The valuable data is Edge's live profile**, and Edge must be able to read and
   write it continuously while running. bruhswer cannot wrap a live Chromium profile
   in its own encryption layer without breaking the browser. Encrypting it at rest
   between sessions would leave it plaintext during every session - which is when the
   machine is actually in use and most likely to be attacked.
2. **Edge already does the part that matters.** Cookies and saved credentials inside
   the profile are already DPAPI-protected by Chromium. Adding a second, bruhswer-managed
   layer over the top duplicates that for the sensitive fields and adds nothing for the
   rest.
3. **The right control for full-disk theft is full-disk encryption.** BitLocker covers
   every file, including the ones bruhswer does not manage, without a bespoke
   key-management path that could lose the user's data after a Windows account change.

So the honest summary is: **this is a trade-off, decided against**, not a protection
that would have been useless. If you are worried about someone stealing the disk, turn
BitLocker on - that is the control that actually addresses it.

### What actually protects this data

| Threat | Protected? | By what |
|---|---|---|
| **Physical disk theft** | **Yes, if BitLocker is on. Otherwise partly.** | Windows full-disk encryption. bruhswer reports Defender status but does **not** claim BitLocker; check it yourself with `manage-bde -status`. Without BitLocker, most of the profile is readable offline - though Edge's own DPAPI-protected fields (cookies, saved credentials) still resist an attacker who does not know the account password. |
| **Offline copying of the profile** | **Yes, if BitLocker is on. Otherwise partly.** | Same as above. This row previously said application-level encryption could not help here. That was wrong - see the corrected reasoning below. |
| **Another Windows user on the same PC** | **Yes** | `%LOCALAPPDATA%` is per-user; the persistent profile additionally has inheritance removed and is granted only to `SYSTEM` and the owning user. Verified by real `icacls` readback plus a write/read probe at every launch. |
| **A local Administrator** | **No** | An administrator can take ownership of any file. This is Windows' model, not a bruhswer weakness, and no user-mode encryption changes it. |
| **Same-user malicious process** | **No** | It runs with the user's token and can read anything the user can. Stated plainly: **encryption would not change this**, because the data must be decryptable by that very token. |
| **Compromised browser process** | **No** | Same as above. Stage 4 gate A4 measured that the browser process runs on an ordinary user token. |
| **A malicious website** | **Yes, for other sites' data** | Not by encryption - by Edge's origin isolation, and by bruhswer giving the session its own profile so page data cannot reach the user's ordinary browsing profile. |

**The honest one-line summary, and the one that belongs in user-facing text:**

> bruhswer's data is protected by Windows file permissions, and by BitLocker if you
> have it on. It is not protected against anything already running as you.

---

## 5. Deletion behaviour

Deletion is **verified**, never assumed. `shutil.rmtree` returning without raising is
not evidence - the code re-checks that the path is gone and reports the count of
anything left behind. Files locked by a still-running browser process are the common
real cause, and that is reported as an incomplete destruction rather than a success.

What deletion **cannot** promise, and what the UI says so:

- files the user deliberately exported from quarantine
- anything the site already sent to its own servers
- Windows-level artefacts outside the profile folder
- forensic recovery of the underlying disk blocks

`--uninstall` removes profiles, quarantine and logs after a typed `DELETE`
confirmation, asks a second time if quarantine is not empty, and deliberately **keeps**
the Host Guard rollback record - deleting that would strand any host change bruhswer
made with no way to undo it.
