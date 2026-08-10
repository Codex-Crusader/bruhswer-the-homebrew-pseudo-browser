# Stage 7 - Host Guard real-world validation

**Date:** 2026-08-09 · **Result: `HOST GUARD REMEDIATION - VERIFIED`**

Closes the one Stage 6 acceptance criterion that was left open: *"HostGuard remediation must be verified on the real host and rollback must also be verified."*

`STAGE-6-RESULTS.md` §10 recorded that criterion as **"Implemented with verify + verified rollback; not exercised on this host."** That statement was accurate when written and is **not** rewritten here - this document records what happened when it finally was exercised.

---

## 1. Baseline (Step 1)

Taken before anything was touched.

```
run_all.py:  unit 34 · persistent 13 · end-to-end 10 · network regression 10 · user path 19
             86 assertions, 0 failures

Network      CampusWiFi   category=Public   ipv4=Internet   ipv6=NoTraffic
Firewall     Domain / Private / Public  all enabled
bruhswer     BRUHWSER-edge-deny-ipv4-private  enabled=True  Block
             BRUHWSER-edge-deny-ipv6-local    enabled=True  Block
File+Printer 17 of 17 rules applying to Public are ENABLED
             15 with profile "Private, Public"   2 with profile "Any" (LLMNR)
SMB          SMB1=False  SMB2=True  RequireSecuritySignature=False  EnableSecuritySignature=False
Defender     RTP=True  Tamper=True  CFA=1        VBS=2  SecurityServices=2
Rollback     hostguard-rollback.json ABSENT - bruhswer had never changed this host
```

---

## 2. Port 30002 (Step 2) - identified, not touched

```
socket     0.0.0.0:30002  LISTEN  pid 6048
process    ToolkitService (Windows service "Toolkit Service")
runs as    LocalSystem      StartMode Auto      State Running
path       C:\Program Files (x86)\Toolkit\Service\ToolkitService.exe
product    ToolkitService 1.0.0.2
signature  Valid            signer CN=SEAGATE TECHNOLOGY LLC
```

**Known application:** Seagate Toolkit, the backup/management software that ships with Seagate external drives. Signed by Seagate and valid.

**Is it reachable from the Public network?** Two enabled inbound ALLOW rules named `Toolkit` exist on the Public profile - but they name **`toolkit.exe`**, and the listener is **`ToolkitService.exe`**. Different executables.

```
Public profile Enabled              True
Public profile DefaultInboundAction NotConfigured  (=> Block)
Rules naming ToolkitService.exe or port 30002 on Public:  NONE
```

**Assessment `[INFERRED]`:** with Public inbound defaulting to Block and no rule covering that program or port, inbound connections to 30002 are most likely dropped at the firewall despite the socket binding `0.0.0.0`. **This was not proven** - proving it needs a second device on the network, which is out of scope and would require the LAN probing this project forbids.

**Nothing about this service was changed.** Not stopped, not disabled, not reconfigured, and its firewall rules were left alone.

This also refines Host Guard's own reporting: the "unexpected listening services" check flags a socket **bound** to all interfaces. That is not the same as **reachable**. The check remains a delta against an observed baseline, exactly as `BRUHWSER-SECURITY.md` §11 residual risk 8 says.

---

## 3. A design defect found before applying anything

The baseline exposed a real fault in the Stage 6 remediation.

**What Stage 6 did:** `Disable-NetFirewallRule` on every File and Printer Sharing rule applying to Public, while telling the user *"Home and work networks are NOT affected. Sharing still works there."*

**Why that was wrong:** those rules are **shared across profiles**. On this machine 15 carried `Private, Public` and 2 carried `Any`. Disabling them switches them off **everywhere** - so file sharing on the user's home network would have broken, and the reassuring sentence would have been false.

**The fix:** remove **only** `Public` from each rule's profile list and keep every other profile it had. That is the smallest change that does what the script actually promised.

```
15 rules   Private, Public  ->  Private
 2 rules   Any              ->  Domain,Private
```

Verification was strengthened to match: after applying, each rule is re-read and must satisfy **both** conditions - `Public` is gone **and** every other original profile is still present. Either failing triggers `REMEDIATION = FAILED` and an automatic rollback.

---

## 4. A second defect, found between the two remediations

After `fix-sharing` succeeded, the rollback record was inspected before running `fix-smb`:

```
SharingProfiles entries : 17
SmbRequireSigning       : <null - NOT recorded>
```

`Save-State` refused to write at all when a record already existed. That rule is correct for a field **already captured** - re-capturing would record *our own change* as the "original". But it silently dropped every **other** field. Running `fix-sharing` then `fix-smb` would have left the SMB original value unrecorded, and `-Action revert` would have skipped restoring SMB while still reporting `ROLLBACK = OK`.

**An incomplete rollback that reports success is worse than one that fails loudly.**

**The fix:** "first capture wins" now applies **per field**, not per file. Confirmed working - after `fix-smb` the record held both:

```
SharingProfiles: 17 entries   SmbRequireSigning: False   (the true original)
```

---

## 5. The plan (Step 3) and approval (Step 4)

`bruhswer-hostguard.ps1 -Action plan` was added - read-only, unelevated, changes nothing - and printed the full rule-by-rule current → target table, why each change matters, how it would be verified, and how it would be rolled back.

The user approved **both** changes explicitly. The stage brief itself was **not** treated as approval.

---

## 6. Apply and verify (Step 5)

```
2026-08-09 13:53:55  fix-sharing    OK        removed Public from 17 rule(s)
2026-08-09 13:55:28  fix-smb        OK        RequireSecuritySignature=true
```

**fix-sharing**

```
[1/7 CAPTURE] previous state recorded    captured: SharingProfiles
[4/7 APPLY  ] removing Public from each rule
[5/7 VERIFY ] re-reading every rule
    enabled sharing rules still applying to Public: 0
    verification problems: 0
REMEDIATION = VERIFIED
```

**fix-smb**

```
[1/7 CAPTURE] captured: SmbRequireSigning
[4/7 APPLY  ] setting RequireSecuritySignature
[5/7 VERIFY ] SMB signing required: True
REMEDIATION = VERIFIED
```

Neither verdict came from an exit code. Both came from re-reading the state afterwards.

---

## 7. Security effect (Step 6)

```
File and Printer Sharing
  enabled applying to PUBLIC  :  0    (was 17)
  enabled applying to PRIVATE : 17    (home sharing preserved - the whole point of the fix)

  File and Printer Sharing (SMB-In)         enabled=True  profile=Private / Domain
  File and Printer Sharing (NB-Session-In)  enabled=True  profile=Private / Domain
  File and Printer Sharing (LLMNR-UDP-In)   enabled=True  profile=Domain, Private

SMB   RequireSecuritySignature True (was False)   SMB1 False, SMB2 True (unchanged)
```

**Unchanged, as promised:**

```
Network category      Public                       (unchanged)
Firewall profiles     3/3 enabled                  (unchanged)
bruhswer rules        2, both enabled, Block       (untouched)
Toolkit rules         enabled, profile=Public      (untouched)
Toolkit service       Running                      (untouched)
Defender RTP/Tamper   True / True     CFA 1        (untouched)
VBS                   2                            (untouched)
QEMU                  present                      (untouched)
HypervisorPlatform    enabled                      (untouched)
```

**bruhswer itself, re-run against the hardened host:**

```
PASS  unit / static analysis          PASS  network regression (SS12/SS13)
PASS  persistent profile              PASS  full user path (SS30)
PASS  end-to-end session
86 assertions, 0 failures
```

Browser networking, LAN blocking, localhost honesty, internet connectivity and download quarantine all still behave exactly as before. **The host hardening did not affect the browser policy, and the browser policy did not affect the host hardening.**

No LAN scanning was performed. Only the predetermined gateway address and `1.1.1.1` were probed.

---

## 8. Rollback (Step 7) - exercised and independently verified

```
2026-08-09 14:00:51  revert  OK  original state restored and verified
```

The script's own report:

```
restoring the original profile on 17 rule(s)
VERIFY: 17 of 17 rule(s) restored exactly
restoring SMB signing to False
VERIFY: SMB signing required = False
rollback record removed.
ROLLBACK = OK
```

**Independently re-measured afterwards, not taken from the script's word:**

| | Baseline | After rollback |
|---|---|---|
| rules `Private, Public` | 15 | **15** |
| rules all-three-profiles | 2 (shown as `Any`) | **2** (shown as `Domain, Private, Public`) |
| total enabled applying to Public | 17 | **17** |
| `RequireSecuritySignature` | False | **False** |
| `EnableSecuritySignature` | False | **False** |
| SMB1 / SMB2 | False / True | **False / True** |
| rollback record | absent | **absent** |

**One honest nuance:** the two LLMNR rules read `Any` at baseline and `Domain, Private, Public` after rollback. `Any` is Windows' shorthand for exactly those three profiles, so the **effective** state is identical - but the stored string is normalised, so this is *equivalent*, not *byte-identical*. Recorded rather than glossed over.

**Full cycle proven:**

```
original state -> remediation -> VERIFIED hardened -> rollback -> VERIFIED original
```

---

## 9. Final state

The user approved the hardening, so it was re-applied after the rollback test, and re-verified:

```
enabled applying to PUBLIC   : 0
enabled applying to PRIVATE  : 17
SMB RequireSecuritySignature : True
rollback record              : present (SharingProfiles 17 entries, SmbRequireSigning False)
```

**The host is hardened, and one command undoes it:**

```powershell
powershell -ExecutionPolicy Bypass -File tools\bruhswer-hostguard.ps1 -Action revert
```

---

## 10. Limitations and residual risk

1. **Port 30002's LAN reachability is `[INFERRED]`, not measured.** The firewall policy analysis says it should be dropped inbound on Public; proving it needs a second device.
2. **"Listening on all interfaces" ≠ "reachable".** Host Guard reports the socket binding, which is what it can see locally. It remains a delta against an observed baseline, not a service audit.
3. **The Toolkit `toolkit.exe` ALLOW rules on Public were left in place.** They allow that executable inbound on **any TCP and UDP port** while on a Public network. They are not part of the File and Printer Sharing group and were outside the approved scope, so they were not touched. **This is a real remaining exposure and is called out rather than quietly fixed.**
4. **SMB signing may break very old clients** connecting to shares on this PC. Reversible.
5. **`Any` normalises to `Domain, Private, Public` on rollback** - equivalent, not string-identical.
6. **Rollback was tested once, from a state this script created.** It has not been tested against a host modified by something else in between.
7. Everything Stage 6 already listed as residual still applies - localhost is still `NOT ENFORCEABLE`, DNS is still `UNKNOWN`, VPN is still `UNSUPPORTED`.

---

## 11. Result

```
HOST GUARD REMEDIATION - VERIFIED
```

Both remediations were applied to the real host, verified by re-reading actual state rather than trusting an exit code, rolled back, and independently confirmed to have restored the original state. Two defects were found and fixed during the process - one that would have broken home file sharing, one that would have produced a silently incomplete rollback.
