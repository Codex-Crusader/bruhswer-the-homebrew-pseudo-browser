"""Measure the browser's actual process tokens, on THIS machine, right now.

WHY THIS EXISTS
    bruhswer used to report "Chromium renderer sandbox in use - AppContainer, untrusted
    integrity, no privileges" as a hardcoded PASS. That was measured once, on one
    machine, with one Edge build (Stage 4 gate A3) - and then asserted as fact for every
    user.

    It is not safe to assume. On that same machine, Chrome's renderers were restricted
    but NOT AppContainer - one mechanism short of Edge's. A different Edge version, a
    policy, or a future Chromium change could move that line, and bruhswer would keep
    showing a confident green light for a boundary that had quietly weakened.

    "A security indicator that lies is worse than no indicator" is this project's own
    rule. So the sandbox status is measured from the live process tree instead, and
    reported UNKNOWN when there is nothing running to measure.

Read-only. Opens tokens with the minimum access needed to read their properties, and
never touches a process it did not launch.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
from collections.abc import Sequence
from dataclasses import dataclass

from ..logging_setup import get_logger

_log = get_logger("tokens")

KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)

INVALID_HANDLE_VALUE = wt.HANDLE(-1).value
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008

TOKEN_PRIVILEGES = 3
TOKEN_INTEGRITY_LEVEL = 25
TOKEN_IS_APPCONTAINER = 29

INTEGRITY_NAMES = {0x0000: "UNTRUSTED", 0x1000: "LOW", 0x2000: "MEDIUM",
                   0x2100: "MEDIUM_PLUS", 0x3000: "HIGH", 0x4000: "SYSTEM"}

KERNEL32.OpenProcess.restype = wt.HANDLE
KERNEL32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
KERNEL32.CloseHandle.argtypes = [wt.HANDLE]
KERNEL32.CloseHandle.restype = wt.BOOL
ADVAPI32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
ADVAPI32.OpenProcessToken.restype = wt.BOOL
ADVAPI32.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                         wt.DWORD, ctypes.POINTER(wt.DWORD)]
ADVAPI32.GetTokenInformation.restype = wt.BOOL
ADVAPI32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
ADVAPI32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
ADVAPI32.GetSidSubAuthority.restype = ctypes.POINTER(wt.DWORD)
ADVAPI32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wt.DWORD]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]


class _TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", _SID_AND_ATTRIBUTES)]


@dataclass(frozen=True)
class TokenFacts:
    pid: int
    is_appcontainer: bool | None
    integrity: str | None
    privilege_count: int | None
    readable: bool


def _token_info(token: wt.HANDLE, info_class: int):
    """Return the ctypes BUFFER, never a copy of its bytes.

    TOKEN_MANDATORY_LABEL contains a POINTER to a SID that lives inside this buffer.
    An earlier version returned `buf.raw[:n]` - a plain bytes copy - and then cast that
    copy back to the struct. The pointer inside still referred to the original buffer,
    which Python had already freed, so reading the integrity level dereferenced freed
    memory and crashed the process with an access violation.

    Keeping the real buffer alive and casting THAT is the fix.
    """
    need = wt.DWORD(0)
    ADVAPI32.GetTokenInformation(token, info_class, None, 0, ctypes.byref(need))
    if not need.value:
        return None
    buf = ctypes.create_string_buffer(need.value)
    got = wt.DWORD(0)
    if not ADVAPI32.GetTokenInformation(token, info_class, buf, need,
                                        ctypes.byref(got)):
        return None
    return buf


def read(pid: int) -> TokenFacts:
    """Token properties for one process. Never raises."""
    handle = KERNEL32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle or handle == INVALID_HANDLE_VALUE:
        return TokenFacts(pid, None, None, None, readable=False)

    token = wt.HANDLE()
    try:
        if not ADVAPI32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
            return TokenFacts(pid, None, None, None, readable=False)

        is_ac: bool | None = None
        value = wt.DWORD(0)
        got = wt.DWORD(0)
        if ADVAPI32.GetTokenInformation(token, TOKEN_IS_APPCONTAINER,
                                        ctypes.byref(value), ctypes.sizeof(value),
                                        ctypes.byref(got)):
            is_ac = bool(value.value)

        integrity: str | None = None
        label_buf = _token_info(token, TOKEN_INTEGRITY_LEVEL)
        if label_buf is not None:
            # label_buf must stay referenced for as long as the SID pointer is used.
            label = ctypes.cast(label_buf,
                                ctypes.POINTER(_TOKEN_MANDATORY_LABEL)).contents
            sid = label.Label.Sid
            if sid:
                count = ADVAPI32.GetSidSubAuthorityCount(ctypes.c_void_p(sid))
                if count:
                    rid = ADVAPI32.GetSidSubAuthority(ctypes.c_void_p(sid),
                                                      count[0] - 1)[0]
                    integrity = INTEGRITY_NAMES.get(rid, f"0x{rid:04X}")

        privileges: int | None = None
        priv_buf = _token_info(token, TOKEN_PRIVILEGES)
        if priv_buf is not None and len(priv_buf.raw) >= 4:
            privileges = int.from_bytes(priv_buf.raw[:4], "little")

        return TokenFacts(pid, is_ac, integrity, privileges, readable=True)
    finally:
        if token:
            KERNEL32.CloseHandle(token)
        KERNEL32.CloseHandle(wt.HANDLE(handle))


def summarise_renderers(renderer_pids: Sequence[int]) -> dict:
    """What is actually true of this session's renderer processes right now.

    `unreadable` IS PART OF THE ANSWER, and leaving it out was a real defect.

    This function used to return only the readable tokens, and the caller compared
    `untrusted == measured` to decide PASS. With three renderers running and one token
    that could not be opened, `measured` was 2, `untrusted` was 2, and the check went
    green -- reporting "All 2 renderer process(es) run at UNTRUSTED integrity" while a
    third renderer, whose containment was completely unknown, was hosting page content.

    Measured directly, not reasoned about: patching `read` so PID 3 returns
    readable=False and PIDs 1-2 return UNTRUSTED produced verdict PASS. A process that
    was never measured was being counted as a process that passed, which is the exact
    thing this project treats as a vulnerability rather than a reporting nit.

    So the count of processes we FAILED to measure is now returned alongside the ones we
    did, and the caller is responsible for refusing to go green while it is non-zero.
    """
    facts = [read(pid) for pid in renderer_pids]
    readable = [f for f in facts if f.readable]
    unreadable = len(facts) - len(readable)
    if not readable:
        return {"measured": 0, "unreadable": unreadable, "appcontainer": 0,
                "untrusted": 0, "zero_privileges": 0, "worst_integrity": None}
    return {
        "measured": len(readable),
        "unreadable": unreadable,
        "appcontainer": sum(1 for f in readable if f.is_appcontainer),
        "untrusted": sum(1 for f in readable if f.integrity == "UNTRUSTED"),
        "zero_privileges": sum(1 for f in readable if f.privilege_count == 0),
        "worst_integrity": max(
            (f.integrity or "?" for f in readable),
            key=lambda name: list(INTEGRITY_NAMES.values()).index(name)
            if name in INTEGRITY_NAMES.values() else 99),
    }
