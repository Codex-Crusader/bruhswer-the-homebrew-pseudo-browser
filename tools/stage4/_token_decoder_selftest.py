"""Validate the token-group/capability decoder used by a3_stock_sandbox_measure.py.

WHY THIS EXISTS
---------------
A3 reported LPAC=None and CAPABILITIES=<empty> for every process, including Edge
renderers that are definitely AppContainer tokens. Two explanations are possible:

  1. those tokens genuinely carry no ALL[_RESTRICTED]_APPLICATION_PACKAGES group and
     no capabilities, or
  2. the decoder is broken and silently returns empty lists

Reporting (1) without ruling out (2) would be inventing a measurement. This script
runs the same decoder against THIS process, whose token certainly has many groups. If
the decoder returns a populated list here and an empty one for a renderer, the empty
result is a real property of that token, not a bug.
"""

import ctypes
import ctypes.wintypes as wt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a3_stock_sandbox_measure import (  # noqa: E402
    INVALID_HANDLE_VALUE, PROCESS_QUERY_LIMITED_INFORMATION, TOKEN_QUERY,
    TokenCapabilities, TokenGroups, _get_info, _sid_list, advapi32, kernel32,
)


def dump(pid, label):
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h or h == INVALID_HANDLE_VALUE:
        print("  %s (pid %d): OpenProcess failed %d"
              % (label, pid, ctypes.get_last_error()))
        return
    tok = wt.HANDLE()
    try:
        if not advapi32.OpenProcessToken(h, TOKEN_QUERY, ctypes.byref(tok)):
            print("  %s (pid %d): OpenProcessToken failed %d"
                  % (label, pid, ctypes.get_last_error()))
            return
        gbuf = _get_info(tok, TokenGroups)
        cbuf = _get_info(tok, TokenCapabilities)
        groups = _sid_list(gbuf)
        caps = _sid_list(cbuf)
        print("  %s (pid %d):" % (label, pid))
        print("      TokenGroups buffer      : %s"
              % ("None" if gbuf is None else "%d bytes" % len(gbuf.raw)))
        print("      groups decoded          : %d" % len(groups))
        for s in groups[:8]:
            print("          %s" % s)
        if len(groups) > 8:
            print("          ... (+%d more)" % (len(groups) - 8))
        print("      TokenCapabilities buffer: %s"
              % ("None" if cbuf is None else "%d bytes" % len(cbuf.raw)))
        print("      capabilities decoded    : %d" % len(caps))
        for s in caps[:8]:
            print("          %s" % s)
    finally:
        if tok:
            kernel32.CloseHandle(tok)
        kernel32.CloseHandle(wt.HANDLE(h))


def main():
    print("Token decoder self-test")
    print("=" * 70)
    print("\nCONTROL - this Python process (ordinary user token, many groups expected):")
    dump(os.getpid(), "self")
    print("\nIf 'groups decoded' above is 0, the DECODER is broken and every LPAC/")
    print("capability result reported by A3 must be treated as UNKNOWN, not as a")
    print("measurement.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
