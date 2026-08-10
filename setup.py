"""bruhswer is an application, not an installable Python package.

This file exists ONLY to turn a confusing setuptools error into an explicit one.

Without it, `pip wheel .` fails with "Multiple top-level packages discovered in a
flat-layout", which reads like the packaging is misconfigured. It is not
misconfigured - it is deliberately absent, and the reasoning is at the top of
pyproject.toml.

The short version: the previous build config produced a wheel containing five
modules and silently omitting all nine subpackages, including every security
guard. Making discovery "work" would have installed a top-level package named
`app` into site-packages, squatting one of the most generic importable names
there is, for a distribution channel that does not exist. bruhswer has no console
entry point and nothing imports it.

Install it the two supported ways instead:

    the Windows installer from the Releases page
    or:  git clone ... && cd bruhswer && python bruhswer.py
"""

import sys

sys.exit(
    "\n"
    "bruhswer is a Windows application, not a pip-installable package.\n"
    "\n"
    "There is deliberately no build backend. See the comment at the top of\n"
    "pyproject.toml for why - the short version is that the wheel this project\n"
    "used to build was silently missing nine of its ten packages, and fixing\n"
    "that would have squatted the top-level name `app` in site-packages.\n"
    "\n"
    "Run it instead:\n"
    "\n"
    "    cd bruhswer\n"
    "    python bruhswer.py\n"
    "\n"
    "or install the signed-by-nobody Windows installer from the Releases page,\n"
    "after checking its SHA-256 against the published checksum.\n"
)
