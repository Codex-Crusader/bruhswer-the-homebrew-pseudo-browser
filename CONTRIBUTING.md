# Contributing

Issues and pull requests are welcome.

## Two house rules, both non-negotiable

**1. No unverified claims.**

If you add a control, add the test that proves it. If the platform cannot enforce it,
the software says `NOT ENFORCEABLE` or `UNKNOWN` - and that is a perfectly good outcome,
not a failure to fix. A green light nobody measured is the defect class this project
treats as a vulnerability, including in its own code.

**2. No new dependencies.**

Standard library only, without a genuinely strong case. Every package added is a package
a user has to trust, and a browser-hardening tool that quietly pulls in a dependency
tree has given away the argument it is making. CI fails the build if a
`requirements.txt` appears.

## Before you open a pull request

```powershell
pip install -e .[dev]           # ruff, pinned to the version CI runs
ruff check .                    # this gates the build
ruff check --preview --select E1,E2,E3,W1,W2,W3 .
python bruhswer\tests\run_all.py
```

The suite needs network policy applied, or the five suites that depend on it are
reported as SKIPPED. A skipped suite is not a pass.

If you changed anything under `bruhswer/app/` or `bruhswer.py`, regenerate the file
manifest as the last step before you commit:

```powershell
python bruhswer\tools\hash_manifest.py --write
```

A manifest generated before the last source change ships a build that reports FAIL on a
perfectly good install, which trains the user to ignore the one indicator that would
have told them their copy was damaged.

## Style

Code files are for code. Explanation belongs in `docs/`. A comment should say why
something is the way it is when that is not obvious from reading it - not restate what
the line does.

Never strip a `# noqa` marker or the reason text attached to a lint suppression. Both
are load-bearing: the `RUF100` ignore exists specifically for the `E402` markers that
guard imports following a `sys.path` insert.

## Reporting a security problem

**Do not open a public issue.** See [`SECURITY.md`](SECURITY.md) and use GitHub's
private vulnerability reporting.

If you want to attack it deliberately, [`docs/SECURITY-TESTING.md`](docs/SECURITY-TESTING.md)
is written for you: trust-boundary map, every place untrusted input enters, how to set
up and tear down a test environment, safe harbour, a report template, and a table of
what is already known so you do not spend a weekend rediscovering a documented platform
limitation. It also lists things previously tried that did not work, which is usually
the part nobody writes down.

Where the project is going, and what it refuses to do: [`docs/ROADMAP.md`](docs/ROADMAP.md).
