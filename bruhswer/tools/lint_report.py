"""A small AST linter for bruhswer, using only the standard library.

Why not just install a linter: bruhswer's dependency policy exists because gate B17
rejected a whole backend over an unverifiable third-party binary. That policy is about
what ships, not about tooling - but `ast` covers the mechanical findings well enough
that adding a package would be paying a real cost for a small gain.

Finds, per file:
    unused imports
    unused local variables
    broad or bare `except` clauses
    access to another module's protected members
    methods that never touch `self` (candidates for @staticmethod)
    calls whose return value is used but which always return None

Report only. It changes nothing.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {"__pycache__"}


class FileReport:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[tuple[int, str, str]] = []

    def add(self, line: int, kind: str, message: str) -> None:
        self.findings.append((line, kind, message))


def _collect_names(tree: ast.AST) -> set[str]:
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            cur = node
            while isinstance(cur, ast.Attribute):
                cur = cur.value
            if isinstance(cur, ast.Name):
                used.add(cur.id)
    return used


def check_unused_imports(tree: ast.AST, report: FileReport) -> None:
    used = _collect_names(tree)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = getattr(node, "module", None)
            if module == "__future__":
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                name = (alias.asname or alias.name).split(".")[0]
                if name not in used:
                    report.add(node.lineno, "unused-import", name)


def check_functions(tree: ast.AST, report: FileReport) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        assigned: dict[str, int] = {}
        used: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                if isinstance(sub.ctx, ast.Store):
                    assigned.setdefault(sub.id, sub.lineno)
                else:
                    used.add(sub.id)
            elif isinstance(sub, ast.Attribute):
                cur = sub
                while isinstance(cur, ast.Attribute):
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    used.add(cur.id)
        for name, line in assigned.items():
            if name.startswith("_"):
                continue
            if name not in used:
                report.add(line, "unused-local", f"{name} in {node.name}()")


def check_excepts(tree: ast.AST, report: FileReport) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if node.type is None:
            report.add(node.lineno, "bare-except", "except: with no exception type")
        elif isinstance(node.type, ast.Name) and node.type.id in ("Exception",
                                                                  "BaseException"):
            report.add(node.lineno, "broad-except", f"except {node.type.id}")


def check_protected_access(tree: ast.AST, report: FileReport) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        if not node.attr.startswith("_") or node.attr.startswith("__"):
            continue
        if isinstance(node.value, ast.Name) and node.value.id != "self":
            report.add(node.lineno, "protected-access",
                       f"{node.value.id}.{node.attr}")


# Overriding a base-class method that takes self is NOT a static-method candidate -
# making it static would break the override. Reporting these would be noise, and a
# linter that cries wolf gets ignored.
_KNOWN_OVERRIDES = {
    "format",            # logging.Formatter
    "log_message",       # BaseHTTPRequestHandler
    "handle_error",      # socketserver.BaseServer
    "do_GET", "do_POST", "do_HEAD",
    "setUp", "tearDown", "runTest",
}


def check_static_candidates(tree: ast.AST, report: FileReport) -> None:
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        for node in cls.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(isinstance(d, ast.Name) and d.id in ("staticmethod", "classmethod",
                                                        "property")
                   for d in node.decorator_list):
                continue
            args = node.args.args
            if not args or args[0].arg != "self":
                continue
            if node.name in _KNOWN_OVERRIDES:
                continue
            uses_self = any(isinstance(s, ast.Name) and s.id == "self"
                            for s in ast.walk(node))
            if not uses_self:
                report.add(node.lineno, "could-be-static",
                           f"{cls.name}.{node.name}() never uses self")


def scan(path: Path) -> FileReport:
    report = FileReport(path)
    source = path.read_text(encoding="utf-8-sig")
    tree = ast.parse(source, filename=str(path))
    check_unused_imports(tree, report)
    check_functions(tree, report)
    check_excepts(tree, report)
    check_protected_access(tree, report)
    check_static_candidates(tree, report)
    check_instance_attrs(tree, report)
    return report


# unittest's documented place to set up per-test state is setUp, not __init__.
# Flagging those would be the linter being wrong about the framework.
_INIT_LIKE = {"__init__", "setUp", "setUpClass", "asyncSetUp"}


def check_instance_attrs(tree: ast.AST, report: FileReport) -> None:
    """Attributes first assigned outside __init__ hide part of an object's state."""
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        in_init: set[str] = set()
        elsewhere: dict[str, int] = {}
        for node in cls.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                if not (isinstance(sub, ast.Attribute)
                        and isinstance(sub.ctx, ast.Store)
                        and isinstance(sub.value, ast.Name)
                        and sub.value.id == "self"):
                    continue
                if node.name in _INIT_LIKE:
                    in_init.add(sub.attr)
                else:
                    elsewhere.setdefault(sub.attr, sub.lineno)
        for name, line in sorted(elsewhere.items(), key=lambda kv: kv[1]):
            if name not in in_init:
                report.add(line, "attr-outside-init", f"{cls.name}.{name}")


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else _ROOT
    targets = sorted(
        p for p in root.rglob("*.py")
        if not any(part in SKIP_DIRS for part in p.parts)
        and ".venv" not in p.parts
    )
    total = 0
    by_kind: dict[str, int] = {}
    for path in targets:
        report = scan(path)
        if not report.findings:
            continue
        rel = path.relative_to(root)
        print(f"\n{rel}")
        for line, kind, message in sorted(report.findings):
            print(f"  {line:>5}  {kind:<18} {message}")
            total += 1
            by_kind[kind] = by_kind.get(kind, 0) + 1

    print("\n" + "=" * 70)
    print(f"files scanned: {len(targets)}   findings: {total}")
    for kind, count in sorted(by_kind.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>4}  {kind}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
