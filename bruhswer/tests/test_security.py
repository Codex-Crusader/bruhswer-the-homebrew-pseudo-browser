"""BRUHWSER security tests. Standard library unittest, no dependencies.

    python -m unittest discover -s bruhswer/tests -v

Every test here corresponds to a claim BRUHWSER makes. Brief SS53: claim -> threat ->
control -> test -> evidence -> verdict. If a test fails, the claim is false, not the
test.

These run offline and change nothing on the host.
"""

from __future__ import annotations

import ast
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from app import config  # noqa: E402
from app.browser import edge  # noqa: E402
from app.controller import controller as ctrl  # noqa: E402
from app.downloads import quarantine  # noqa: E402
from app.privacy import privacy_guard  # noqa: E402
from app.security import browser_guard  # noqa: E402
from app.sessions import session_manager  # noqa: E402
from app.verdict import Check, Verdict, worst  # noqa: E402


class TestNoDangerousPrimitives(unittest.TestCase):
    """Brief SS15/SS48: these must not exist anywhere in BRUHWSER's own source.

    Parsed with `ast`, not grepped. A text search cannot tell code from a docstring --
    the first version of this test failed on the sentence in sysquery.py that PROMISES
    shell=True is never used. It also cannot tell `subprocess.run(argv)` (fine, argv is
    a list we built) from `subprocess.run("del *")` (not fine). The AST can.
    """

    BANNED_CALLS = {"eval", "exec", "compile", "__import__"}
    BANNED_ATTR_CALLS = {("os", "system"), ("os", "popen"), ("os", "execv"),
                         ("pickle", "load"), ("pickle", "loads")}

    @staticmethod
    def _sources():
        # utf-8-sig, because a stray BOM should not stop the security scan from
        # running. A test that silently skips files is worse than no test.
        for path in (_ROOT / "app").rglob("*.py"):
            yield path, ast.parse(path.read_text(encoding="utf-8-sig"),
                                  filename=str(path))

    def test_every_source_file_was_scanned(self):
        """Guard against the scan quietly covering nothing."""
        scanned = [p for p, _ in self._sources()]
        self.assertGreaterEqual(len(scanned), 10, f"only scanned {len(scanned)} files")

    def test_no_shell_true(self):
        offenders = []
        for path, tree in self._sources():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for kw in node.keywords:
                    if (kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True):
                        offenders.append(f"{path.relative_to(_ROOT)}:{node.lineno}")
        self.assertEqual(offenders, [], f"shell=True found at {offenders}")

    def test_no_dynamic_execution(self):
        offenders = []
        for path, tree in self._sources():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Name) and func.id in self.BANNED_CALLS:
                    offenders.append(f"{path.relative_to(_ROOT)}:{node.lineno} {func.id}")
                if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                        and (func.value.id, func.attr) in self.BANNED_ATTR_CALLS):
                    offenders.append(
                        f"{path.relative_to(_ROOT)}:{node.lineno} "
                        f"{func.value.id}.{func.attr}")
        self.assertEqual(offenders, [], f"dynamic execution found at {offenders}")

    def test_no_generic_execution_verb(self):
        """There must be no function offering arbitrary execution."""
        banned = {"execute_command", "run_shell", "run_powershell", "run_command",
                  "admin_command", "execute_host", "cmd"}
        offenders = []
        for path, tree in self._sources():
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name in banned:
                        offenders.append(f"{path.relative_to(_ROOT)}: def {node.name}")
        self.assertEqual(offenders, [])

    def test_every_subprocess_call_hides_its_console_window(self):
        """bruhswer is a GUI app; helper processes must not flash console windows.

        Reported from real use: startup popped up a stream of black command prompts,
        one per PowerShell verification query. Every subprocess call in `app/` must pass
        creationflags (CREATE_NO_WINDOW), and this test fails if a new call site forgets.
        """
        offenders = []
        for path, tree in self._sources():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if not (isinstance(func, ast.Attribute)
                        and func.attr in ("run", "Popen", "call", "check_output")
                        and isinstance(func.value, ast.Name)
                        and func.value.id == "subprocess"):
                    continue
                if not any(kw.arg == "creationflags" for kw in node.keywords):
                    offenders.append(f"{path.relative_to(_ROOT)}:{node.lineno}")
        self.assertEqual(offenders, [],
                         f"subprocess call without creationflags at {offenders}")

    def test_subprocess_first_argument_is_never_a_string(self):
        """A string first argument is how command injection happens on Windows.

        A variable is acceptable -- BRUHWSER builds those lists itself, and
        TestBrowserCommandLine covers what goes into them.
        """
        offenders = []
        for path, tree in self._sources():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                is_subprocess = (
                    isinstance(func, ast.Attribute)
                    and func.attr in ("run", "Popen", "call", "check_output")
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "subprocess")
                if not is_subprocess or not node.args:
                    continue
                first = node.args[0]
                if isinstance(first, (ast.JoinedStr,)) or (
                        isinstance(first, ast.Constant) and isinstance(first.value, str)):
                    offenders.append(f"{path.relative_to(_ROOT)}:{node.lineno}")
        self.assertEqual(offenders, [], f"string command line at {offenders}")


class TestNoLocalListener(unittest.TestCase):
    """Brief SS25 and the hardening brief SS6: bruhswer must create NO local endpoint.

    This is the single most load-bearing structural claim bruhswer makes about its own
    attack surface. Stage 4 gate A16 measured that Windows Firewall does not filter
    loopback, so a compromised browser process can reach ANY socket or pipe this
    process opens, and no rule can stop it. bruhswer therefore does not get to have a
    localhost control API, a debug server, a DevTools endpoint or an IPC listener - not
    a hardened one, not a localhost-bound one, not a temporary one.

    The UI and the controller live in one process and call each other directly, so
    there is nothing for a listener to do. These tests fail if that ever changes.
    """

    # Modules whose entire purpose is to accept an inbound connection.
    BANNED_IMPORTS = {"socket", "socketserver", "http.server", "asyncio", "ssl",
                      "xmlrpc.server", "multiprocessing.connection", "wsgiref",
                      "flask", "fastapi", "aiohttp", "tornado", "uvicorn",
                      "websockets", "werkzeug"}

    # Calls that open or accept on an endpoint, whatever the module they came from.
    #
    # `bind` and `accept` are deliberately NOT in this set: Tk's event system uses
    # widget.bind("<Return>", ...) all over the UI, and banning the bare name would
    # make this test fire on ordinary keyboard handling. A test that cries wolf on
    # every Tk callback gets muted, and then it protects nothing. Socket binds are
    # caught precisely by test_no_socket_style_bind below instead.
    BANNED_ATTRS = {"listen", "create_server", "start_server", "create_connection",
                    "serve_forever", "CreateNamedPipe", "CreateNamedPipeW",
                    "ConnectNamedPipe"}

    @staticmethod
    def _sources():
        for path in (_ROOT / "app").rglob("*.py"):
            yield path, ast.parse(path.read_text(encoding="utf-8-sig"),
                                  filename=str(path))

    def test_no_server_module_is_imported(self):
        offenders = []
        for path, tree in self._sources():
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    # Match the module and any parent package, so `import http.server`
                    # and `from http import server` are both caught.
                    parts = name.split(".")
                    if any(".".join(parts[:i + 1]) in self.BANNED_IMPORTS
                           for i in range(len(parts))):
                        offenders.append(
                            f"{path.relative_to(_ROOT)}:{node.lineno} imports {name}")
        self.assertEqual(offenders, [], f"listener-capable import at {offenders}")

    def test_no_bind_listen_or_named_pipe_call(self):
        offenders = []
        for path, tree in self._sources():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = (func.attr if isinstance(func, ast.Attribute)
                        else func.id if isinstance(func, ast.Name) else "")
                if name in self.BANNED_ATTRS:
                    offenders.append(
                        f"{path.relative_to(_ROOT)}:{node.lineno} calls {name}")
        self.assertEqual(offenders, [], f"endpoint call at {offenders}")

    def test_no_socket_style_bind(self):
        """A socket bind is `sock.bind((host, port))` - the argument is an ADDRESS.

        Tk's `widget.bind("<Return>", handler)` takes an event string, so keying on
        the shape of the first argument separates the two exactly, with no allow-list
        of widget names to keep up to date.
        """
        offenders = []
        for path, tree in self._sources():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if not (isinstance(func, ast.Attribute) and func.attr == "bind"
                        and node.args):
                    continue
                first = node.args[0]
                event_string = (isinstance(first, ast.Constant)
                                and isinstance(first.value, str))
                if not event_string:
                    offenders.append(
                        f"{path.relative_to(_ROOT)}:{node.lineno} binds a non-event")
        self.assertEqual(offenders, [], f"socket-style bind at {offenders}")

    def test_scan_actually_covered_the_application(self):
        """A scan that silently covers nothing proves nothing."""
        self.assertGreaterEqual(len(list(self._sources())), 10)

    def test_no_remote_debugging_flag_can_reach_the_browser(self):
        """The DevTools protocol is the listener bruhswer is most likely to grow.

        --remote-debugging-port opens an UNAUTHENTICATED localhost endpoint that grants
        full control of the browser to anything that can reach it - and on this
        platform, a compromised renderer can. It is in DANGEROUS_FLAGS, and
        edge.build_command refuses it rather than filtering it.
        """
        self.assertIn("--remote-debugging-port", config.DANGEROUS_FLAGS)
        self.assertIn("--remote-debugging-pipe", config.DANGEROUS_FLAGS)
        for flag in ("--remote-debugging-port=9222", "--remote-debugging-pipe"):
            with self.assertRaises(ValueError):
                edge.build_command(Path("msedge.exe"), Path("p"), (flag,))
        # And none of the flags bruhswer actually ships may open one.
        for flag in config.BASE_EDGE_FLAGS:
            self.assertNotIn("remote-debugging", flag)


class TestFilenameSanitisation(unittest.TestCase):
    """Brief SS36/SS40: a downloaded filename is hostile text, never a path."""

    def test_traversal_is_removed(self):
        for hostile in (r"..\..\..\Windows\System32\evil.exe",
                        "../../../../etc/passwd",
                        r"C:\Users\someone\Desktop\owned.txt",
                        r"\\attacker\share\payload.exe"):
            safe = quarantine.safe_export_name(hostile)
            self.assertNotIn("..", safe, hostile)
            self.assertNotIn("\\", safe, hostile)
            self.assertNotIn("/", safe, hostile)
            self.assertNotIn(":", safe, hostile)

    def test_alternate_data_stream_is_removed(self):
        self.assertNotIn(":", quarantine.safe_export_name("report.pdf:hidden.exe"))

    def test_reserved_device_names_are_defused(self):
        for name in ("CON", "con.txt", "PRN.pdf", "aux", "COM1.dat", "lpt9"):
            safe = quarantine.safe_export_name(name)
            stem = safe.split(".")[0].lower()
            self.assertNotIn(stem, {"con", "prn", "aux", "com1", "lpt9"}, name)

    def test_null_bytes_removed(self):
        self.assertNotIn("\x00", quarantine.safe_export_name("bad\x00name.txt"))

    def test_empty_gets_a_name(self):
        for hostile in ("", "...", "   ", "/", "\\", ".."):
            self.assertTrue(quarantine.safe_export_name(hostile))

    def test_length_bounded(self):
        self.assertLessEqual(len(quarantine.safe_export_name("A" * 5000 + ".txt")), 120)

    def test_ordinary_name_survives(self):
        self.assertEqual(quarantine.safe_export_name("lecture-notes.pdf"),
                         "lecture-notes.pdf")


class TestBrowserCommandLine(unittest.TestCase):
    """Brief SS48: BRUHWSER must never start the browser with a weakened sandbox."""

    def setUp(self):
        self.edge = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
        self.profile = config.PROFILE_PERSISTENT

    def test_dangerous_flags_are_refused(self):
        for flag in ("--no-sandbox", "--disable-web-security",
                     "--ignore-certificate-errors", "--remote-debugging-port=9222",
                     "--disable-site-isolation-trials"):
            with self.assertRaises(ValueError, msg=flag):
                edge.build_command(self.edge, self.profile, (flag,))

    def test_non_http_urls_are_refused(self):
        for url in ("file:///C:/Windows/win.ini", "javascript:alert(1)",
                    r"\\attacker\share", "data:text/html,<script>"):
            with self.assertRaises(ValueError, msg=url):
                edge.build_command(self.edge, self.profile, (), url)

    def test_exactly_one_profile_argument(self):
        argv = edge.build_command(self.edge, self.profile, ())
        self.assertEqual(sum(1 for a in argv if a.startswith("--user-data-dir=")), 1)

    def test_url_cannot_smuggle_a_flag(self):
        """A URL is a separate argv element, so it can never become a flag."""
        argv = edge.build_command(self.edge, self.profile, (),
                                  "https://example.com/?x=--no-sandbox")
        self.assertEqual(argv[-1], "https://example.com/?x=--no-sandbox")
        self.assertNotIn("--no-sandbox", argv[:-1])


class TestDownloadDirectoryIsAPreference(unittest.TestCase):
    """Regression guard for a real bug (brief SS24, SS36).

    bruhswer used to pass `--download-directory=<quarantine>` on the command line.
    That is NOT a Chromium switch. Edge ignored it silently, downloads went to the
    user's REAL Downloads folder, and the quarantine feature was a false claim - while
    every test still passed, because nothing had ever downloaded a file.

    These tests make the failure loud if anyone reintroduces it.
    """

    def test_no_fake_download_flag_in_the_launch_command(self):
        controller = ctrl.Controller()
        if controller.edge_path is None:
            self.skipTest("Edge not installed")
        argv = controller.preview_launch_command(config.PROFILE_PERSISTENT)
        offenders = [a for a in argv if a.startswith("--download-directory")]
        self.assertEqual(offenders, [],
                         "--download-directory is not a real Chromium switch; the "
                         "download location must be a profile preference")

    def test_download_directory_is_written_and_verified_as_a_preference(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile"
            target = Path(tmp) / "quarantine"
            target.mkdir(parents=True)

            ok, _ = privacy_guard.verify_download_directory(profile, target)
            self.assertFalse(ok, "must not pass before anything is written")

            privacy_guard.apply_download_directory(profile, target)
            ok, detail = privacy_guard.verify_download_directory(profile, target)
            self.assertTrue(ok, detail)

            prefs = json.loads(
                (profile / "Default" / "Preferences").read_text(encoding="utf-8"))
            self.assertEqual(prefs["download"]["default_directory"], str(target))
            self.assertIs(prefs["download"]["prompt_for_download"], False,
                          "a save prompt would let a hostile download escape quarantine")

    def test_verify_rejects_a_wrong_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile"
            good = Path(tmp) / "quarantine"
            elsewhere = Path(tmp) / "somewhere-else"
            good.mkdir(parents=True)
            elsewhere.mkdir(parents=True)
            privacy_guard.apply_download_directory(profile, elsewhere)
            ok, detail = privacy_guard.verify_download_directory(profile, good)
            self.assertFalse(ok, "pointing somewhere else must fail verification")
            self.assertIn("expected", detail)


class TestBrowserLaunchFlags(unittest.TestCase):
    """Guards a measured finding about what Edge opens on startup.

    Measured: a fresh profile launched with only --no-first-run --no-default-browser-check
    ended up showing "Redirecting... and 1 more page" - an ad/redirect tab the user never
    asked for. Launched with bruhswer's flag set, the same fresh profile showed exactly
    "about:blank". The difference is the --disable-features list.

    Nothing else in the suite would notice if those flags were dropped, so the browser
    would quietly start opening unrequested pages again.
    """

    def test_startup_noise_suppression_flags_present(self):
        joined = " ".join(config.BASE_EDGE_FLAGS)
        for needed in ("--no-first-run", "--no-default-browser-check",
                       "--disable-background-networking", "--no-service-autorun"):
            self.assertIn(needed, joined)
        self.assertIn("--disable-features=", joined,
                      "the measured fix for the unrequested redirect tab")

    def test_crash_restore_is_suppressed_by_a_flag_not_a_preference(self):
        """A crashed session must not silently reopen the previous tabs.

        MEASURED: `session.restore_on_startup` as a preference does NOT stick - Edge
        rewrote it on all three of three consecutive launches. So the guarantee rests on
        a launch flag Edge cannot revert, plus a graceful WM_CLOSE that stops the profile
        being marked crashed in the first place. Asserting the preference here would have
        been asserting something that does not hold.
        """
        self.assertIn("--hide-crash-restore-bubble", config.BASE_EDGE_FLAGS)
        keys = {s.key for s in privacy_guard.STANDARD}
        self.assertNotIn("session.restore_on_startup", keys,
                         "measured not to stick; must not be claimed as enforced")

    def test_no_flag_weakens_the_browser(self):
        joined = " ".join(config.BASE_EDGE_FLAGS)
        for bad in config.DANGEROUS_FLAGS:
            self.assertNotIn(bad, joined)


class TestSessionDestruction(unittest.TestCase):
    """Brief SS42: never claim a session was destroyed when it was not."""

    def test_refuses_path_outside_disposable_root(self):
        rogue = session_manager.Session(
            mode=session_manager.DISPOSABLE, session_id="a" * 16,
            profile_dir=Path.home() / "Documents",
            created=session_manager.datetime.now(session_manager.timezone.utc))
        ok, message = session_manager.destroy(rogue)
        self.assertFalse(ok)
        self.assertIn("Refused", message)

    def test_rejects_malformed_session_id(self):
        rogue = session_manager.Session(
            mode=session_manager.DISPOSABLE, session_id="../../etc",
            profile_dir=config.PROFILE_DISPOSABLE_ROOT / "x",
            created=session_manager.datetime.now(session_manager.timezone.utc))
        with self.assertRaises(ValueError):
            session_manager.destroy(rogue)

    def test_create_and_destroy_roundtrip(self):
        session = session_manager.create(session_manager.DISPOSABLE)
        self.assertTrue(session.profile_dir.is_dir())
        (session.profile_dir / "marker.txt").write_text("x", encoding="utf-8")
        ok, message = session_manager.destroy(session)
        self.assertTrue(ok, message)
        self.assertFalse(session.profile_dir.exists())


class TestQuarantineExport(unittest.TestCase):
    def test_export_refuses_source_outside_quarantine(self):
        outside = quarantine.QuarantinedFile(
            path=Path(__file__), size=1,
            modified=session_manager.datetime.now(session_manager.timezone.utc))
        ok, message = quarantine.export(outside, Path.home())
        self.assertFalse(ok)
        self.assertIn("Refused", message)

    def test_executable_types_are_flagged(self):
        item = quarantine.QuarantinedFile(
            path=Path("totally-legit.exe"), size=1,
            modified=session_manager.datetime.now(session_manager.timezone.utc))
        self.assertTrue(item.is_executable_type)


class TestProfileCollisionUsesPathAncestry(unittest.TestCase):
    """The check used str.startswith, so a sibling directory whose name merely began
    with the same characters counted as a collision and blocked the launch."""

    def setUp(self):
        self.edge = Path(config.os.environ["LOCALAPPDATA"]) / "Microsoft" / "Edge" / \
            "User Data"

    def test_sibling_with_a_prefix_name_is_not_a_collision(self):
        self.assertFalse(browser_guard._is_within(
            Path(str(self.edge) + "-Evil"), self.edge))

    def test_the_directory_itself_is_a_collision(self):
        self.assertTrue(browser_guard._is_within(self.edge, self.edge))

    def test_a_profile_inside_it_is_a_collision(self):
        self.assertTrue(browser_guard._is_within(self.edge / "Default", self.edge))

    def test_windows_path_case_does_not_defeat_the_check(self):
        self.assertTrue(browser_guard._is_within(
            Path(str(self.edge).upper()) / "Default", self.edge))

    def test_bruhswers_own_profile_is_not_a_collision(self):
        self.assertFalse(browser_guard._is_within(
            config.PROFILE_PERSISTENT, self.edge))


class TestFailClosedSemantics(unittest.TestCase):
    """Brief SS8: UNKNOWN is never a pass."""

    def test_unknown_blocks_launch(self):
        check = Check("t", "t", Verdict.UNKNOWN, "", critical=True)
        self.assertTrue(check.blocks_launch)

    def test_fail_blocks_launch(self):
        self.assertTrue(Check("t", "t", Verdict.FAIL, "", critical=True).blocks_launch)

    def test_pass_does_not_block(self):
        self.assertFalse(Check("t", "t", Verdict.PASS, "", critical=True).blocks_launch)

    def test_non_critical_never_blocks(self):
        self.assertFalse(Check("t", "t", Verdict.FAIL, "", critical=False).blocks_launch)

    def test_known_unenforceable_does_not_block_but_is_never_green(self):
        check = Check("t", "t", Verdict.FAIL, "", critical=True, enforceable=False)
        self.assertFalse(check.blocks_launch)
        self.assertEqual(check.indicator(), "NOT ENFORCEABLE")

    def test_aggregate_prefers_fail_then_unknown(self):
        self.assertIs(worst([Check("a", "a", Verdict.PASS, ""),
                             Check("b", "b", Verdict.UNKNOWN, ""),
                             Check("c", "c", Verdict.FAIL, "")]), Verdict.FAIL)
        self.assertIs(worst([Check("a", "a", Verdict.PASS, ""),
                             Check("b", "b", Verdict.UNKNOWN, "")]), Verdict.UNKNOWN)
        self.assertIs(worst([Check("a", "a", Verdict.PASS, "")]), Verdict.PASS)

    def test_unenforceable_excluded_from_aggregate(self):
        """A platform limitation must not permanently paint every category red."""
        self.assertIs(worst([Check("a", "a", Verdict.PASS, ""),
                             Check("b", "b", Verdict.FAIL, "", enforceable=False)]),
                      Verdict.PASS)


class TestDisposableLeavesNothingBehind(unittest.TestCase):
    """A disposable session must not leave downloads on disk after it is destroyed.

    REGRESSION. Measured defect: destroy() removed the profile and reported "destroyed
    and verified gone" while the session's quarantine folder - containing every file
    downloaded during that session - stayed on disk permanently. sweep_orphans only
    looked at profiles, and the quarantine panel only lists the CURRENT session, so
    those files were unreachable from the UI and never cleaned up by anything.
    """

    def test_destroy_removes_the_sessions_quarantine(self):
        session = session_manager.create(session_manager.DISPOSABLE)
        qdir = quarantine.quarantine_dir_for(session.session_id)
        payload = qdir / "leftover.txt"
        payload.write_text("downloaded during a disposable session", encoding="utf-8")

        self.assertTrue(payload.is_file(), "setup failed")
        pending = session_manager.pending_quarantine(session)
        self.assertEqual([p.name for p in pending], ["leftover.txt"])

        ok, message = session_manager.destroy(session)
        self.assertTrue(ok, message)
        self.assertFalse(session.profile_dir.exists(), "profile survived")
        self.assertFalse(payload.exists(), "downloaded file survived destruction")
        self.assertFalse(qdir.exists(), "quarantine folder survived destruction")
        # The user is told what went, rather than left to guess.
        self.assertIn("1 quarantined download", message)

    def test_sweep_removes_quarantine_orphaned_by_a_crash(self):
        """The crash path: profile gone, quarantine left behind."""
        session = session_manager.create(session_manager.DISPOSABLE)
        qdir = quarantine.quarantine_dir_for(session.session_id)
        (qdir / "orphan.txt").write_text("x", encoding="utf-8")

        # Simulate a hard kill: the profile vanishes, the quarantine does not.
        shutil.rmtree(session.profile_dir, ignore_errors=True)
        self.assertTrue(qdir.is_dir(), "setup failed")

        session_manager.sweep_orphans()
        self.assertFalse(qdir.exists(), "orphaned quarantine survived the sweep")

    def test_sweep_refuses_to_delete_through_a_junction(self):
        """A junction planted under the disposable root must not redirect the sweep.

        Found by independent review. `Path.is_dir()` follows a directory junction, so
        a junction named like a session id looks exactly like an orphaned profile.
        Anything running as the user - including a compromised browser process - can
        create one, and following it would turn bruhswer's startup sweep into a
        delete-anything primitive aimed wherever the junction points.

        Skipped, not silently passed, if the OS will not create a junction: a test
        that quietly proves nothing is worse than one that says it could not run.
        """
        import subprocess as sp

        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "victim"
            victim.mkdir()
            treasure = victim / "important.txt"
            treasure.write_text("must survive", encoding="utf-8")

            link = config.PROFILE_DISPOSABLE_ROOT / "abcdef0123456789"
            if link.exists():
                self.skipTest("a real session already occupies the test name")
            proc = sp.run(["cmd", "/c", "mklink", "/J", str(link), str(victim)],
                          capture_output=True, text=True, shell=False,
                          creationflags=config.NO_WINDOW)
            if proc.returncode != 0 or not link.exists():
                self.skipTest(f"could not create a junction: {proc.stderr.strip()}")

            try:
                session_manager.sweep_orphans()
                self.assertTrue(treasure.is_file(),
                                "sweep_orphans deleted through a junction")
                self.assertEqual(treasure.read_text(encoding="utf-8"), "must survive")
            finally:
                # Remove the junction itself, never its target.
                try:
                    link.rmdir()
                except OSError:
                    pass

    def test_persistent_quarantine_is_never_swept(self):
        """The persistent session's downloads must survive restarts."""
        qdir = quarantine.quarantine_dir_for("persistent000000")
        keeper = qdir / "keep-me.txt"
        keeper.write_text("persistent download", encoding="utf-8")
        try:
            session_manager.sweep_orphans()
            self.assertTrue(keeper.is_file(),
                            "sweep destroyed a persistent session's download")
        finally:
            keeper.unlink(missing_ok=True)


class TestConfigSanity(unittest.TestCase):
    def test_all_paths_are_under_one_root(self):
        for path in (config.PROFILE_PERSISTENT, config.PROFILE_DISPOSABLE_ROOT,
                     config.QUARANTINE, config.LOGS, config.STATE):
            self.assertTrue(path.is_relative_to(config.ROOT), str(path))

    def test_no_reserved_ipc_surface_remains_in_config(self):
        """bruhswer must not carry a control-channel it does not implement.

        config.py used to reserve a named pipe and a verb allow-list for a UI-to-
        controller channel that was never built - the UI and controller share one
        process and call each other directly. A dormant endpoint name in config is a
        standing invitation to implement one, and Stage 4 measured that any local
        endpoint is reachable by a compromised browser process. The names are gone,
        and this test fails if one comes back.
        """
        for name in ("PIPE_NAME", "ALLOWED_IPC_VERBS", "MAX_IPC_MESSAGE_BYTES"):
            self.assertFalse(hasattr(config, name),
                             f"config.{name} is back; bruhswer has no IPC channel")

    def test_cgnat_is_not_blocked(self):
        """100.64/10 carries some users' only path to the internet (brief SS19)."""
        self.assertNotIn("100.64.0.0/10", config.BLOCKED_IPV4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
