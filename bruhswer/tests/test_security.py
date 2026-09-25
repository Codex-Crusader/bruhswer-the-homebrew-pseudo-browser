"""BRUHWSER security tests. Standard library unittest, no dependencies.

    python -m unittest discover -s bruhswer/tests -v

Each test is a claim bruhswer makes; if it fails, the claim is false. Offline, and
changes nothing on the host.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
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
    """Dangerous primitives, found with `ast`: grep cannot tell code from docstrings,
    or run(argv) from run("del *")."""

    BANNED_CALLS = {"eval", "exec", "compile", "__import__"}
    BANNED_ATTR_CALLS = {("os", "system"), ("os", "popen"), ("os", "execv"),
                         ("pickle", "load"), ("pickle", "loads")}

    @staticmethod
    def _sources():
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
        """Every subprocess call passes creationflags, or startup flashes consoles."""
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
        """A string first argument is how command injection happens; a variable (a
        list bruhswer built) is fine."""
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
    """bruhswer creates NO local endpoint: a compromised browser can reach any socket
    or pipe on loopback, and no firewall rule stops it (gate A16)."""

    # Plus importlib, which can name a banned module in a string. Known gap: ctypes can
    # call Winsock directly; the runtime port check in test_localhost_surface.py is the
    # real control.
    BANNED_IMPORTS = {"socket", "socketserver", "http.server", "asyncio", "ssl",
                      "xmlrpc.server", "multiprocessing.connection", "wsgiref",
                      "flask", "fastapi", "aiohttp", "tornado", "uvicorn",
                      "websockets", "werkzeug", "importlib"}

    # Not `bind`: Tk uses widget.bind everywhere. test_no_socket_style_bind covers it.
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
        """A socket bind takes an address tuple; Tk's bind takes an event string."""
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
        """--remote-debugging-port would open an unauthenticated control endpoint;
        build_command refuses it."""
        self.assertIn("--remote-debugging-port", config.DANGEROUS_FLAGS)
        self.assertIn("--remote-debugging-pipe", config.DANGEROUS_FLAGS)
        for flag in ("--remote-debugging-port=9222", "--remote-debugging-pipe"):
            with self.assertRaises(ValueError):
                edge.build_command(Path("msedge.exe"), Path("p"), (flag,))
        for flag in config.BASE_EDGE_FLAGS:
            self.assertNotIn("remote-debugging", flag)


class TestFilenameSanitisation(unittest.TestCase):
    """A downloaded filename is hostile text, never a path."""

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
    """The browser never starts with a weakened sandbox."""

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
    """--download-directory is not a Chromium switch; Edge ignored it and downloads
    went to the real Downloads folder while every test passed."""

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
    """Measured: without the --disable-features list a fresh profile opens an
    ad/redirect page instead of about:blank."""

    def test_startup_noise_suppression_flags_present(self):
        joined = " ".join(config.BASE_EDGE_FLAGS)
        for needed in ("--no-first-run", "--no-default-browser-check",
                       "--disable-background-networking", "--no-service-autorun"):
            self.assertIn(needed, joined)
        self.assertIn("--disable-features=", joined,
                      "the measured fix for the unrequested redirect tab")

    def test_crash_restore_is_suppressed_by_a_flag_not_a_preference(self):
        """No tab restore after a crash. The preference does not stick (Edge rewrote it
        3 of 3 launches), so a launch flag does it."""
        self.assertIn("--hide-crash-restore-bubble", config.BASE_EDGE_FLAGS)
        keys = {s.key for s in privacy_guard.STANDARD}
        self.assertNotIn("session.restore_on_startup", keys,
                         "measured not to stick; must not be claimed as enforced")

    def test_no_flag_weakens_the_browser(self):
        joined = " ".join(config.BASE_EDGE_FLAGS)
        for bad in config.DANGEROUS_FLAGS:
            self.assertNotIn(bad, joined)


class TestSessionDestruction(unittest.TestCase):
    """Never claim a session was destroyed when it was not."""

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


class TestQuarantineFolderNamingHasOneDerivation(unittest.TestCase):
    """One derivation of the quarantine folder name; a second copy diverged for the
    persistent session id."""

    def test_disposable_id_matches_what_downloads_were_actually_written_under(self):
        session_id = "a" * 16
        via_quarantine = quarantine.folder_name_for(session_id)
        session = session_manager.Session(
            mode=session_manager.DISPOSABLE, session_id=session_id,
            profile_dir=config.PROFILE_DISPOSABLE_ROOT / session_id,
            created=session_manager.datetime.now(session_manager.timezone.utc))
        session_manager.pending_quarantine(session)  # must not raise on a missing dir
        self.assertEqual(via_quarantine, "a" * 16)

    def test_persistent_id_no_longer_diverges(self):
        """The id that diverged ('ee000000' before the fix)."""
        session_id = "persistent000000"
        self.assertEqual(quarantine.folder_name_for(session_id), session_id)


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

    @staticmethod
    def _item(name: str, sniffed: str | None = None) -> quarantine.QuarantinedFile:
        return quarantine.QuarantinedFile(
            path=Path(name), size=1,
            modified=session_manager.datetime.now(session_manager.timezone.utc),
            sniffed_kind=sniffed)

    def test_disk_images_and_active_documents_carry_a_warning(self):
        """ISO and VHD files were the route past Mark of the Web; macro documents and
        OneNote files carry code. None of them drew a warning."""
        for name in ("setup.iso", "disk.img", "disk.vhd", "disk.vhdx", "a.docm",
                     "a.xlsm", "a.pptm", "notes.one", "INVOICE.ISO"):
            with self.subTest(name=name):
                self.assertIsNotNone(self._item(name).type_warning)

    def test_disk_images_are_not_called_programs(self):
        item = self._item("setup.iso")
        self.assertFalse(item.is_executable_type)
        self.assertNotIn("program", item.type_warning)

    def test_a_program_named_as_a_disk_image_is_still_a_mismatch(self):
        """The container set must not feed extension_mismatch, or a PE called
        'invoice.iso' loses the one warning that reads its bytes."""
        item = self._item("invoice.iso", sniffed="Windows executable (PE)")
        self.assertTrue(item.extension_mismatch)

    def test_ordinary_files_carry_no_type_warning(self):
        for name in ("photo.jpg", "report.pdf", "a.docx", "archive.zip"):
            with self.subTest(name=name):
                self.assertIsNone(self._item(name).type_warning)


class TestExportKeepsMarkOfTheWeb(unittest.TestCase):
    """An exported copy keeps Mark of the Web (shutil.copy2 dropped it on 3.11).

    The source has no stream, so copy2 cannot pass the test by carrying one, and
    PowerShell reads it back, not the code that wrote it.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="bruh-motw-"))
        self.quarantine_root = self.tmp / "quarantine"
        self.quarantine_root.mkdir()
        self.dest = self.tmp / "exported"
        self.dest.mkdir()
        self.source = self.quarantine_root / "report.pdf"
        self.source.write_bytes(b"%PDF-1.7 test")
        self.item = quarantine.QuarantinedFile(
            self.source, self.source.stat().st_size,
            session_manager.datetime.now(session_manager.timezone.utc))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _export(self):
        original = config.QUARANTINE
        config.QUARANTINE = self.quarantine_root
        try:
            return quarantine.export(self.item, self.dest)
        finally:
            config.QUARANTINE = original

    @staticmethod
    def _stream_as_windows_reads_it(path: Path) -> str:
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
             "Get-Content -LiteralPath $env:BRUH_MOTW_FILE "
             f"-Stream {config.ZONE_IDENTIFIER_STREAM} -ErrorAction Stop"],
            capture_output=True, text=True, timeout=60, shell=False,
            creationflags=config.NO_WINDOW,
            env={**os.environ, "BRUH_MOTW_FILE": str(path)})
        return proc.stdout if proc.returncode == 0 else ""

    def test_the_source_starts_without_a_mark(self):
        """Without this, the test below could pass on a copy2 that carried a stream."""
        self.assertEqual(self._stream_as_windows_reads_it(self.source), "")

    def test_export_writes_the_internet_zone(self):
        ok, message = self._export()
        self.assertTrue(ok, message)
        exported = self.dest / "report.pdf"
        stream = self._stream_as_windows_reads_it(exported)
        self.assertIn(f"ZoneId={config.ZONE_ID_INTERNET}", stream.splitlines())

    def test_a_one_letter_name_is_marked_too(self):
        """Path.with_name("a:Zone.Identifier") reads "a:" as a drive and raises
        ValueError, which escaped export() after the copy and left it unmarked."""
        self.source.rename(self.quarantine_root / "a")
        self.item = quarantine.QuarantinedFile(
            self.quarantine_root / "a", 1,
            session_manager.datetime.now(session_manager.timezone.utc))
        ok, message = self._export()
        self.assertTrue(ok, message)
        stream = self._stream_as_windows_reads_it(self.dest / "a")
        self.assertIn(f"ZoneId={config.ZONE_ID_INTERNET}", stream.splitlines())

    def test_export_is_refused_and_removed_when_the_mark_cannot_be_written(self):
        original = quarantine.mark_of_the_web
        quarantine.mark_of_the_web = lambda _path: False
        try:
            ok, message = self._export()
        finally:
            quarantine.mark_of_the_web = original
        self.assertFalse(ok)
        self.assertIn("Refused", message)
        self.assertEqual(list(self.dest.iterdir()), [],
                         "an unmarked copy was left in the user's folder")


class TestEdgeSignerIsComparedByField(unittest.TestCase):
    """The signer check was `"Microsoft Corporation" in subject`, a substring test."""

    # Read from Get-AuthenticodeSignature on msedge.exe, 2026-09-25.
    REAL_SUBJECT = ("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, "
                    "S=Washington, C=US")
    REAL_ISSUER = ("CN=Microsoft Code Signing PCA 2024, O=Microsoft Corporation, "
                   "C=US")

    def test_the_real_signer_is_accepted(self):
        self.assertTrue(edge.is_microsoft_signer(self.REAL_SUBJECT, self.REAL_ISSUER))

    def test_lookalike_signers_are_refused(self):
        lookalikes = [
            "CN=Not Microsoft Corporation Ltd, O=Microsoft Corporation, C=US",
            "CN=Microsoft Corporation Evil, O=Microsoft Corporation, C=US",
            "CN=Evil, O=Microsoft Corporation, C=US",
            "CN=Microsoft Corporation, O=Evil Ltd, C=US",
            'CN="Microsoft Corporation, O=Microsoft Corporation", O=Evil, C=US',
            "CN=Microsoft Corporation, CN=Evil, O=Microsoft Corporation, C=US",
            "",
        ]
        for subject in lookalikes:
            with self.subTest(subject=subject):
                self.assertFalse(edge.is_microsoft_signer(subject, self.REAL_ISSUER))

    def test_a_non_microsoft_issuer_is_refused(self):
        for issuer in ("CN=Microsoft Code Signing PCA 2024, O=Evil CA, C=US",
                       "CN=Evil CA, O=Microsoft Corporation Evil, C=US", ""):
            with self.subTest(issuer=issuer):
                self.assertFalse(edge.is_microsoft_signer(self.REAL_SUBJECT, issuer))

    def test_quoted_values_are_parsed_whole(self):
        fields = edge.dn_fields('CN=A, O="Contoso, ""The"" Ltd", C=US')
        self.assertEqual(fields["O"], ['Contoso, "The" Ltd'])
        self.assertEqual(fields["C"], ["US"])

    def test_the_installed_edge_passes_through_the_production_probe(self):
        """The fixtures above are one reading. This reads the signer the way
        verify_runtime does, so a format the parser cannot handle fails here."""
        edge_path = config.find_edge()
        if edge_path is None:
            self.skipTest("Microsoft Edge is not installed here")
        signature = [c for c in edge.verify_runtime(edge_path)
                     if c.check_id == "edge.signature"]
        self.assertEqual(len(signature), 1)
        self.assertIs(signature[0].verdict, Verdict.PASS, signature[0].evidence)


class TestProfileCollisionUsesPathAncestry(unittest.TestCase):
    """Ancestry, not str.startswith: a sibling with a prefix name blocked launch."""

    def setUp(self):
        self.edge = Path(config.os.environ["LOCALAPPDATA"]) / "Microsoft" / "Edge" / \
            "User Data"

    def test_sibling_with_a_prefix_name_is_not_a_collision(self):
        self.assertFalse(browser_guard._is_within(  # lint: allow protected-access
            Path(str(self.edge) + "-Evil"), self.edge))

    def test_the_directory_itself_is_a_collision(self):
        self.assertTrue(browser_guard._is_within(  # lint: allow protected-access
            self.edge, self.edge))

    def test_a_profile_inside_it_is_a_collision(self):
        self.assertTrue(browser_guard._is_within(  # lint: allow protected-access
            self.edge / "Default", self.edge))

    def test_windows_path_case_does_not_defeat_the_check(self):
        self.assertTrue(browser_guard._is_within(  # lint: allow protected-access
            Path(str(self.edge).upper()) / "Default", self.edge))

    def test_bruhswers_own_profile_is_not_a_collision(self):
        self.assertFalse(browser_guard._is_within(  # lint: allow protected-access
            config.PROFILE_PERSISTENT, self.edge))


class TestFailClosedSemantics(unittest.TestCase):
    """UNKNOWN is never a pass."""

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
    """A destroyed disposable session leaves no downloads. The quarantine once
    survived a "destroyed and verified gone" report."""

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
        self.assertIn("1 quarantined download", message)

    def test_sweep_removes_quarantine_orphaned_by_a_crash(self):
        """The crash path: profile gone, quarantine left behind."""
        session = session_manager.create(session_manager.DISPOSABLE)
        qdir = quarantine.quarantine_dir_for(session.session_id)
        (qdir / "orphan.txt").write_text("x", encoding="utf-8")

        shutil.rmtree(session.profile_dir, ignore_errors=True)
        self.assertTrue(qdir.is_dir(), "setup failed")

        session_manager.sweep_orphans()
        self.assertFalse(qdir.exists(), "orphaned quarantine survived the sweep")

    def test_sweep_refuses_to_delete_through_a_junction(self):
        """A junction named like a session id must not turn the sweep into a
        delete-anything. Skipped, not passed, if no junction can be made."""
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
        """No reserved pipe name or verb list for a control channel."""
        for name in ("PIPE_NAME", "ALLOWED_IPC_VERBS", "MAX_IPC_MESSAGE_BYTES"):
            self.assertFalse(hasattr(config, name),
                             f"config.{name} is back; bruhswer has no IPC channel")

    def test_cgnat_is_not_blocked(self):
        """100.64/10 carries some users' only path to the internet."""
        self.assertNotIn("100.64.0.0/10", config.BLOCKED_IPV4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
