"""Batch recovery safety, scheduling and bounded computation regressions."""
import binascii
import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zipcracker_core as core
from test_recursive import archive

REPO = Path(core.__file__).parent
COLLISION_SOURCE = bytes.fromhex("6152515c2c")


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zipcracker-batch-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / "out"
        self.env = dict(os.environ, ZIPCRACKER_AUTO_INSTALL_PYZIPPER="0",
                        ZIPCRACKER_AUTO_INSTALL_BKCRACK="0", ZIPCRACKER_THREADS="2",
                        ZIPCRACKER_SKIP_ORIG_PW_RECOVERY="1")

    def cli(self, path, *args, expected=0, script="ZipCracker_en.py"):
        result = subprocess.run([sys.executable, str(REPO / script), str(path),
                                 *map(str, args), "-o", str(self.out)], cwd=self.root,
                                env=self.env, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertFalse(list(self.root.rglob(".zipcracker-extract-*")))
        return result

    def encrypted(self, content, name="payload.txt"):
        if not shutil.which("zip"):
            self.skipTest("Info-ZIP is optional")
        (self.root / name).write_bytes(content)
        path = self.root / "inner.zip"
        subprocess.run(["zip", "-q", "-0", "-P", "testpass", str(path), name],
                       cwd=self.root, check=True)
        return path

    def dictionary(self, password="testpass"):
        path = self.root / "dict.txt"
        path.write_text(password + "\n", encoding="utf-8")
        return path

    def metadata_zip(self, entries):
        """CRC unit tests need central-directory metadata, not a crypto writer."""
        zf = zipfile.ZipFile(io.BytesIO(archive(entries)))
        for info in zf.infolist():
            if not info.is_dir():
                info.flag_bits |= 1
        self.addCleanup(zf.close)
        return zf

    def test_batch_prompt_never_reads_input(self):
        with mock.patch("builtins.input", side_effect=AssertionError("input called")):
            self.assertTrue(core.prompt_yes_no("en", "?", "?", batch=True, batch_answer=True))
            self.assertFalse(core.prompt_yes_no("en", "?", "?", batch=True))

    def test_environment_precedes_batch_default(self):
        for value, expected in (("yes", True), ("off", False)):
            with mock.patch.dict(os.environ, {"ZIPCRACKER_TEST_PROMPT": value}):
                self.assertEqual(core.prompt_yes_no("en", "?", "?", batch=True,
                    batch_answer=not expected, env_name="ZIPCRACKER_TEST_PROMPT"), expected)

    def test_noninteractive_setting_overrides_tty(self):
        with mock.patch.object(core.sys.stdin, "isatty", return_value=True), mock.patch("builtins.input", side_effect=AssertionError):
            self.assertFalse(core.prompt_yes_no("en", "?", "?", interactive=False))

    def test_pyzipper_batch_skip_and_explicit_install(self):
        path = self.root / "plain.zip"
        path.write_bytes(archive([]))
        for value, should_install in (("", False), ("1", True)):
            with mock.patch.dict(os.environ, {core.PYZIPPER_AUTO_INSTALL_ENV: value}), mock.patch.object(core, "refresh_pyzipper_state", return_value=False), mock.patch.object(core, "get_pyzipper_version", return_value=None), mock.patch.object(core, "auto_install_pyzipper", return_value=(False, "test fixture")) as install, mock.patch("builtins.input", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(core.offer_pyzipper_install("en", str(path), batch=True))
                self.assertEqual(install.called, should_install)

    def test_bkcrack_batch_skip_and_explicit_install(self):
        for value, should_install in (("", False), ("1", True)):
            with mock.patch.dict(os.environ, {core.BKCRACK_AUTO_INSTALL_ENV: value}), mock.patch.object(core, "find_bkcrack_executable", return_value=None), mock.patch.object(core.shutil, "which", return_value=None), mock.patch.object(core, "_find_bkcrack_in_tree", return_value=None), mock.patch.object(core, "bkcrack_auto_install_mode", return_value="release"), mock.patch.object(core, "_install_bkcrack_from_release", return_value=(False, "test fixture")) as install, mock.patch("builtins.input", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()):
                self.assertIsNone(core.offer_bkcrack_install("en", required=True, batch=True))
                self.assertEqual(install.called, should_install)

    def test_batch_long_crc_is_skipped(self):
        zf = self.metadata_zip([("payload.txt", COLLISION_SOURCE)])
        with mock.patch.object(core, "crack_crc") as crc, contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(core.get_crc("unused", zf, "en", batch=True))
        crc.assert_not_called()

    def test_crc_collision_only_publishes_separate_candidate(self):
        self.assertEqual(binascii.crc32(COLLISION_SOURCE), binascii.crc32(b"00000"))
        zf = self.metadata_zip([("sub/payload.txt", COLLISION_SOURCE)])
        context = core.ExtractionContext()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(core.get_crc("unused", zf, "en", batch=True, allow_candidates=True,
                                         out_dir=str(self.out), extraction_context=context))
        self.assertFalse(context.completed)
        self.assertEqual(context.names, [])
        self.assertFalse(self.out.exists())
        self.assertEqual((self.root / "out_crc_candidates/sub/payload.txt").read_bytes(), b"00000")

    def test_crc_candidate_preserves_previous_candidate_output(self):
        previous = self.root / "out_crc_candidates/payload.txt"
        previous.parent.mkdir()
        previous.write_bytes(b"previous user output")
        zf = self.metadata_zip([("payload.txt", COLLISION_SOURCE)])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(core.get_crc("unused", zf, "en", batch=True, allow_candidates=True, out_dir=str(self.out)))
        backups = list(self.root.glob("out_crc_candidates_backup_*/payload.txt"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"previous user output")

    def test_short_recovery_via_options_without_global_state(self):
        path = self.encrypted(b"a")
        options = core.ZipCrackerOptions(batch=True, interactive=False, out_dir=str(self.out))
        with mock.patch("builtins.input", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()):
            outcome = core.run_crack_pipeline(str(path), "en", options)
        self.assertTrue(outcome.success)
        self.assertTrue(outcome.extracted)
        self.assertEqual((self.out / "payload.txt").read_bytes(), b"a")

    def test_batch_does_not_leak_into_next_call(self):
        zf = self.metadata_zip([("payload.txt", b"a")])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(core.get_crc("unused", zf, "en", batch=True, interactive=False))
            self.assertFalse(core.get_crc("unused", zf, "en", batch=False, interactive=False))

    def test_crc_candidate_budget_stops_exactly(self):
        budget = core.CrcBudget(max_candidates=3, timeout=5)
        with mock.patch.object(core, "_short_crc_preimage", wraps=core._short_crc_preimage) as solve, contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(core.crack_crc("payload", binascii.crc32(b"zzzzz"), 5, "en", budget=budget))
        self.assertEqual(budget.attempted, 3)
        self.assertEqual(solve.call_count, 3)

    def test_crc_time_budget_stops_before_computation(self):
        with mock.patch.object(core.time, "monotonic", side_effect=[0.0, 2.0]), mock.patch.object(core.binascii, "crc32") as crc, contextlib.redirect_stdout(io.StringIO()):
            budget = core.CrcBudget(timeout=1)
            self.assertIsNone(core.crack_crc("payload", 1234, 6, "en", budget=budget))
        crc.assert_not_called()

    def test_crc_budget_shared_across_members(self):
        zf = self.metadata_zip([("first", b"1"), ("second", b"2")])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(core.get_crc("unused", zf, "en", batch=True, max_candidates=1, out_dir=str(self.out)))
        self.assertFalse(self.out.exists())

    def test_inverse_crc_recovers_full_printable_range(self):
        for raw in (b"zzz", b"zzzz", b"1234", b"flag", b"\\\t\r\n", b"~! @"):
            with self.subTest(raw=raw), contextlib.redirect_stdout(io.StringIO()):
                budget = core.CrcBudget(max_candidates=1)
                self.assertEqual(core.crack_crc("payload", binascii.crc32(raw), len(raw), "en", budget=budget), raw)
                self.assertEqual(budget.attempted, 1)

    def test_inverse_crc_recovers_nonprintable_preimage(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(core.crack_crc("payload", binascii.crc32(b"\xff" * 4), 4, "en"), b"\xff" * 4)

    def test_inverse_crc_obeys_exhausted_budget(self):
        budget = core.CrcBudget(max_candidates=5)
        for _ in range(5):
            self.assertTrue(budget.take())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(core.crack_crc("payload", binascii.crc32(b"0000"), 4, "en", budget=budget))
        self.assertEqual(budget.attempted, 5)

    def test_bundled_four_byte_crc_sample(self):
        sample = self.root / "sample.zip"
        sample.write_bytes((REPO / "test03.zip").read_bytes())
        self.cli(sample, "--batch")
        recovered = (self.out / "key.txt").read_bytes()
        with zipfile.ZipFile(sample) as zf:
            self.assertEqual(len(recovered), zf.getinfo("key.txt").file_size)
            self.assertEqual(binascii.crc32(recovered), zf.getinfo("key.txt").CRC)

    def test_crc_budget_excludes_time_waiting_for_user(self):
        zf = self.metadata_zip([("first", b"1"), ("second", b"zz")])
        clock = [0.0]

        def consent(*args, **kwargs):
            clock[0] += 10.0
            return True

        with mock.patch.object(core.sys.stdin, "isatty", return_value=True), mock.patch.object(core.time, "monotonic", side_effect=lambda: clock[0]), mock.patch.object(core, "prompt_yes_no", side_effect=consent), contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(core.get_crc("unused", zf, "en", timeout=5, out_dir=str(self.out)))
        self.assertEqual((self.out / "second").read_bytes(), b"zz")

    def test_candidate_destination_preserves_input_inside_it(self):
        candidate_root = self.root / "out_crc_candidates"
        candidate_root.mkdir()
        source = candidate_root / "payload.zip"
        source.write_bytes(archive([("payload.zip", COLLISION_SOURCE)]))
        before = source.read_bytes()
        zf = self.metadata_zip([("payload.zip", COLLISION_SOURCE)])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(core.get_crc(str(source), zf, "en", batch=True, allow_candidates=True, out_dir=str(self.out)))
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual((candidate_root / "payload_extracted/payload.zip").read_bytes(), b"00000")

    def test_clear_member_is_read_without_enumeration(self):
        zf = self.metadata_zip([("encrypted", b"a"), ("clear", b"\x00")])
        zf.getinfo("clear").flag_bits &= ~1
        with mock.patch.object(core, "crack_crc", wraps=core.crack_crc) as crc, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(core.get_crc("unused", zf, "en", batch=True, out_dir=str(self.out)))
        self.assertEqual(crc.call_count, 1)
        self.assertEqual((self.out / "clear").read_bytes(), b"\x00")

    def test_crc_skips_aes_metadata(self):
        zf = self.metadata_zip([("aes.txt", b"a")])
        zf.getinfo("aes.txt").extra = bytes.fromhex("0199070002004145030000")
        with mock.patch.object(core, "crack_crc") as crc, contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(core.get_crc("unused", zf, "en", batch=True))
        crc.assert_not_called()

    def test_crc_duplicate_members_keep_final_content(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            zf = self.metadata_zip([("same", b"a"), ("same", b"bb")])
        context = core.ExtractionContext(budget=core.ExtractionBudget(3))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(core.get_crc("unused", zf, "en", batch=True, out_dir=str(self.out), extraction_context=context))
        self.assertEqual((self.out / "same").read_bytes(), b"bb")
        self.assertEqual(context.budget.written_bytes, 2)

    def test_crc_unsafe_path_rejected_before_computation(self):
        zf = self.metadata_zip([("../escape.txt", b"a")])
        with mock.patch.object(core, "crack_crc") as crc:
            with self.assertRaises(ValueError):
                core.get_crc("unused", zf, "en", batch=True, out_dir=str(self.out))
        crc.assert_not_called()

    def test_correct_dictionary_precedes_crc_collision(self):
        path = self.encrypted(COLLISION_SOURCE)
        self.cli(path, self.dictionary(), "--batch", "--crc-candidates")
        self.assertEqual((self.out / "payload.txt").read_bytes(), COLLISION_SOURCE)
        self.assertFalse((self.root / "out_crc_candidates").exists())

    def test_correct_dictionary_precedes_six_byte_crc(self):
        path = self.encrypted(b"\xff" * 6)
        self.cli(path, self.dictionary(), "--batch", "--crc-candidates")
        self.assertEqual((self.out / "payload.txt").read_bytes(), b"\xff" * 6)

    def test_correct_mask_precedes_crc_collision(self):
        path = self.encrypted(COLLISION_SOURCE)
        self.cli(path, "-m", "testpass", "--batch", "--crc-candidates")
        self.assertEqual((self.out / "payload.txt").read_bytes(), COLLISION_SOURCE)

    def test_wrong_dictionary_keeps_inner_collision_archive(self):
        inner = self.encrypted(COLLISION_SOURCE)
        outer = self.root / "outer.zip"
        outer.write_bytes(archive([("inner.zip", inner.read_bytes())]))
        self.cli(outer, self.dictionary("wrongpass"), "-r", "--batch", "--crc-candidates", expected=1)
        self.assertEqual((self.out / "inner.zip").read_bytes(), inner.read_bytes())
        self.assertFalse((self.out / "nested_0001_inner").exists())
        candidate = list(self.out.glob("nested_*_crc_candidates/payload.txt"))
        self.assertEqual(len(candidate), 1)
        self.assertEqual(candidate[0].read_bytes(), b"00000")
        self.assertTrue(outer.exists())

    def test_wrong_dictionary_can_fall_back_to_short_crc(self):
        inner = self.encrypted(b"a")
        self.cli(inner, self.dictionary("wrongpass"), "--batch")
        self.assertEqual((self.out / "payload.txt").read_bytes(), b"a")

    def test_batch_recursive_short_crc_and_chinese_entry(self):
        inner = self.encrypted(b"a")
        outer = self.root / "outer.zip"
        outer.write_bytes(archive([("inner.zip", inner.read_bytes())]))
        self.cli(outer, "-r", "--batch", script="ZipCracker.py")
        self.assertEqual(next(self.out.rglob("payload.txt")).read_bytes(), b"a")
        self.assertFalse(list(self.out.rglob("*.zip")))
        self.assertTrue(outer.exists())

    def test_batch_oversized_mask_never_starts_crc_or_passwords(self):
        path = self.encrypted(COLLISION_SOURCE)
        options = core.ZipCrackerOptions(batch=True, dict_path_or_mask_flag="-m", mask_value="?d" * 12, out_dir=str(self.out))
        with mock.patch.object(core, "get_crc") as crc, mock.patch.object(core, "run_parallel_passwords") as passwords, mock.patch("builtins.input", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()):
            outcome = core.run_crack_pipeline(str(path), "en", options)
        self.assertFalse(outcome.success)
        crc.assert_not_called()
        passwords.assert_not_called()

    def test_batch_nested_template_fallback_reached(self):
        path = self.encrypted(bytes.fromhex("89504e470d0a1a0a0000000d49484452") + b"x" * 64, "image.png")
        options = core.build_nested_options(core.ZipCrackerOptions(batch=True, out_dir=str(self.out)))
        self.assertTrue(core.detect_template_kpa_suggestions(str(path), "en"))
        with mock.patch.object(core, "crack_password_with_file", return_value=False), mock.patch.object(core, "crack_with_generated_numeric_dict", return_value=False), mock.patch.object(core, "offer_template_kpa_after_standard_failures", return_value=False) as template, contextlib.redirect_stdout(io.StringIO()):
            core.run_crack_pipeline(str(path), "en", options)
        self.assertTrue(template.called)
        self.assertTrue(template.call_args[1]["batch"])
        self.assertFalse(template.call_args[1]["interactive"])

    def test_explicit_dictionary_does_not_enable_nested_template_fallback(self):
        options = core.ZipCrackerOptions(batch=True, dict_path_or_mask_flag="dict.txt", kpa_plain_path="outer.txt")
        nested = core.build_nested_options(options)
        self.assertFalse(nested.basic_default_mode)
        self.assertIsNone(nested.kpa_plain_path)
        self.assertTrue(nested.batch)

    def test_template_attempts_share_deadline(self):
        attempts = [core.KnownPlaintextAttempt("image.png", None) for _ in range(3)]
        with mock.patch.object(core.time, "monotonic", side_effect=[1.0, 2.0, 5.0]), mock.patch.object(core, "run_bkcrack_known_plaintext_attack", return_value=False) as attack, contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(core.run_bkcrack_known_plaintext_attempts("unused", attempts, str(self.out), "en", "bk", deadline=4.0))
        self.assertEqual(attack.call_count, 2)
        self.assertEqual([call[1]["attack_timeout"] for call in attack.call_args_list], [3.0, 2.0])

    def test_template_timeout_keeps_original_and_cleans_log(self):
        before = set(Path(tempfile.gettempdir()).glob("zipcracker_bkcrack_*.log"))
        with mock.patch.object(core.subprocess, "run", side_effect=subprocess.TimeoutExpired("bk", 1)), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(core.run_bkcrack_known_plaintext_attack("unused", "image.png", "", str(self.out), "en", "bk", extra_specs=[(0, b"known plaintext")], attack_timeout=1))
        self.assertEqual(set(Path(tempfile.gettempdir()).glob("zipcracker_bkcrack_*.log")), before)
        self.assertFalse(self.out.exists())

    def test_invalid_cli_budgets(self):
        for flag, value in (("--crc-max-candidates", "0"), ("--crc-max-candidates", "1.5"),
                            ("--crc-timeout", "0"), ("--crc-timeout", "nan"),
                            ("--template-timeout", "inf"), ("--template-timeout", "-1")):
            with self.subTest(flag=flag, value=value):
                self.cli("missing.zip", "--batch", flag, value, expected=1)

    def test_help_documents_batch_budgets(self):
        result = subprocess.run([sys.executable, str(REPO / "ZipCracker_en.py"), "--help"], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        for flag in ("--batch", "--crc-candidates", "--crc-max-candidates", "--crc-timeout", "--template-timeout"):
            self.assertIn(flag, result.stdout)


if __name__ == "__main__":
    unittest.main()
