import contextlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zipcracker_core as core

REPO = Path(core.__file__).parent


def archive(entries, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return stream.getvalue()


class RecursiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zipcracker-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / "out"
        self.env = dict(os.environ, ZIPCRACKER_AUTO_INSTALL_PYZIPPER="0",
                        ZIPCRACKER_AUTO_INSTALL_BKCRACK="0", ZIPCRACKER_THREADS="2",
                        ZIPCRACKER_SKIP_ORIG_PW_RECOVERY="1")

    def run_cli(self, *args, script="ZipCracker.py", expected=0, timeout=60):
        result = subprocess.run([sys.executable, str(REPO / script), *map(str, args)],
                                cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=timeout)
        self.assertEqual(result.returncode, expected, result.stdout[-6000:])
        self.assertNotIn("Traceback", result.stdout)
        self.assertFalse(list(self.root.rglob(".zipcracker-extract-*")))
        return result

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def chain(self, levels=3):
        data = archive([("final.txt", b"complete nested archive output")])
        for i in range(levels - 1):
            data = archive([(f"level_{i}.zip", data)])
        return self.write("outer.zip", data)

    def legacy(self, target, password, *names):
        if not shutil.which("zip"):
            self.skipTest("Info-ZIP is not installed")
        subprocess.run(["zip", "-q", "-0", "-P", password, str(self.root / target), *names],
                       cwd=self.root, check=True)
        return self.root / target

    def dictionary(self, password="testpass"):
        return self.write("dict.txt", (password + "\n").encode())

    def test_plain_chain(self):
        original = self.chain()
        before = original.read_bytes()
        self.run_cli(original, "-r", "-o", self.out)
        self.assertEqual(len(list(self.out.rglob("final.txt"))), 1)
        self.assertFalse(list(self.out.rglob("*.zip")))
        self.assertEqual(original.read_bytes(), before)

    def test_1100_layers_use_flat_paths(self):
        original = self.chain(1100)
        self.run_cli(original, "-r", "-o", self.out)
        files = list(self.out.rglob("final.txt"))
        self.assertEqual(len(files), 1)
        self.assertLess(len(files[0].relative_to(self.out).parts), 4)

    def test_keep_archives(self):
        self.run_cli(self.chain(), "-r", "--keep-nested-zips", "-o", self.out)
        self.assertEqual(len(list(self.out.rglob("*.zip"))), 2)

    def test_depth_limit_returns_failure(self):
        self.run_cli(self.chain(), "-r", "--max-depth", "1", "-o", self.out, expected=1)
        self.assertEqual(len(list(self.out.rglob("*.zip"))), 1)
        self.assertFalse(list(self.out.rglob("final.txt")))

    def test_archive_count_includes_outer_archive(self):
        self.run_cli(self.chain(), "-r", "--max-archives", "1", "-o", self.out, expected=1)
        self.assertEqual(len(list(self.out.rglob("*.zip"))), 1)

    def test_total_size_limit_before_extraction(self):
        original = self.write("outer.zip", archive([("big.txt", b"x" * 2048)], zipfile.ZIP_DEFLATED))
        self.run_cli(original, "-r", "--max-total-size", "1KiB", "-o", self.out, expected=1)
        self.assertFalse(self.out.exists())
        self.assertTrue(original.exists())

    def test_total_size_limit_shared_by_layers(self):
        inner = archive([("big.txt", b"x" * 2000)], zipfile.ZIP_DEFLATED)
        original = self.write("outer.zip", archive([("inner.zip", inner)]))
        self.run_cli(original, "-r", "--max-total-size", str(len(inner) + 1999), "-o", self.out, expected=1)
        self.assertTrue((self.out / "inner.zip").exists())
        self.assertFalse(list(self.out.rglob("big.txt")))

    def test_empty_archive_does_not_scan_existing_output(self):
        stale = self.write("out/unrelated.zip", archive([("precious.txt", b"user data")]))
        before = stale.read_bytes()
        self.run_cli(self.write("empty.zip", archive([])), "-r", "-o", self.out)
        self.assertEqual(stale.read_bytes(), before)
        self.assertFalse(list(self.out.rglob("precious.txt")))

    def test_existing_files_are_backed_up_without_changing_output_paths(self):
        existing = self.write("out/final.txt", b"existing user data")
        self.run_cli(self.chain(1), "-r", "-o", self.out)
        self.assertEqual(existing.read_bytes(), b"complete nested archive output")
        backups = list(self.root.glob("out_backup_*/final.txt"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"existing user data")

    def test_input_inside_output_is_preserved(self):
        original = self.write("out/input.zip", archive([("final.txt", b"nested output")]))
        before = original.read_bytes()
        self.run_cli(original, "-r", "-o", self.out)
        self.assertEqual(original.read_bytes(), before)
        self.assertEqual(len(list(self.out.rglob("final.txt"))), 1)

    def test_dictionary_nested_and_stale_zip(self):
        self.write("inner.zip", archive([("final.txt", b"nested output")]))
        original = self.legacy("outer.zip", "testpass", "inner.zip")
        stale = self.write("out/unrelated.zip", archive([("precious.txt", b"user data")]))
        before = stale.read_bytes()
        self.run_cli(original, self.dictionary(), "-r", "-o", self.out)
        self.assertEqual(stale.read_bytes(), before)
        self.assertFalse(list(self.out.rglob("precious.txt")))
        self.assertEqual(len(list(self.out.rglob("final.txt"))), 1)

    def test_mask_nested(self):
        self.write("inner.zip", archive([("final.txt", b"nested output")]))
        original = self.legacy("outer.zip", "7", "inner.zip")
        self.run_cli(original, "-m", "?d", "-r", "-o", self.out)
        self.assertEqual(len(list(self.out.rglob("final.txt"))), 1)

    def test_partial_password_success_keeps_archive(self):
        self.write("small.txt", b"first password works")
        self.write("large.txt", b"second password is different " * 20)
        self.legacy("mixed.zip", "testpass", "small.txt")
        mixed = self.legacy("mixed.zip", "differentpass", "large.txt").read_bytes()
        original = self.write("outer.zip", archive([("mixed.zip", mixed)]))
        self.run_cli(original, self.dictionary(), "-r", "-o", self.out, expected=1)
        self.assertEqual((self.out / "mixed.zip").read_bytes(), mixed)
        self.assertFalse(list(self.out.rglob("small.txt")))
        self.assertFalse(list(self.out.rglob("large.txt")))

    def test_wrong_password_returns_failure(self):
        self.write("payload.txt", b"this nested archive must fail")
        encrypted = self.legacy("inner.zip", "testpass", "payload.txt").read_bytes()
        original = self.write("outer.zip", archive([("inner.zip", encrypted)]))
        self.run_cli(original, self.dictionary("wrongpass"), "-r", "-o", self.out, expected=1)
        self.assertEqual((self.out / "inner.zip").read_bytes(), encrypted)

    @unittest.skipUnless(core.HAS_PYZIPPER, "pyzipper is optional")
    def test_aes_nested(self):
        original = self.root / "outer.zip"
        with core.pyzipper.AESZipFile(original, "w", encryption=core.pyzipper.WZ_AES) as zf:
            zf.setpassword(b"testpass")
            zf.writestr("inner.zip", archive([("final.txt", b"AES nested output")]))
        self.run_cli(original, self.dictionary(), "-r", "-o", self.out)
        self.assertEqual(len(list(self.out.rglob("final.txt"))), 1)

    @unittest.skipUnless(core.HAS_PYZIPPER, "pyzipper is optional")
    def test_aes_partial_failure_keeps_archive(self):
        stream = io.BytesIO()
        with core.pyzipper.AESZipFile(stream, "w", encryption=core.pyzipper.WZ_AES) as zf:
            zf.setpassword(b"testpass")
            zf.writestr("small.txt", b"first password works")
            zf.setpassword(b"differentpass")
            zf.writestr("large.txt", b"second password is different " * 20)
        inner = stream.getvalue()
        original = self.write("outer.zip", archive([("mixed.zip", inner)]))
        self.run_cli(original, self.dictionary(), "-r", "-o", self.out, expected=1)
        self.assertEqual((self.out / "mixed.zip").read_bytes(), inner)
        self.assertFalse(list(self.out.rglob("small.txt")))

    def test_pseudo_encrypted_sample(self):
        original = self.write("pseudo.zip", (REPO / "test01.zip").read_bytes())
        self.run_cli(original, "-r", "-o", self.out)
        self.assertTrue(self.out.exists())
        self.assertTrue(list(self.out.rglob("*")))

    @unittest.skipUnless(shutil.which("bkcrack"), "bkcrack is optional")
    def test_known_plaintext_nested(self):
        plain = self.write("inner.zip", archive([("final.txt", b"known plaintext nested output")]))
        reference = self.write("reference.zip", archive([("inner.zip", plain.read_bytes())]))
        original = self.legacy("outer.zip", "testpass", "inner.zip")
        self.run_cli(original, "-kpa", reference, "--bkcrack", "-r", "-o", self.out)
        self.assertEqual(len(list(self.out.rglob("final.txt"))), 1)

    def test_backslash_paths_are_tracked_after_normalization(self):
        original = self.write("outer.zip", archive([("sub\\inner.zip", archive([("final.txt", b"normalized paths")]))]))
        self.run_cli(original, "-r", "-o", self.out)
        self.assertEqual(len(list(self.out.rglob("final.txt"))), 1)
        self.assertFalse(list(self.out.rglob("*.zip")))

    def test_uppercase_zip_in_subdirectory(self):
        original = self.write("outer.zip", archive([("sub/INNER.ZIP", archive([("final.txt", b"uppercase zip")]))]))
        self.run_cli(original, "-r", "-o", self.out)
        self.assertEqual(len(list(self.out.rglob("final.txt"))), 1)

    def test_corrupted_inner_zip_is_preserved(self):
        original = self.write("outer.zip", archive([("broken.zip", b"PK damaged archive")]))
        self.run_cli(original, "-r", "-o", self.out, expected=1)
        self.assertEqual((self.out / "broken.zip").read_bytes(), b"PK damaged archive")

    def test_crc_failure_does_not_publish_partial_output(self):
        data = bytearray(archive([("first.txt", b"first entry"), ("broken.txt", b"corrupted entry")]))
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            info = zf.getinfo("broken.txt")
            offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
        data[offset] ^= 1
        original = self.write("outer.zip", data)
        self.run_cli(original, "-r", "-o", self.out, expected=1)
        self.assertFalse(self.out.exists())
        self.assertTrue(original.exists())

    def test_unsafe_paths_rejected(self):
        for name in ("../escape.txt", "/absolute.txt", "C:/drive.txt", "..\\escape.txt", "a/../../escape.txt", "file:stream"):
            with self.subTest(name=name):
                original = self.write("unsafe.zip", archive([(name, b"unsafe")]))
                self.run_cli(original, "-r", "-o", self.out, expected=1)
                self.assertFalse(self.out.exists())

    def test_symlink_member_rejected(self):
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        original = self.write("unsafe.zip", archive([(info, b"../outside")]))
        self.run_cli(original, "-r", "-o", self.out, expected=1)
        self.assertFalse(self.out.exists())

    def test_duplicate_paths_keep_extractall_last_entry_behavior(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            original = self.write("duplicates.zip", archive([("same.txt", b"one"), ("same.txt", b"two")]))
        self.run_cli(original, "-r", "-o", self.out)
        self.assertEqual((self.out / "same.txt").read_bytes(), b"two")

    def test_file_directory_conflict_rejected(self):
        original = self.write("conflict.zip", archive([("dir", b"file"), ("dir/child.txt", b"child")]))
        self.run_cli(original, "-r", "-o", self.out, expected=1)
        self.assertFalse(self.out.exists())

    def test_bkcrack_fallback_validates_crc_and_tracks_names(self):
        original = self.write("plain.zip", archive([("sub/file.txt", b"fallback output")]))
        extraction = core.ExtractionContext()
        ok, names = core.extract_with_bkcrack_keys("unused", ("0", "0", "0"), str(original), str(self.out), "en", extraction_context=extraction)
        self.assertTrue(ok, names)
        self.assertEqual(extraction.names, ["sub/file.txt"])
        self.assertTrue(extraction.completed)
        self.assertEqual((self.out / "sub/file.txt").read_bytes(), b"fallback output")

    def test_no_manifest_never_scans_existing_output(self):
        stale = self.write("out/unrelated.zip", archive([("precious.txt", b"user data")]))
        with contextlib.redirect_stdout(io.StringIO()):
            summary = core.run_nested_extraction(str(self.out), str(self.out), "en", core.ZipCrackerOptions(recursive=True))
        self.assertTrue(summary.success)
        self.assertEqual(summary.processed, 0)
        self.assertTrue(stale.exists())

    def test_english_cli(self):
        self.run_cli(self.chain(), "-r", "-o", self.out, script="ZipCracker_en.py")
        self.assertEqual(len(list(self.out.rglob("final.txt"))), 1)

    def test_invalid_limits(self):
        for flag, value in (("--max-depth", "0"), ("--max-archives", "-1"), ("--max-total-size", "garbage"), ("--max-total-size", "0MiB")):
            with self.subTest(flag=flag, value=value):
                self.run_cli("missing.zip", "-r", flag, value, expected=1)


    def test_default_dictionary_from_other_working_directory(self):
        self.write("payload.txt", b"default dictionary from another directory")
        original = self.legacy("outer.zip", "123456", "payload.txt")
        self.run_cli(original, "-o", self.out)
        self.assertEqual((self.out / "payload.txt").read_bytes(), b"default dictionary from another directory")

    def test_user_dictionary_directory_and_streaming(self):
        self.write("payload.txt", b"directory dictionary streaming")
        original = self.legacy("outer.zip", "testpass", "payload.txt")
        self.write("dicts/01.txt", b"wrongpass\n")
        self.write("dicts/02.txt", b"testpass")
        self.env["ZIPCRACKER_SKIP_DICT_COUNT"] = "1"
        self.run_cli(original, "dicts", "-o", self.out)
        self.assertEqual((self.out / "payload.txt").read_bytes(), b"directory dictionary streaming")

    def test_numeric_fallback_with_local_dictionary_priority(self):
        self.write("payload.txt", b"numeric fallback stays available")
        original = self.legacy("outer.zip", "7", "payload.txt")
        self.write("password_list.txt", b"wrongpass\n")
        result = self.run_cli(original, "-o", self.out)
        self.assertIn("1-6", result.stdout)
        self.assertEqual((self.out / "payload.txt").read_bytes(), b"numeric fallback stays available")

    def test_kpa_password_verification_without_bkcrack(self):
        plain = self.write("payload.txt", b"known plaintext fast dictionary verification")
        original = self.legacy("outer.zip", "testpass", "payload.txt")
        options = core.ZipCrackerOptions(out_dir=str(self.out), kpa_plain_path=str(plain),
                                        dict_path_or_mask_flag=str(self.dictionary()), interactive=False)
        with mock.patch.object(core, "find_bkcrack_executable", return_value=None), mock.patch.object(core, "offer_bkcrack_install", return_value=None), contextlib.redirect_stdout(io.StringIO()):
            outcome = core.run_crack_pipeline(str(original), "en", options)
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.extracted_names, ["payload.txt"])
        self.assertEqual((self.out / "payload.txt").read_bytes(), plain.read_bytes())

    def test_crc_miss_does_not_report_success(self):
        original = self.write("short.zip", archive([("short.txt", b"\x00")]))
        with zipfile.ZipFile(original) as zf, mock.patch.object(core.sys.stdin, "isatty", return_value=True), mock.patch("builtins.input", return_value="y"), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(core.get_crc(str(original), zf, "en"))

    def test_crc_recovery_saves_files(self):
        original = self.write("short.zip", archive([("short.txt", b"a")]))
        extraction = core.ExtractionContext()
        with zipfile.ZipFile(original) as zf, mock.patch.object(core.sys.stdin, "isatty", return_value=True), mock.patch("builtins.input", return_value="y"), contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(core.get_crc(str(original), zf, "en", out_dir=str(self.out), extraction_context=extraction))
        self.assertEqual((self.out / "short.txt").read_bytes(), b"a")
        self.assertEqual(extraction.names, ["short.txt"])
        self.assertTrue(extraction.completed)

    def test_bkcrack_decompress_all_supported_methods(self):
        payload = b"verified compressed fallback " * 10000
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            with self.subTest(method=method):
                original = self.write("method.zip", archive([("data.txt", payload)], method))
                with zipfile.ZipFile(original) as zf:
                    info = zf.getinfo("data.txt")
                compressed = core.read_zip_entry_raw_data(str(original), "data.txt")
                self.assertEqual(core.decompress_zip_member_data(info, compressed), payload)

    @unittest.skipUnless(core.HAS_PYZIPPER, "pyzipper is optional")
    def test_missing_aes_dependency_does_not_scan_dictionary(self):
        original = self.root / "aes.zip"
        with core.pyzipper.AESZipFile(original, "w", encryption=core.pyzipper.WZ_AES) as zf:
            zf.setpassword(b"testpass")
            zf.writestr("payload.txt", b"AES dependency must be present")
        options = core.ZipCrackerOptions(out_dir=str(self.out), interactive=False)
        with mock.patch.object(core, "HAS_PYZIPPER", False), mock.patch.object(core, "crack_password_with_file") as attack, contextlib.redirect_stdout(io.StringIO()):
            outcome = core.run_crack_pipeline(str(original), "en", options)
        attack.assert_not_called()
        self.assertFalse(outcome.success)
        self.assertTrue(original.exists())

    def test_failed_output_merge_restores_old_files(self):
        self.write("out/a.txt", b"original A")
        self.write("out/b.txt", b"original B")
        stage = self.root / "stage"
        stage.mkdir()
        (stage / "a.txt").write_bytes(b"new A")
        (stage / "b.txt").write_bytes(b"new B")
        rename = os.rename

        def fail_second(source, target):
            if Path(source) == stage / "b.txt":
                raise OSError("simulated disk failure")
            return rename(source, target)

        with mock.patch.object(core.os, "rename", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "simulated disk failure"):
                core.publish_extraction(str(stage), str(self.out))
        self.assertEqual((self.out / "a.txt").read_bytes(), b"original A")
        self.assertEqual((self.out / "b.txt").read_bytes(), b"original B")

    def test_large_verification_streams_without_whole_file_read(self):
        self.write("large.txt", b"x" * (2 * core.STREAM_READ_CHUNK_SIZE))
        original = self.legacy("large.zip", "testpass", "large.txt")
        verifier = core.PasswordVerifier(str(original))
        self.addCleanup(verifier.close_thread_archive)
        with mock.patch.object(zipfile.ZipFile, "read", side_effect=AssertionError("whole-file read")):
            self.assertTrue(verifier.verify_password("testpass"))


if __name__ == "__main__":
    unittest.main()
