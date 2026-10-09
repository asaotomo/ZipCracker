"""Independent CRC oracles, ZIP header variants and password-search failures."""
import binascii
import contextlib
import io
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import zipcracker_core as core


def legacy_archive(data, *, descriptor=False, check_override=None):
    """Reference STORE/ZipCrypto writer; zipfile is the independent reader."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zf:
        zf.writestr(zipfile.ZipInfo("payload.bin", (2026, 10, 9, 12, 0, 0)), data)
        info = zf.getinfo("payload.bin")
    original = stream.getvalue()
    with zipfile.ZipFile(io.BytesIO(original)) as zf:
        central_offset = zf.start_dir
    local = bytearray(original[:info.header_offset + 30 + len(info.filename)])
    central = bytearray(original[central_offset:-22])
    end = bytearray(original[-22:])
    flags = 9 if descriptor else 1
    struct.pack_into("<H", local, 6, flags)
    struct.pack_into("<H", central, 8, flags)
    struct.pack_into("<I", central, 20, len(data) + 12)
    local_sizes = (0, 0, 0) if descriptor else (info.CRC, len(data) + 12, len(data))
    struct.pack_into("<III", local, 14, *local_sizes)
    check = (struct.unpack_from("<H", local, 10)[0] >> 8) if descriptor else info.CRC >> 24
    if check_override is not None:
        check = check_override
    header = bytes(range(11)) + bytes((check,))
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(byte):
        keys[0] = binascii.crc32(bytes((byte,)), keys[0] ^ 0xFFFFFFFF) ^ 0xFFFFFFFF
        keys[1] = ((keys[1] + (keys[0] & 255)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = binascii.crc32(bytes((keys[1] >> 24,)), keys[2] ^ 0xFFFFFFFF) ^ 0xFFFFFFFF

    for byte in b"testpass":
        update(byte)
    encrypted = bytearray()
    for byte in header + data:
        key = keys[2] | 2
        encrypted.append(byte ^ (((key * (key ^ 1)) >> 8) & 255))
        update(byte)
    trailer = struct.pack("<4sIII", b"PK\x07\x08", info.CRC, len(data) + 12, len(data)) if descriptor else b""
    struct.pack_into("<I", end, 16, len(local) + len(encrypted) + len(trailer))
    return bytes(local) + bytes(encrypted) + trailer + bytes(central) + bytes(end)


class AlgorithmTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zipcracker-algorithms-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def verifier(self, data=b"verified payload", **kwargs):
        path = self.root / "sample.zip"
        path.write_bytes(legacy_archive(data, **kwargs))
        verifier = core.PasswordVerifier(str(path))
        self.addCleanup(verifier.close_thread_archive)
        return verifier

    def test_core_output_helpers_preserve_legacy_encoding(self):
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding="cp1252", errors="strict")
        self.addCleanup(stream.close)
        core.timestamped_print("[*] 中文", file=stream, flush=True)
        core.raw_print("中文", file=stream, flush=True)
        self.assertEqual(stream.encoding, "cp1252")
        self.assertEqual(buffer.getvalue().count(b"\\u4e2d\\u6587"), 2)

    def test_api_backup_publication_succeeds_with_legacy_stdout(self):
        destination = self.root / "out"
        destination.mkdir()
        (destination / "file.txt").write_bytes(b"old")
        stage = self.root / "staging"
        stage.mkdir()
        (stage / "file.txt").write_bytes(b"new")
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding="cp1252", errors="strict")
        self.addCleanup(stream.close)
        with mock.patch.object(core.sys, "stdout", stream):
            core.publish_extraction(str(stage), str(destination))
        stream.flush()
        self.assertIn(b"Previous output files backed up", buffer.getvalue())
        self.assertEqual((destination / "file.txt").read_bytes(), b"new")
        backups = list(self.root.glob("out_backup_*/file.txt"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"old")

    def test_crc_recovers_every_one_and_two_byte_message(self):
        for size in (1, 2):
            for value in range(1 << (8 * size)):
                raw = value.to_bytes(size, "little")
                self.assertEqual(core._short_crc_preimage(binascii.crc32(raw), size), raw)

    def test_crc_recovers_random_binary_three_and_four_byte_messages(self):
        rng = random.Random(23)
        for size in (3, 4):
            for _ in range(2000):
                raw = bytes(rng.randrange(256) for _ in range(size))
                self.assertEqual(core._short_crc_preimage(binascii.crc32(raw), size), raw)

    def test_crc_four_bytes_roundtrip_arbitrary_checksums(self):
        rng = random.Random(7)
        for _ in range(1000):
            crc = rng.getrandbits(32)
            raw = core._short_crc_preimage(crc, 4)
            self.assertEqual(len(raw), 4)
            self.assertEqual(binascii.crc32(raw), crc)

    def test_crc_rejects_impossible_short_metadata(self):
        for size in (1, 2, 3):
            self.assertIsNone(core._short_crc_preimage(0, size))

    def test_crc_inverse_supports_nonzero_initial_states(self):
        rng = random.Random(99)
        for size in range(1, 5):
            for _ in range(100):
                seed = rng.getrandbits(32)
                raw = bytes(rng.randrange(256) for _ in range(size))
                self.assertEqual(core._short_crc_preimage(binascii.crc32(raw, seed), size, seed), raw)

    def test_long_crc_candidates_are_bounded_printable_and_crc_valid(self):
        for raw in (b"hello", b"zzzzz", b"flag{}", b"zzzzzz"):
            budget = core.CrcBudget(max_candidates=10000)
            with contextlib.redirect_stdout(io.StringIO()):
                result = core.crack_crc("sample", binascii.crc32(raw), len(raw), "en", budget=budget)
            self.assertIsNotNone(result)
            self.assertEqual(len(result), len(raw))
            self.assertEqual(binascii.crc32(result), binascii.crc32(raw))
            self.assertTrue(all(byte in core.string.printable.encode("ascii") for byte in result))
            self.assertLessEqual(budget.attempted, 100 ** (len(raw) - 4))

    def test_binary_crc_recovers_real_encrypted_archive(self):
        raw = b"\x00\xff\x80\x01"
        verifier = self.verifier(raw)
        out = self.root / "out"
        with zipfile.ZipFile(verifier.zip_file) as zf, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(core.get_crc(verifier.zip_file, zf, "en", batch=True, out_dir=str(out)))
        self.assertEqual((out / "payload.bin").read_bytes(), raw)

    def test_header_filters_both_descriptor_and_crc_variants(self):
        for descriptor in (False, True):
            for use_pyzipper in (False, core.HAS_PYZIPPER):
                with self.subTest(descriptor=descriptor, pyzipper=use_pyzipper), mock.patch.object(core, "HAS_PYZIPPER", use_pyzipper):
                    verifier = self.verifier(descriptor=descriptor)
                    self.assertIsNotNone(verifier._zipcrypto_header)
                    self.assertFalse(verifier.verify_password("wrongpass"))
                    self.assertTrue(verifier.verify_password("testpass"))
                    verifier.close_thread_archive()

    def test_wrong_header_rejects_without_opening_archive(self):
        verifier = self.verifier()
        header, check = verifier._zipcrypto_header
        password = next("wrong%d" % i for i in range(100)
                        if core._ZipDecrypter(("wrong%d" % i).encode())(header)[11] != check)
        with mock.patch.object(verifier, "_open_archive", side_effect=AssertionError("archive opened")):
            self.assertFalse(verifier.verify_password(password))

    def test_header_collision_still_requires_full_crc_verification(self):
        verifier = self.verifier()
        header, check = verifier._zipcrypto_header
        password = next("wrong%d" % i for i in range(5000)
                        if core._ZipDecrypter(("wrong%d" % i).encode())(header)[11] == check)
        self.assertFalse(verifier.verify_password(password))

    def test_duplicate_name_verifies_actual_encrypted_entry(self):
        for use_pyzipper in (False, core.HAS_PYZIPPER):
            with mock.patch.object(core, "HAS_PYZIPPER", use_pyzipper):
                verifier = self.verifier(b"encrypted earlier entry")
                verifier.close_thread_archive()
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(verifier.zip_file, "a") as zf:
                        zf.writestr("payload.bin", b"clear final entry")
                verifier = core.PasswordVerifier(verifier.zip_file)
                self.addCleanup(verifier.close_thread_archive)
                self.assertFalse(verifier.verify_password("wrongpass"))
                self.assertTrue(verifier.verify_password("testpass"))
                verifier.extract("testpass", str(self.root / "out"))
                self.assertEqual((self.root / "out/payload.bin").read_bytes(), b"clear final entry")
                verifier.close_thread_archive()

    @unittest.skipUnless(core.HAS_PYZIPPER, "pyzipper is optional")
    def test_aes_duplicate_uses_backend_entry_object(self):
        path = self.root / "aes.zip"
        with core.pyzipper.AESZipFile(path, "w", encryption=core.pyzipper.WZ_AES) as zf:
            zf.setpassword(b"testpass")
            zf.writestr("payload.bin", b"AES original")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "a") as zf:
                zf.writestr("payload.bin", b"clear duplicate")
        verifier = core.PasswordVerifier(str(path))
        self.addCleanup(verifier.close_thread_archive)
        self.assertIsNone(verifier._zipcrypto_header)
        self.assertFalse(verifier.verify_password("wrongpass"))
        self.assertTrue(verifier.verify_password("testpass"))

    def test_surrogate_password_does_not_kill_worker(self):
        self.assertFalse(self.verifier().verify_password("\udcff"))

    def test_kpa_rejects_empty_and_wrong_length_plaintext(self):
        for cipher, plain in ((b"x" * 12, b""), (b"short", b"x"), (b"x" * 20, b"x")):
            self.assertFalse(core.zipcrypto_plaintext_matches_password("testpass", cipher, plain))
        with mock.patch.object(core, "iter_password_file_batches", side_effect=AssertionError("dictionary scanned")):
            self.assertIsNone(core.try_fast_password_from_plaintext(b"x" * 12, b""))

    def test_kpa_stops_after_first_mismatching_block(self):
        decrypt = mock.Mock(side_effect=lambda raw: b"!" * len(raw))
        with mock.patch.object(core, "_ZipDecrypter", return_value=decrypt):
            self.assertFalse(core.zipcrypto_plaintext_matches_password("wrong", b"z" * 100012, b"x" * 100000))
        self.assertEqual([len(call[0][0]) for call in decrypt.call_args_list], [12, 64])

    def test_kpa_checks_whole_matching_payload_and_zip_integrity(self):
        data = b"known plaintext " * 100
        verifier = self.verifier(data)
        cipher = core.read_zip_entry_ciphertext(verifier.zip_file, "payload.bin")
        self.assertTrue(core.zipcrypto_plaintext_matches_password("testpass", cipher, data))
        self.assertFalse(core.zipcrypto_plaintext_matches_password("testpass", cipher, data[:-1] + b"!"))
        # Correct payload with an invalid encrypted check byte must still fail.
        verifier = self.verifier(data, check_override=((binascii.crc32(data) >> 24) ^ 1))
        cipher = core.read_zip_entry_ciphertext(verifier.zip_file, "payload.bin")
        self.assertTrue(core.zipcrypto_plaintext_matches_password("testpass", cipher, data))
        verifier.kpa_ciphertext = cipher
        verifier.kpa_plaintext_bytes = data
        self.assertFalse(verifier.verify_password("testpass"))
        # A matching check byte and exact known plaintext still cannot bypass
        # a damaged CRC in the archive's metadata.
        damaged = bytearray(legacy_archive(data))
        with zipfile.ZipFile(io.BytesIO(damaged)) as zf:
            central_offset = zf.start_dir
        struct.pack_into("<I", damaged, 14, binascii.crc32(data) ^ 1)
        struct.pack_into("<I", damaged, central_offset + 16, binascii.crc32(data) ^ 1)
        path = self.root / "bad_crc.zip"
        path.write_bytes(damaged)
        verifier = core.PasswordVerifier(str(path),
                    kpa_ciphertext=core.read_zip_entry_ciphertext(str(path), "payload.bin"),
                    kpa_plaintext_bytes=data)
        self.addCleanup(verifier.close_thread_archive)
        self.assertFalse(verifier.verify_password("testpass"))

    def test_kpa_dictionary_resolves_outside_repository(self):
        old = os.getcwd()
        try:
            os.chdir(self.root)
            with mock.patch.object(core, "iter_password_file_batches", return_value=iter([["uncommon-test-password"]])) as batches, mock.patch.object(core, "zipcrypto_plaintext_matches_password", side_effect=lambda password, *_: password == "uncommon-test-password"):
                self.assertEqual(core.try_fast_password_from_plaintext(b"x" * 17, b"plain"), "uncommon-test-password")
            self.assertEqual(Path(batches.call_args[0][0]), REPO / "password_list.txt")
        finally:
            os.chdir(old)

    def test_worker_failure_and_producer_interrupt_do_not_hang(self):
        cases = {
            "worker": 'def verify_password(self, password): raise ValueError("worker failure")',
            "producer": 'def verify_password(self, password): time.sleep(0.01); return False',
        }
        for case, method in cases.items():
            code = '''import contextlib, io, time
import zipcracker_core as core
class Verifier:
 %s
 def close_thread_archive(self): pass
def batches():
 for _ in range(%d): yield ["wrong"] * 1000
 %s
try:
 with contextlib.redirect_stdout(io.StringIO()):
  core.run_parallel_passwords(Verifier(), batches(), 50000, "unused", "en", 1)
except %s as exc:
 assert str(exc) == %s
else:
 raise AssertionError("error was lost")
''' % (method, 50 if case == "worker" else 2,
       'raise KeyboardInterrupt("producer interrupt")' if case == "producer" else 'pass',
       'ValueError' if case == "worker" else 'KeyboardInterrupt',
       json.dumps("worker failure" if case == "worker" else "producer interrupt"))
            with self.subTest(case=case):
                result = subprocess.run([sys.executable, "-c", code], cwd=REPO,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
