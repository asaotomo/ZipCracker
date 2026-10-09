"""End-to-end validation of the bundled CTF batch/CRC fixture."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

REPO = Path(__file__).resolve().parents[1]
FLAG = b"flag{batch_crc32_safe_recovery}"
COLLISION_SOURCE = bytes.fromhex("6152515c2c")


class CtfSampleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zipcracker-test07-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sample = self.root / "test07.zip"
        self.sample.write_bytes((REPO / "test07.zip").read_bytes())
        self.original_hash = hashlib.sha256(self.sample.read_bytes()).digest()
        self.out = self.root / "out"
        self.env = dict(os.environ, ZIPCRACKER_AUTO_INSTALL_PYZIPPER="0",
                        ZIPCRACKER_AUTO_INSTALL_BKCRACK="0", ZIPCRACKER_THREADS="2",
                        ZIPCRACKER_SKIP_ORIG_PW_RECOVERY="1")

    def cli(self, *args, expected=0, script="ZipCracker.py"):
        result = subprocess.run(
            [sys.executable, str(REPO / script), str(self.sample), *map(str, args),
             "-r", "--batch", "-o", str(self.out)], cwd=self.root, env=self.env,
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertEqual(hashlib.sha256(self.sample.read_bytes()).digest(), self.original_hash)
        self.assertFalse(list(self.root.rglob(".zipcracker-extract-*")))
        return result

    def assert_flag(self):
        shards = sorted(self.out.rglob("shards/*.txt"))
        self.assertEqual(len(shards), 8)
        self.assertEqual(b"".join(path.read_bytes() for path in shards), FLAG)

    def assert_verified_collision(self):
        files = list(self.out.rglob("collision.txt"))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_bytes(), COLLISION_SOURCE)

    def test_default_batch_recovers_all_branches(self):
        self.cli()
        self.assert_flag()
        self.assert_verified_collision()
        self.assertFalse(list(self.out.rglob("*.zip")))
        checkpoints = list(self.out.rglob("checkpoint.txt"))
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(checkpoints[0].read_bytes(),
                         b"CTF07 checkpoint: clear archives should extract without prompts.\n")

    def test_explicit_dictionary_falls_back_to_crc_in_english_cli(self):
        self.cli(REPO / "test07_dict.txt", script="ZipCracker_en.py")
        self.assert_flag()
        self.assert_verified_collision()
        self.assertFalse(list(self.out.rglob("*.zip")))

    def test_wrong_dictionary_candidate_does_not_complete_or_delete_archive(self):
        dictionary = self.root / "outer_only.txt"
        dictionary.write_text("password\n", encoding="utf-8")
        self.cli(dictionary, "--crc-candidates", expected=1)
        self.assert_flag()
        candidates = list(self.out.rglob("*crc_candidates/collision.txt"))
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].read_bytes(), b"00000")
        self.assertEqual(list(self.out.rglob("collision.txt")), candidates)
        remaining = list(self.out.rglob("*.zip"))
        self.assertEqual([path.name for path in remaining], ["02_crc_collision.zip"])
        # The unresolved archive must remain intact and decrypt to the real source.
        with zipfile.ZipFile(remaining[0]) as zf:
            self.assertEqual(zf.read("collision.txt", pwd=b"123456"), COLLISION_SOURCE)

    def test_exhausted_crc_budget_preserves_shard_archive(self):
        self.cli(REPO / "test07_dict.txt", "--crc-max-candidates", "1", expected=1)
        self.assertFalse(list(self.out.rglob("shards/*.txt")))
        self.assert_verified_collision()
        self.assertEqual([path.name for path in self.out.rglob("*.zip")],
                         ["01_crc_shards.zip"])

    def test_keep_nested_archives_preserves_all_five_intermediates(self):
        self.cli("--keep-nested-zips")
        self.assert_flag()
        self.assert_verified_collision()
        self.assertEqual({path.name for path in self.out.rglob("*.zip")}, {
            "stage1_pseudo.zip", "stage2.zip", "01_crc_shards.zip",
            "02_crc_collision.zip", "03_clear_checkpoint.zip"})


if __name__ == "__main__":
    unittest.main()
