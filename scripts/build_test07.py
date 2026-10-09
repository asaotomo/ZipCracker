#!/usr/bin/env python3
"""Build the CTF batch/CRC safety fixture; regeneration requires Info-ZIP."""
import argparse
import binascii
import io
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zipfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FLAG = b"flag{batch_crc32_safe_recovery}"
COLLISION_CONTENT = bytes.fromhex("6152515c2c")
OUTER_PASSWORD = "password"
COLLISION_PASSWORD = "123456"
SHARDS_PASSWORD = "CTF07-crc-only-a9f!"
FIXTURE_TIME = (2026, 10, 9, 12, 0, 0)


def plain_zip(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=FIXTURE_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            zf.writestr(info, data)
    return stream.getvalue()


def encrypted_zip(entries, password, work_dir, label):
    stage = work_dir / label
    stage.mkdir()
    names = []
    for name, data in entries:
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        names.append(name)
    target_zip = work_dir / (label + ".zip")
    subprocess.run(["zip", "-q", "-X", "-0", "-P", password,
                    str(target_zip), *names], cwd=stage, check=True)
    data = target_zip.read_bytes()
    # Validate the actual ciphertext and plaintext, not just metadata.
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name, expected in entries:
            assert zf.read(name, pwd=password.encode("ascii")) == expected
            assert zf.getinfo(name).flag_bits & 1
    return data


def pseudo_encrypt(data):
    result = bytearray(data)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        central_offset = zf.start_dir
    for info in infos:
        offset = info.header_offset + 6
        flags = struct.unpack_from("<H", result, offset)[0]
        struct.pack_into("<H", result, offset, flags | 1)
    cursor = central_offset
    for _ in infos:
        if result[cursor:cursor + 4] != b"PK\x01\x02":
            raise ValueError("Unexpected central-directory layout")
        flags = struct.unpack_from("<H", result, cursor + 8)[0]
        struct.pack_into("<H", result, cursor + 8, flags | 1)
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", result, cursor + 28)
        cursor += 46 + name_size + extra_size + comment_size
    return bytes(result)


def build(output):
    if not shutil.which("zip"):
        raise RuntimeError("Install Info-ZIP to regenerate this fixture")
    assert binascii.crc32(COLLISION_CONTENT) == binascii.crc32(b"00000") == 0x4ADC54F5
    with tempfile.TemporaryDirectory(prefix="zipcracker-build-test07-") as directory:
        work = Path(directory)
        shards = [("shards/%02d.txt" % (index // 4 + 1), FLAG[index:index + 4])
                  for index in range(0, len(FLAG), 4)]
        shard_zip = encrypted_zip(shards, SHARDS_PASSWORD, work, "crc_shards")
        collision_zip = encrypted_zip([("collision.txt", COLLISION_CONTENT)],
                                      COLLISION_PASSWORD, work, "crc_collision")
        note_zip = plain_zip([("checkpoint.txt", b"CTF07 checkpoint: clear archives should extract without prompts.\n")])
        hub_zip = plain_zip([
            ("01_crc_shards.zip", shard_zip),
            ("02_crc_collision.zip", collision_zip),
            ("03_clear_checkpoint.zip", note_zip),
        ])
        fake_zip = pseudo_encrypt(plain_zip([("stage2.zip", hub_zip)]))
        briefing = (
            b"CTF07: Batch recovery lab\n"
            b"A weak outer password protects a pseudo-encrypted wrapper and three inner branches.\n"
            b"Recover the numbered shards and concatenate them in filename order for the flag.\n"
            b"Do not trust a five-byte CRC32 match: checksum equality does not prove original content.\n"
            b"Suggested command: python3 ZipCracker.py test07.zip -r --batch\n"
            b"See docs/TEST07_CTF_SAMPLE.md for validation commands and expected outcomes.\n"
        )
        outer = encrypted_zip([("briefing.txt", briefing), ("stage1_pseudo.zip", fake_zip)],
                              OUTER_PASSWORD, work, "outer")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(outer)
        print("Created %s (%d bytes)" % (output, len(outer)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "test07.zip")
    build(parser.parse_args().output.resolve())
