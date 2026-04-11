#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import binascii
import builtins
import bz2
import copy
import hashlib
import importlib
import itertools as its
import json
import multiprocessing
import os
import platform
import queue
import re
import shlex
import shutil
import ssl
import string
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
import lzma
import zlib
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Optional, Sequence, Tuple
from zipfile import _ZipDecrypter

try:
    from importlib import metadata as importlib_metadata
except ImportError:
    try:
        import importlib_metadata
    except ImportError:
        importlib_metadata = None

try:
    import pyzipper

    HAS_PYZIPPER = True
except ImportError:
    pyzipper = None
    HAS_PYZIPPER = False

CHARSET_DIGITS = string.digits
CHARSET_LOWER = string.ascii_lowercase
CHARSET_UPPER = string.ascii_uppercase
CHARSET_SYMBOLS = string.punctuation
OUT_DIR_DEFAULT = "unzipped_files"
ZIPCRACKER_VERSION = "2.1.0"
BKCRACK_REPO_URL = "https://github.com/kimci86/bkcrack"
BKCRACK_RELEASES_API = "https://api.github.com/repos/kimci86/bkcrack/releases/latest"
MSVC_REDIST_URL = "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist"
MSVC_REDIST_X86_URL = "https://aka.ms/vc14/vc_redist.x86.exe"
MSVC_REDIST_X64_URL = "https://aka.ms/vc14/vc_redist.x64.exe"
MSVC_REDIST_ARM64_URL = "https://aka.ms/vc14/vc_redist.arm64.exe"
BKCRACK_AUTO_INSTALL_ENV = "ZIPCRACKER_AUTO_INSTALL_BKCRACK"
BKCRACK_SKIP_ORIG_PW_RECOVERY_ENV = "ZIPCRACKER_SKIP_ORIG_PW_RECOVERY"
ZIPCRACKER_SKIP_DICT_COUNT_ENV = "ZIPCRACKER_SKIP_DICT_COUNT"
PYZIPPER_AUTO_INSTALL_ENV = "ZIPCRACKER_AUTO_INSTALL_PYZIPPER"
STREAM_READ_CHUNK_SIZE = 1024 * 1024
PYPI_TUNA_SIMPLE_URL = "https://pypi.tuna.tsinghua.edu.cn/simple"
LOG_TIME_FORMAT = "%H:%M:%S"
LOG_PREFIX_MARKERS = ("[+]", "[*]", "[!]", "[-]", "[?]")

COMMON_EXTRA_PASSWORDS = (
    "password",
    "123456",
    "12345678",
    "qwerty",
    "secret",
    "admin",
    "root",
    "666666",
    "111111",
    "5211314",
    "password123",
    "P@ssw0rd",
    "iloveyou",
)

KPA_TEMPLATE_CHOICES = ("png", "zip", "exe", "pcapng")
KPA_TEMPLATE_ALIASES = {
    "pe": "exe",
    "windows-exe": "exe",
}
KPA_TEMPLATE_ENTRY_EXTENSIONS = {
    "png": (".png",),
    "zip": (".zip",),
    "exe": (".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl"),
    "pcapng": (".pcapng",),
}
AUTO_TEMPLATE_CANDIDATE_NAMES = {
    "png": {"png-header", "png-rgb-idat", "png-rgba-idat", "png-gray-idat"},
    "pcapng": {"pcapng-shb"},
    "exe": {"exe-dos-stub", "exe-dos-stub-pe80"},
    "zip": set(),
}


@dataclass
class KnownPlaintextTemplate:
    name: str
    plain_offset: int
    plaintext_bytes: bytes
    extra_specs: list[tuple[int, bytes]] = field(default_factory=list)


@dataclass
class KnownPlaintextAttempt:
    inner_name: str
    plain_source: Optional[dict]
    plain_offset: int = 0
    extra_specs: list[tuple[int, bytes]] = field(default_factory=list)
    label: str = ""
    cleanup_paths: list[str] = field(default_factory=list)
    template_name: Optional[str] = None


@dataclass
class TemplateKpaSuggestion:
    inner_name: str
    template_name: str
    file_size: int
    compress_type: int
    confidence: str = "high"
    reason: str = ""


def loc(locale: str, zh: str, en: str) -> str:
    return en if locale == "en" else zh


def current_log_timestamp() -> str:
    return time.strftime(LOG_TIME_FORMAT, time.localtime())


def prefix_output_lines(text: str, *, timestamp: Optional[str] = None) -> str:
    if not text:
        return text
    prefix = f"[{timestamp or current_log_timestamp()}] "
    parts = text.splitlines(True)
    if not parts:
        return prefix + text
    rendered: list[str] = []
    for part in parts:
        if part in ("\n", "\r\n", "\r"):
            rendered.append(part)
            continue
        if part.lstrip().startswith(LOG_PREFIX_MARKERS):
            rendered.append(prefix + part)
        else:
            rendered.append(part)
    if not text.endswith(("\n", "\r")) and parts and parts[-1] == "":
        rendered.append(prefix)
    return "".join(rendered)


def timestamped_prompt(text: str) -> str:
    return prefix_output_lines(text)


def timestamped_print(*args, **kwargs) -> None:
    sep = kwargs.pop("sep", " ")
    end = kwargs.pop("end", "\n")
    file = kwargs.pop("file", sys.stdout)
    flush = kwargs.pop("flush", False)
    text = sep.join(str(arg) for arg in args) + end
    builtins.print(
        prefix_output_lines(text),
        end="",
        file=file,
        flush=flush,
        **kwargs,
    )


def raw_print(*args, **kwargs) -> None:
    builtins.print(*args, **kwargs)


print = timestamped_print


def normalize_password_line(line: str) -> str:
    return line.rstrip("\r\n")


def normalize_kpa_template_name(name: str) -> str:
    normalized = name.strip().lower()
    return KPA_TEMPLATE_ALIASES.get(normalized, normalized)


def parse_kpa_offset(value: str, locale: str) -> int:
    try:
        offset = int(value, 0)
    except ValueError as exc:
        raise ValueError(
            loc(
                locale,
                f"KPA 偏移量无效: {value}",
                f"Invalid KPA offset: {value}",
            )
        ) from exc
    if offset < 0:
        raise ValueError(
            loc(
                locale,
                f"KPA 偏移量不能为负数: {value}",
                f"KPA offset cannot be negative: {value}",
            )
        )
    return offset


def parse_kpa_extra_spec(offset_text: str, hex_text: str, locale: str) -> tuple[int, bytes]:
    offset = parse_kpa_offset(offset_text, locale)
    normalized = re.sub(r"\s+", "", hex_text)
    if normalized.lower().startswith("0x"):
        normalized = normalized[2:]
    if not normalized:
        raise ValueError(
            loc(
                locale,
                "KPA 附加字节不能为空。",
                "KPA extra bytes cannot be empty.",
            )
        )
    if len(normalized) % 2 != 0:
        raise ValueError(
            loc(
                locale,
                f"KPA 附加字节必须是偶数个十六进制字符: {hex_text}",
                f"KPA extra bytes must contain an even number of hex characters: {hex_text}",
            )
        )
    try:
        return offset, bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(
            loc(
                locale,
                f"KPA 附加字节不是合法十六进制: {hex_text}",
                f"KPA extra bytes are not valid hexadecimal: {hex_text}",
            )
        ) from exc


def format_hex_bytes(data: bytes, *, limit: int = 16) -> str:
    text = data.hex()
    if len(data) <= limit:
        return text
    return f"{text[: limit * 2]}..."


def merge_known_plaintext_ranges(
    plain_offset: int,
    plain_length: int,
    extra_specs: Sequence[tuple[int, bytes]],
) -> tuple[int, int]:
    ranges: list[tuple[int, int]] = []
    if plain_length > 0:
        ranges.append((plain_offset, plain_offset + plain_length))
    for extra_offset, extra_bytes in extra_specs:
        if extra_bytes:
            ranges.append((extra_offset, extra_offset + len(extra_bytes)))
    if not ranges:
        return 0, 0
    ranges.sort()
    merged: list[list[int]] = []
    for start, end in ranges:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    total_known = sum(end - start for start, end in merged)
    max_contiguous = max(end - start for start, end in merged)
    return total_known, max_contiguous


def write_temp_known_plaintext_fragment(data: bytes, suffix: str = ".bin") -> str:
    fd, path = tempfile.mkstemp(prefix="zipcracker_kpa_", suffix=suffix)
    os.close(fd)
    with open(path, "wb") as fp:
        fp.write(data)
    return path


def refresh_pyzipper_state() -> bool:
    global pyzipper, HAS_PYZIPPER
    try:
        pyzipper = importlib.import_module("pyzipper")
        HAS_PYZIPPER = True
        return True
    except ImportError:
        pyzipper = None
        HAS_PYZIPPER = False
        return False


def get_pyzipper_version() -> Optional[str]:
    if importlib_metadata is None:
        return None
    try:
        return importlib_metadata.version("pyzipper")
    except Exception as exc:
        package_not_found = getattr(importlib_metadata, "PackageNotFoundError", None)
        if package_not_found and isinstance(exc, package_not_found):
            return None
        return None


def sha256_file(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _http_get_json(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"ZipCracker/{ZIPCRACKER_VERSION}",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        if platform.system() == "Windows" and is_ssl_cert_verify_error(exc):
            return json.loads(
                _windows_fetch_url_text(
                    url,
                    accept_header="application/vnd.github+json",
                )
            )
        raise


def _http_download_file(url: str, dest_path: str) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": f"ZipCracker/{ZIPCRACKER_VERSION}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response, open(
            dest_path, "wb"
        ) as output:
            shutil.copyfileobj(response, output)
    except urllib.error.URLError as exc:
        if platform.system() == "Windows" and is_ssl_cert_verify_error(exc):
            _windows_download_file(url, dest_path)
            return
        raise


def is_ssl_cert_verify_error(exc: BaseException) -> bool:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return True
    reason = getattr(exc, "reason", None)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return True
    detail = f"{exc}\n{reason or ''}".lower()
    return "certificate verify failed" in detail or "certificate_verify_failed" in detail


def _windows_curl_executable() -> Optional[str]:
    for name in ("curl.exe", "curl"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _windows_fetch_url_text(url: str, *, accept_header: str = "") -> str:
    curl_exe = _windows_curl_executable()
    if curl_exe:
        cmd = [
            curl_exe,
            "-fsSL",
            "--retry",
            "2",
            "--connect-timeout",
            "20",
            "-H",
            f"User-Agent: ZipCracker/{ZIPCRACKER_VERSION}",
        ]
        if accept_header:
            cmd.extend(["-H", f"Accept: {accept_header}"])
        cmd.append(url)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if proc.returncode == 0:
            return proc.stdout

    powershell = shutil.which("powershell") or shutil.which("powershell.exe")
    if not powershell:
        raise urllib.error.URLError(
            "Windows HTTPS fallback is unavailable because neither curl.exe nor PowerShell was found."
        )

    ps_script = [
        "$ProgressPreference='SilentlyContinue'",
        "$headers=@{'User-Agent'='ZipCracker/%s'}" % ZIPCRACKER_VERSION,
    ]
    if accept_header:
        ps_script.append("$headers['Accept']='%s'" % accept_header)
    ps_script.append("(Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri '%s').Content" % url.replace("'", "''"))
    proc = subprocess.run(
        [powershell, "-NoProfile", "-Command", "; ".join(ps_script)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if proc.returncode != 0:
        raise urllib.error.URLError((proc.stderr or proc.stdout or "").strip())
    return proc.stdout


def _windows_download_file(url: str, dest_path: str) -> None:
    curl_exe = _windows_curl_executable()
    if curl_exe:
        proc = subprocess.run(
            [
                curl_exe,
                "-fL",
                "--retry",
                "2",
                "--connect-timeout",
                "20",
                "-H",
                f"User-Agent: ZipCracker/{ZIPCRACKER_VERSION}",
                "-o",
                dest_path,
                url,
            ],
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if proc.returncode == 0:
            return

    powershell = shutil.which("powershell") or shutil.which("powershell.exe")
    if not powershell:
        raise urllib.error.URLError(
            "Windows HTTPS fallback is unavailable because neither curl.exe nor PowerShell was found."
        )
    ps_script = "; ".join(
        [
            "$ProgressPreference='SilentlyContinue'",
            "$headers=@{'User-Agent'='ZipCracker/%s'}" % ZIPCRACKER_VERSION,
            "Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri '%s' -OutFile '%s'"
            % (url.replace("'", "''"), dest_path.replace("'", "''")),
        ]
    )
    proc = subprocess.run(
        [powershell, "-NoProfile", "-Command", ps_script],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if proc.returncode != 0:
        raise urllib.error.URLError((proc.stderr or proc.stdout or "").strip())


def get_release_asset_sha256(asset: dict) -> Optional[str]:
    digest = (asset.get("digest") or "").strip()
    if not digest:
        return None
    if ":" in digest:
        algo, value = digest.split(":", 1)
        if algo.lower() != "sha256":
            return None
        return value.lower()
    return digest.lower()


def _read_os_release() -> dict:
    info = {}
    os_release_path = "/etc/os-release"
    if not os.path.isfile(os_release_path):
        return info
    with open(os_release_path, "r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            info[key] = value.strip().strip('"')
    return info


def detect_os_info() -> dict:
    system = platform.system()
    machine = (platform.machine() or "").lower()
    info = {
        "system": system,
        "machine": machine,
        "pretty_name": system or "Unknown OS",
        "distro_id": "",
        "distro_like": "",
        "version_id": "",
    }
    if system == "Darwin":
        version = platform.mac_ver()[0]
        info["pretty_name"] = f"macOS {version}".strip()
    elif system == "Windows":
        release = platform.release()
        version = platform.version()
        info["pretty_name"] = f"Windows {release} ({version})".strip()
    elif system == "Linux":
        os_release = _read_os_release()
        info["distro_id"] = os_release.get("ID", "").lower()
        info["distro_like"] = os_release.get("ID_LIKE", "").lower()
        info["version_id"] = os_release.get("VERSION_ID", "")
        info["pretty_name"] = (
            os_release.get("PRETTY_NAME")
            or os_release.get("NAME")
            or "Linux"
        )
    return info


def zip_has_aes_members(zip_file: str) -> bool:
    try:
        with zipfile.ZipFile(zip_file, "r") as zf:
            return any(_has_winzip_aes_extra(info) for info in zf.infolist())
    except Exception:
        return False


def collect_archive_encryption_profile(zip_file: str) -> dict:
    profile = {
        "total_entries": 0,
        "encrypted_entries": 0,
        "unencrypted_entries": 0,
        "aes_entries": 0,
        "zipcrypto_entries": 0,
    }
    try:
        with zipfile.ZipFile(zip_file, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                profile["total_entries"] += 1
                if info.flag_bits & 0x1:
                    profile["encrypted_entries"] += 1
                    if _has_winzip_aes_extra(info):
                        profile["aes_entries"] += 1
                    else:
                        profile["zipcrypto_entries"] += 1
                else:
                    profile["unencrypted_entries"] += 1
    except Exception:
        pass
    return profile


def archive_encryption_notice_lines(
    locale: str, profile: dict, *, pyzipper_ready: bool
) -> list[str]:
    aes_entries = int(profile.get("aes_entries", 0) or 0)
    zipcrypto_entries = int(profile.get("zipcrypto_entries", 0) or 0)
    if aes_entries <= 0:
        return []

    lines = []
    if pyzipper_ready or HAS_PYZIPPER:
        lines.append(
            loc(
                locale,
                f"[!] 检测到该压缩包包含 {aes_entries} 个 AES 加密条目。AES 的密码校验与解压通常明显慢于传统 ZipCrypto，这是正常现象，请耐心等待。",
                f"[!] This archive contains {aes_entries} AES-encrypted entr{'y' if aes_entries == 1 else 'ies'}. AES password verification and extraction are usually much slower than legacy ZipCrypto. This is normal, so please be patient.",
            )
        )
    else:
        lines.append(
            loc(
                locale,
                f"[!] 检测到该压缩包包含 {aes_entries} 个 AES 加密条目，但当前环境未启用 pyzipper。",
                f"[!] This archive contains {aes_entries} AES-encrypted entr{'y' if aes_entries == 1 else 'ies'}, but pyzipper is not enabled in the current environment.",
            )
        )
        lines.append(
            loc(
                locale,
                "[*] ZipCracker 本身支持 AES；当前风险主要来自缺少 pyzipper 依赖，并不代表工具不支持 AES。",
                "[*] ZipCracker itself supports AES. The current risk comes from the missing pyzipper dependency and does not mean the tool lacks AES support.",
            )
        )
        lines.append(
            loc(
                locale,
                "[*] 如果继续，AES 条目的密码验证或解压可能失败，也可能看起来更慢。建议先安装 pyzipper 后再重试。",
                "[*] If you continue, AES entry verification or extraction may fail and may also appear slower. Installing pyzipper before retrying is strongly recommended.",
            )
        )

    if zipcrypto_entries > 0:
        lines.append(
            loc(
                locale,
                f"[*] 该压缩包同时还包含 {zipcrypto_entries} 个传统 ZipCrypto 条目，不同条目的破解速度可能差异明显。",
                f"[*] This archive also contains {zipcrypto_entries} legacy ZipCrypto entr{'y' if zipcrypto_entries == 1 else 'ies'}, so cracking speed may vary noticeably between entries.",
            )
        )
    return lines


def normalize_arch(machine: str) -> str:
    value = (machine or "").lower()
    if value in ("x86_64", "amd64", "x64"):
        return "x86_64"
    if value in ("arm64", "aarch64"):
        return "arm64"
    return value or "unknown"


def arch_keywords(machine: str) -> tuple[str, ...]:
    normalized = normalize_arch(machine)
    if normalized == "x86_64":
        return ("x86_64", "amd64", "x64")
    if normalized == "arm64":
        return ("arm64", "aarch64")
    return (normalized,)


def windows_vc_redist_download_url(os_info: dict) -> str:
    arch = normalize_arch(os_info.get("machine", ""))
    if arch == "arm64":
        return MSVC_REDIST_ARM64_URL
    if arch in ("x86", "i386", "i686"):
        return MSVC_REDIST_X86_URL
    return MSVC_REDIST_X64_URL


def is_ubuntu_like(os_info: dict) -> bool:
    token_blob = " ".join(
        filter(
            None,
            (
                os_info.get("distro_id", ""),
                os_info.get("distro_like", ""),
                os_info.get("pretty_name", ""),
            ),
        )
    ).lower()
    return any(
        token in token_blob
        for token in (
            "ubuntu",
            "linuxmint",
            "pop",
            "elementary",
            "zorin",
            "neon",
            "kali",
            "deepin",
        )
    )


def format_os_label(locale: str, os_info: dict) -> str:
    pretty = os_info.get("pretty_name") or os_info.get("system") or "Unknown OS"
    arch = normalize_arch(os_info.get("machine", ""))
    return loc(locale, f"{pretty} / {arch}", f"{pretty} / {arch}")


def parse_version_tuple(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", value or "")
    if not parts:
        return ()
    return tuple(int(part) for part in parts[:3])


def is_old_ubuntu_lts(os_info: dict) -> bool:
    if os_info.get("system") != "Linux" or not is_ubuntu_like(os_info):
        return False
    version = parse_version_tuple(os_info.get("version_id", ""))
    return bool(version) and version <= (22, 4)


def system_package_install_prefix() -> str:
    if platform.system() != "Windows" and hasattr(os, "geteuid"):
        try:
            if os.geteuid() == 0:
                return ""
        except OSError:
            pass
    return "sudo " if shutil.which("sudo") else ""


def detect_package_manager(os_info: dict) -> str:
    for candidate in ("apt", "dnf", "yum", "pacman", "zypper", "apk"):
        if shutil.which(candidate):
            return candidate

    token_blob = " ".join(
        filter(
            None,
            (
                os_info.get("distro_id", ""),
                os_info.get("distro_like", ""),
                os_info.get("pretty_name", ""),
            ),
        )
    ).lower()
    if any(token in token_blob for token in ("debian", "ubuntu", "mint")):
        return "apt"
    if any(token in token_blob for token in ("rhel", "fedora", "rocky", "alma", "centos")):
        return "dnf"
    if "suse" in token_blob or "opensuse" in token_blob:
        return "zypper"
    if "arch" in token_blob:
        return "pacman"
    if "alpine" in token_blob:
        return "apk"
    return ""


def linux_package_install_command(package_manager: str, packages: Sequence[str]) -> str:
    prefix = system_package_install_prefix()
    package_list = " ".join(packages)
    if package_manager == "apt":
        return f"{prefix}apt update && {prefix}apt install -y {package_list}"
    if package_manager == "dnf":
        return f"{prefix}dnf install -y {package_list}"
    if package_manager == "yum":
        return f"{prefix}yum install -y {package_list}"
    if package_manager == "pacman":
        return f"{prefix}pacman -Sy --noconfirm {package_list}"
    if package_manager == "zypper":
        return f"{prefix}zypper install -y {package_list}"
    if package_manager == "apk":
        return f"{prefix}apk add --no-cache {package_list}"
    return ""


def linux_bkcrack_build_dependency_command(os_info: dict) -> str:
    package_manager = detect_package_manager(os_info)
    packages_map = {
        "apt": ("build-essential", "cmake", "zlib1g-dev", "pkg-config"),
        "dnf": ("gcc-c++", "make", "cmake", "zlib-devel"),
        "yum": ("gcc-c++", "make", "cmake", "zlib-devel"),
        "pacman": ("base-devel", "cmake", "zlib"),
        "zypper": ("gcc-c++", "make", "cmake", "zlib-devel"),
        "apk": ("build-base", "cmake", "zlib-dev", "linux-headers"),
    }
    packages = packages_map.get(package_manager)
    if not packages:
        return ""
    return linux_package_install_command(package_manager, packages)


def linux_python_packaging_command(os_info: dict) -> str:
    package_manager = detect_package_manager(os_info)
    packages_map = {
        "apt": ("python3-pip", "python3-venv"),
        "dnf": ("python3-pip", "python3-virtualenv"),
        "yum": ("python3-pip", "python3-virtualenv"),
        "pacman": ("python-pip", "python-virtualenv"),
        "zypper": ("python3-pip", "python3-virtualenv"),
        "apk": ("py3-pip", "py3-virtualenv"),
    }
    packages = packages_map.get(package_manager)
    if not packages:
        return ""
    return linux_package_install_command(package_manager, packages)


def summarize_command_output(text: str, *, max_lines: int = 10, max_chars: int = 1200) -> str:
    cleaned = (text or "").strip()
    if not cleaned:
        return ""
    lines = cleaned.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    joined = "\n".join(lines)
    if len(joined) > max_chars:
        joined = joined[-max_chars:]
    return joined.strip()


def format_bytes(size: float) -> str:
    value = float(max(size, 0.0))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(value)}{unit}"
            return f"{value:.2f}{unit}"
        value /= 1024.0
    return f"{value:.2f}TB"


def is_running_in_venv() -> bool:
    return (
        getattr(sys, "base_prefix", sys.prefix) != sys.prefix
        or hasattr(sys, "real_prefix")
    )


def pip_should_use_user_flag() -> bool:
    if is_running_in_venv():
        return False
    if platform.system() != "Windows" and hasattr(os, "geteuid"):
        try:
            if os.geteuid() == 0:
                return False
        except OSError:
            pass
    return True


def pyzipper_manual_methods(locale: str, os_info: dict) -> list[str]:
    python_cmd = "py -m pip install pyzipper" if os_info.get("system") == "Windows" else "python3 -m pip install pyzipper"
    exact_cmd = f"{sys.executable} -m pip install pyzipper"
    methods = []
    if locale != "en":
        methods.append(
            f"当前 Python 环境安装（推荐，中文模式优先清华源）: {sys.executable} -m pip install pyzipper -i {PYPI_TUNA_SIMPLE_URL}"
        )
    else:
        methods.append(
            loc(locale, f"Install into the current Python environment (recommended): {exact_cmd}", f"Install into the current Python environment (recommended): {exact_cmd}")
        )
    methods.append(
        loc(locale, f"当前 Python 环境安装（官方源）: {exact_cmd}", f"Install into the current Python environment (recommended): {exact_cmd}")
    )
    methods.append(loc(locale, f"通用命令: {python_cmd}", f"Generic command: {python_cmd}"))
    if is_running_in_venv():
        methods.append(
            loc(
                locale,
                "当前看起来处于虚拟环境中，建议直接安装到这个环境。",
                "A virtual environment appears to be active, so installing into it directly is recommended.",
            )
        )
    elif pip_should_use_user_flag():
        methods.append(
            loc(
                locale,
                f"若无管理员权限，可尝试用户级安装: {sys.executable} -m pip install --user pyzipper",
                f"If you do not have admin rights, try a user install: {sys.executable} -m pip install --user pyzipper",
            )
        )
    if os_info.get("system") == "Linux":
        pip_cmd = linux_python_packaging_command(os_info)
        if pip_cmd:
            methods.append(
                loc(
                    locale,
                    f"若系统缺少 pip / venv，可先安装 Python 打包组件: {pip_cmd}",
                    f"If pip / venv is missing on Linux, install the Python packaging tools first: {pip_cmd}",
                )
            )
    return methods


def build_pyzipper_pip_install_commands(locale: str) -> list[tuple[str, list[str]]]:
    command = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check"]
    if pip_should_use_user_flag():
        command.append("--user")
    official = command + ["pyzipper"]
    if locale != "en":
        tsinghua = command + ["-i", PYPI_TUNA_SIMPLE_URL, "pyzipper"]
        return [("tsinghua", tsinghua), ("official", official)]
    return [("official", official)]


def describe_pyzipper_install_failure(locale: str, detail: str, os_info: dict) -> str:
    summary = summarize_command_output(detail)
    lower_detail = (detail or "").lower()
    hints = []
    if "externally-managed-environment" in lower_detail:
        hints.append(
            loc(
                locale,
                "当前 Python 环境受发行版保护。建议先创建虚拟环境，再执行 `python -m pip install pyzipper`。",
                "This Python environment is distro-managed. Create a virtual environment first, then run `python -m pip install pyzipper` inside it.",
            )
        )
    if (
        "no module named pip" in lower_detail
        or "ensurepip is unavailable" in lower_detail
        or "pip/ensurepip is unavailable" in lower_detail
    ):
        packaging_cmd = linux_python_packaging_command(os_info)
        if packaging_cmd:
            hints.append(
                loc(
                    locale,
                    f"当前系统缺少 pip/venv 组件，可先执行: {packaging_cmd}",
                    f"This system appears to be missing pip/venv components. Install them first with: {packaging_cmd}",
                )
            )
    if "temporary failure in name resolution" in lower_detail or "failed to establish a new connection" in lower_detail:
        hints.append(
            loc(
                locale,
                "看起来是网络或镜像源访问失败，请检查网络、DNS 或 pip 源配置。",
                "This looks like a network or package index access failure. Check connectivity, DNS, or your pip index configuration.",
            )
        )
    if not hints:
        return summary or detail.strip()
    pieces = [summary] if summary else []
    pieces.extend(hints)
    return "\n".join(piece for piece in pieces if piece)


def ensure_pip_available() -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode == 0:
            return True, (proc.stdout or proc.stderr or "").strip()
    except Exception:
        pass

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "ensurepip", "--upgrade"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if proc.returncode == 0:
            return True, (proc.stdout or proc.stderr or "").strip()
        return False, (proc.stderr or proc.stdout or "").strip()
    except Exception as exc:
        return False, str(exc)


def auto_install_pyzipper(locale: str) -> tuple[bool, str]:
    os_info = detect_os_info()
    ok, info = ensure_pip_available()
    if not ok:
        detail = loc(
            locale,
            f"无法使用 pip/ensurepip: {info}",
            f"pip/ensurepip is unavailable: {info}",
        )
        return False, describe_pyzipper_install_failure(locale, detail, os_info)

    if locale != "en":
        print(
            loc(
                locale,
                f"[*] 中文模式优先使用清华 PyPI 镜像安装 pyzipper: {PYPI_TUNA_SIMPLE_URL}",
                f"[*] Chinese locale detected. Preferring the Tsinghua PyPI mirror for pyzipper: {PYPI_TUNA_SIMPLE_URL}",
            )
        )

    last_error = ""
    for source_name, cmd in build_pyzipper_pip_install_commands(locale):
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if proc.returncode == 0:
            break
        last_error = proc.stderr or proc.stdout or ""
        if source_name == "tsinghua":
            print(
                loc(
                    locale,
                    "[!] 通过清华 PyPI 镜像安装 pyzipper 失败，正在自动回退到官方 PyPI...",
                    "[!] Installing pyzipper through the Tsinghua PyPI mirror failed. Falling back to the official PyPI index...",
                )
            )
    else:
        return False, describe_pyzipper_install_failure(
            locale,
            last_error,
            os_info,
        )

    if not refresh_pyzipper_state():
        return False, loc(locale, "安装完成，但当前进程未能导入 pyzipper。", "Installation finished, but the current process could not import pyzipper.")

    version = get_pyzipper_version() or "unknown"
    return True, version


def get_managed_bkcrack_root() -> str:
    if platform.system() == "Windows":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
        return os.path.join(base, "ZipCracker", "tools", "bkcrack")
    return os.path.join(os.path.expanduser("~"), ".zipcracker", "tools", "bkcrack")


def _find_bkcrack_in_tree(root_dir: str) -> Optional[str]:
    if not os.path.isdir(root_dir):
        return None
    exe_name = "bkcrack.exe" if platform.system() == "Windows" else "bkcrack"
    for dirpath, _, filenames in os.walk(root_dir):
        if exe_name in filenames:
            candidate = os.path.join(dirpath, exe_name)
            if platform.system() != "Windows":
                try:
                    os.chmod(candidate, os.stat(candidate).st_mode | 0o111)
                except OSError:
                    pass
            return candidate
    return None


def find_bkcrack_executable() -> Optional[str]:
    found = shutil.which("bkcrack")
    if found and probe_bkcrack_executable(found)["usable"]:
        return found
    managed_root = get_managed_bkcrack_root()
    current_dir = os.path.join(managed_root, "current")
    for candidate in (
        _find_bkcrack_in_tree(current_dir),
        _find_bkcrack_in_tree(managed_root),
    ):
        if candidate and probe_bkcrack_executable(candidate)["usable"]:
            return candidate
    return None


def probe_bkcrack_executable(exec_path: str) -> dict:
    result = {
        "path": exec_path,
        "usable": False,
        "version": None,
        "error": "",
    }
    if not exec_path:
        result["error"] = "empty path"
        return result

    outputs = []
    for command in ([exec_path, "--version"], [exec_path, "-V"]):
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except OSError as exc:
            result["error"] = str(exc)
            return result
        except subprocess.SubprocessError as exc:
            outputs.append(str(exc))
            continue
        merged = (proc.stdout or "").strip()
        merged_err = (proc.stderr or "").strip()
        outputs.extend(filter(None, (merged, merged_err)))
        if proc.returncode == 0:
            line = (merged or merged_err or "").splitlines()
            if line:
                result["usable"] = True
                result["version"] = line[0].strip()
                result["error"] = ""
                return result

    result["error"] = outputs[0].splitlines()[0] if outputs else "unknown error"
    return result


def get_bkcrack_version(exec_path: str) -> Optional[str]:
    return probe_bkcrack_executable(exec_path).get("version")


def _is_supported_archive_name(filename: str) -> bool:
    lowered = filename.lower()
    return lowered.endswith((".zip", ".tar.gz", ".tgz", ".tar.xz", ".tar"))


def _extract_archive(archive_path: str, dest_dir: str) -> None:
    lowered = archive_path.lower()
    if lowered.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dest_dir)
        return
    if lowered.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar")):
        with tarfile.open(archive_path, "r:*") as tf:
            tf.extractall(dest_dir)
        return
    os.makedirs(dest_dir, exist_ok=True)
    shutil.copy2(archive_path, os.path.join(dest_dir, os.path.basename(archive_path)))


def _find_source_root(root_dir: str) -> Optional[str]:
    for dirpath, _, filenames in os.walk(root_dir):
        if "CMakeLists.txt" in filenames:
            return dirpath
    return None


def linux_bkcrack_source_build_command(os_info: dict) -> str:
    compile_cmd = (
        "cmake -S . -B build -DCMAKE_INSTALL_PREFIX=install && "
        "cmake --build build --config Release && "
        "cmake --build build --config Release --target install"
    )
    dep_cmd = linux_bkcrack_build_dependency_command(os_info)
    if dep_cmd:
        return f"{dep_cmd} && {compile_cmd}"
    return compile_cmd


def describe_bkcrack_build_failure(locale: str, detail: str, os_info: dict) -> str:
    summary = summarize_command_output(detail)
    lower_detail = (detail or "").lower()
    hints = []

    if "could not find zlib" in lower_detail or "zlib" in lower_detail:
        hints.append(
            loc(
                locale,
                "看起来缺少 zlib 开发头文件，bkcrack 无法完成链接。",
                "This looks like a missing zlib development header/library dependency required for linking bkcrack.",
            )
        )
    if "cmake_cxx_compiler" in lower_detail or "no c++ compiler" in lower_detail:
        hints.append(
            loc(
                locale,
                "当前系统缺少可用的 C++ 编译器。",
                "No usable C++ compiler was detected on this system.",
            )
        )
    if "ninja" in lower_detail or "make" in lower_detail:
        hints.append(
            loc(
                locale,
                "当前系统可能缺少构建工具（make / ninja）。",
                "This system may be missing a build backend such as make or ninja.",
            )
        )

    dep_cmd = linux_bkcrack_build_dependency_command(os_info)
    if dep_cmd:
        hints.append(
            loc(
                locale,
                f"可先安装 Linux 编译依赖后重试: {dep_cmd}",
                f"Install the Linux build dependencies first, then retry: {dep_cmd}",
            )
        )

    if not hints:
        return summary or detail.strip()
    pieces = [summary] if summary else []
    pieces.extend(hints)
    return "\n".join(piece for piece in pieces if piece)


def describe_bkcrack_install_failure(locale: str, detail: str, os_info: dict) -> str:
    summary = summarize_command_output(detail)
    lower_detail = (detail or "").lower()
    hints = []

    if "certificate verify failed" in lower_detail or "certificate_verify_failed" in lower_detail:
        hints.append(
            loc(
                locale,
                "这通常不是单纯的“国内无法访问 GitHub”，而是当前 Python HTTPS 证书链校验失败。常见原因包括系统根证书缺失、代理/安全软件拦截 HTTPS、或 Python 自身证书环境异常。",
                "This is usually not just 'GitHub is unreachable'. It means HTTPS certificate-chain verification failed in the current Python environment. Common causes include missing system root certificates, HTTPS interception by a proxy/security product, or a broken Python certificate setup.",
            )
        )
        if os_info.get("system") == "Windows":
            hints.append(
                loc(
                    locale,
                    "建议先尝试：1. 校准系统时间 2. 更新系统根证书 3. 关闭会拦截 HTTPS 的代理/杀软 4. 用浏览器手动打开 GitHub release 页面测试。",
                    "Try these first: 1. verify the system clock 2. update Windows root certificates 3. disable any HTTPS-intercepting proxy/antivirus 4. open the GitHub release page in a browser to test.",
                )
            )
    if "timed out" in lower_detail or "name resolution" in lower_detail:
        hints.append(
            loc(
                locale,
                "这更像是网络超时或 DNS 解析问题，请检查网络出口、DNS 或代理设置。",
                "This looks more like a network timeout or DNS resolution problem. Check your outbound network, DNS, or proxy settings.",
            )
        )
    if not hints:
        return summary or detail.strip()
    pieces = [summary] if summary else []
    pieces.extend(hints)
    return "\n".join(piece for piece in pieces if piece)


def windows_exception_code_from_returncode(returncode: int) -> Optional[int]:
    if platform.system() != "Windows":
        return None
    if returncode < 0:
        return None
    if returncode >= 0x80000000:
        return returncode
    return None


def describe_bkcrack_runtime_failure(
    locale: str, returncode: int, output: str = ""
) -> list[str]:
    os_info = detect_os_info()
    lines = [
        loc(
            locale,
            f"[!] bkcrack 退出码: {returncode}",
            f"[!] bkcrack exit code: {returncode}",
        )
    ]
    win_code = windows_exception_code_from_returncode(returncode)
    if win_code == 0xC0000005:
        vc_redist_direct = windows_vc_redist_download_url(os_info)
        lines.append(
            loc(
                locale,
                "[!] 该退出码对应 Windows 异常 0xC0000005（Access Violation，访问冲突）。这不是“密码不对”，而是 bkcrack 进程在运行中崩溃了。",
                "[!] This maps to Windows exception 0xC0000005 (Access Violation). This does not mean 'wrong password'; it means the bkcrack process itself crashed while running.",
            )
        )
        lines.append(
            loc(
                locale,
                "[*] 常见原因：Windows 版 bkcrack 本身崩溃、运行库/安全软件干扰、或多线程运行时异常。",
                "[*] Common causes include a crash inside the Windows bkcrack build, runtime/security-software interference, or a multithreading issue.",
            )
        )
        lines.append(
            loc(
                locale,
                f"[*] 建议先尝试：1. 安装/修复 Microsoft Visual C++ Redistributable（文档 {MSVC_REDIST_URL} ，直链 {vc_redist_direct}） 2. 设 BKCRACK_JOBS=1 再试 3. 临时关闭杀软或给 bkcrack.exe 加白名单 4. 若仍崩溃，优先在 WSL / Linux 下使用 bkcrack。",
                f"[*] Recommended next steps: 1. install/repair Microsoft Visual C++ Redistributable (docs {MSVC_REDIST_URL} , direct download {vc_redist_direct}) 2. retry with BKCRACK_JOBS=1 3. temporarily disable antivirus or whitelist bkcrack.exe 4. if it still crashes, prefer running bkcrack under WSL/Linux.",
            )
        )
    elif win_code == 0xC000001D:
        lines.append(
            loc(
                locale,
                "[!] 该退出码对应 Windows 异常 0xC000001D（Illegal Instruction，非法指令），通常意味着可执行文件与当前 CPU/指令集不兼容。",
                "[!] This maps to Windows exception 0xC000001D (Illegal Instruction), which usually means the executable is incompatible with the current CPU/instruction set.",
            )
        )
    elif win_code == 0xC0000135:
        lines.append(
            loc(
                locale,
                "[!] 该退出码对应 Windows 异常 0xC0000135，通常表示缺少运行时依赖或 DLL。",
                "[!] This maps to Windows exception 0xC0000135, which usually means a required runtime or DLL is missing.",
            )
        )
    elif win_code is not None:
        lines.append(
            loc(
                locale,
                f"[*] 该退出码对应 Windows 异常码 0x{win_code:08X}。",
                f"[*] This return code corresponds to Windows exception 0x{win_code:08X}.",
            )
        )

    lower_output = (output or "").lower()
    if "z reduction" in lower_output and win_code == 0xC0000005:
        lines.append(
            loc(
                locale,
                "[*] 从当前日志看，bkcrack 已经开始处理已知明文（Z reduction 阶段）后才崩溃，说明下载、启动、参数传递都基本正常，问题更像是 bkcrack Windows 运行时崩溃。",
                "[*] Based on the current log, bkcrack started processing the known plaintext (during the Z reduction stage) and then crashed. That means download/startup/argument passing are basically fine; the issue looks more like a runtime crash inside the Windows bkcrack path.",
            )
        )
    return lines


def _choose_bkcrack_release_asset(release: dict, os_info: dict) -> Optional[dict]:
    system = os_info.get("system", "")
    if system == "Darwin":
        os_keywords = ("macos", "darwin")
    elif system == "Windows":
        os_keywords = ("windows", "win")
    elif system == "Linux":
        os_keywords = ("ubuntu", "linux") if is_ubuntu_like(os_info) else ("linux",)
    else:
        return None

    candidates = []
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        lowered = name.lower()
        if not _is_supported_archive_name(lowered):
            continue
        if not any(keyword in lowered for keyword in os_keywords):
            continue
        arch_score = 1 if any(keyword in lowered for keyword in arch_keywords(os_info.get("machine", ""))) else 0
        os_score = 2 if any(keyword in lowered for keyword in os_keywords[:-1] or os_keywords) else 1
        candidates.append((os_score, arch_score, lowered, asset))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    return candidates[0][3]


def bkcrack_manual_methods(locale: str, os_info: dict) -> list[str]:
    compile_cmd = linux_bkcrack_source_build_command(os_info)
    dep_cmd = linux_bkcrack_build_dependency_command(os_info)
    system = os_info.get("system", "")
    if system == "Darwin":
        return [
            loc(locale, "Homebrew（推荐）: brew install bkcrack", "Homebrew (recommended): brew install bkcrack"),
            loc(locale, f"官方预编译包: 打开 {BKCRACK_REPO_URL}/releases 下载适用于 macOS 的压缩包并解压", f"Official precompiled package: open {BKCRACK_REPO_URL}/releases and download the macOS archive"),
            loc(locale, "源码编译: cmake -S . -B build -DCMAKE_INSTALL_PREFIX=install && cmake --build build --config Release && cmake --build build --config Release --target install", "Build from source: cmake -S . -B build -DCMAKE_INSTALL_PREFIX=install && cmake --build build --config Release && cmake --build build --config Release --target install"),
        ]
    if system == "Windows":
        vc_redist_direct = windows_vc_redist_download_url(os_info)
        return [
            loc(locale, f"官方预编译包（推荐）: 打开 {BKCRACK_REPO_URL}/releases 下载适用于 Windows 的压缩包并解压", f"Official precompiled package (recommended): open {BKCRACK_REPO_URL}/releases and download the Windows archive"),
            loc(locale, f"如果运行时报缺少运行库，请安装 Microsoft Visual C++ Redistributable: 文档 {MSVC_REDIST_URL} ，直链 {vc_redist_direct}", f"If bkcrack reports missing runtime libraries, install Microsoft Visual C++ Redistributable: docs {MSVC_REDIST_URL} , direct download {vc_redist_direct}"),
        ]
    if system == "Linux" and is_ubuntu_like(os_info):
        methods = []
        if dep_cmd:
            methods.append(
                loc(
                    locale,
                    f"Linux 构建依赖（apt/Ubuntu 系）: {dep_cmd}",
                    f"Linux build dependencies (apt / Ubuntu family): {dep_cmd}",
                )
            )
        methods.extend(
            [
                loc(locale, f"源码编译（推荐，兼容性最好）: {compile_cmd}", f"Build from source (recommended for compatibility): {compile_cmd}"),
                loc(locale, f"官方预编译包（更适合较新的 Ubuntu / glibc）: 打开 {BKCRACK_REPO_URL}/releases 下载适用于 Ubuntu 的压缩包并解压", f"Official precompiled package (better for newer Ubuntu/glibc): open {BKCRACK_REPO_URL}/releases and download the Ubuntu archive"),
            ]
        )
        return methods
    if system == "Linux":
        methods = []
        if dep_cmd:
            methods.append(
                loc(
                    locale,
                    f"Linux 构建依赖: {dep_cmd}",
                    f"Linux build dependencies: {dep_cmd}",
                )
            )
        methods.extend(
            [
                loc(locale, f"源码编译（推荐）: {compile_cmd}", f"Build from source (recommended): {compile_cmd}"),
                loc(locale, f"如果你的发行版有第三方维护的 bkcrack 包，也可以使用系统包管理器安装；官方说明见 {BKCRACK_REPO_URL}", f"If your distribution provides a third-party bkcrack package, you can also use the system package manager; see {BKCRACK_REPO_URL}"),
            ]
        )
        return methods
    return [
        loc(locale, f"请从官方仓库查看安装说明: {BKCRACK_REPO_URL}", f"Please check the official repository for installation instructions: {BKCRACK_REPO_URL}")
    ]


def bkcrack_auto_install_mode(os_info: dict) -> Optional[str]:
    system = os_info.get("system", "")
    if system in ("Darwin", "Windows"):
        return "release"
    if system == "Linux":
        return "source"
    return None


def _install_bkcrack_from_release(locale: str, os_info: dict) -> tuple[bool, str]:
    release = _http_get_json(BKCRACK_RELEASES_API)
    asset = _choose_bkcrack_release_asset(release, os_info)
    if not asset:
        return False, loc(locale, "未找到与你当前系统匹配的官方预编译包。", "No matching official precompiled package was found for your OS.")

    managed_root = get_managed_bkcrack_root()
    current_dir = os.path.join(managed_root, "current")
    temp_dir = tempfile.mkdtemp(prefix="zipcracker_bkcrack_install_")
    try:
        archive_path = os.path.join(temp_dir, asset["name"])
        print(
            loc(
                locale,
                f"[*] 正在下载 bkcrack 官方预编译包: {asset['name']}（版本 {release.get('tag_name') or 'unknown'}）",
                f"[*] Downloading official bkcrack package: {asset['name']} (version {release.get('tag_name') or 'unknown'})",
            )
        )
        _http_download_file(asset["browser_download_url"], archive_path)
        actual_sha256 = sha256_file(archive_path)
        expected_sha256 = get_release_asset_sha256(asset)
        if expected_sha256:
            if actual_sha256.lower() != expected_sha256.lower():
                return (
                    False,
                    loc(
                        locale,
                        f"下载文件 SHA256 校验失败。期望 {expected_sha256}，实际 {actual_sha256}",
                        f"Downloaded file SHA256 mismatch. Expected {expected_sha256}, got {actual_sha256}",
                    ),
                )
            print(
                loc(
                    locale,
                    f"[+] 已验证下载文件 SHA256: {actual_sha256}",
                    f"[+] Verified downloaded file SHA256: {actual_sha256}",
                )
            )
        else:
            print(
                loc(
                    locale,
                    f"[*] 发布元数据未提供摘要，已本地计算 SHA256: {actual_sha256}",
                    f"[*] Release metadata did not expose a digest, computed local SHA256: {actual_sha256}",
                )
            )
        extract_dir = os.path.join(temp_dir, "extract")
        _extract_archive(archive_path, extract_dir)

        if os.path.isdir(current_dir):
            shutil.rmtree(current_dir, ignore_errors=True)
        os.makedirs(managed_root, exist_ok=True)
        shutil.copytree(extract_dir, current_dir)

        installed = _find_bkcrack_in_tree(current_dir)
        if not installed:
            return False, loc(locale, "已下载并解压，但未找到 bkcrack 可执行文件。", "Downloaded and extracted, but the bkcrack executable was not found.")
        probe = probe_bkcrack_executable(installed)
        if not probe["usable"]:
            return (
                False,
                loc(
                    locale,
                    f"下载的 bkcrack 与当前系统不兼容: {probe['error']}",
                    f"The downloaded bkcrack binary is incompatible with this system: {probe['error']}",
                ),
            )
        version = probe["version"] or release.get("tag_name") or "unknown"
        return True, json.dumps(
            {
                "path": installed,
                "version": version,
                "release_tag": release.get("tag_name") or "",
                "sha256": actual_sha256,
            },
            ensure_ascii=False,
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _install_bkcrack_from_source(locale: str) -> tuple[bool, str]:
    os_info = detect_os_info()
    missing_requirements = []
    if not shutil.which("cmake"):
        missing_requirements.append("cmake")
    if not any(shutil.which(name) for name in ("c++", "g++", "clang++")):
        missing_requirements.append("C++ compiler")
    if not any(shutil.which(name) for name in ("make", "ninja")):
        missing_requirements.append("make/ninja")
    if missing_requirements:
        dep_cmd = linux_bkcrack_build_dependency_command(os_info)
        missing_text = ", ".join(missing_requirements)
        if dep_cmd:
            return (
                False,
                loc(
                    locale,
                    f"源码一键安装缺少必要构建组件: {missing_text}。可先执行: {dep_cmd}",
                    f"Source-based auto-install is missing required build tools: {missing_text}. Install them first with: {dep_cmd}",
                ),
            )
        return (
            False,
            loc(
                locale,
                f"源码一键安装缺少必要构建组件: {missing_text}",
                f"Source-based auto-install is missing required build tools: {missing_text}",
            ),
        )

    release = _http_get_json(BKCRACK_RELEASES_API)
    tarball_url = release.get("tarball_url")
    if not tarball_url:
        return False, loc(locale, "未获取到 bkcrack 源码下载地址。", "Could not resolve the bkcrack source download URL.")

    managed_root = get_managed_bkcrack_root()
    current_dir = os.path.join(managed_root, "current")
    temp_dir = tempfile.mkdtemp(prefix="zipcracker_bkcrack_src_")
    try:
        archive_path = os.path.join(temp_dir, "bkcrack-source.tar.gz")
        print(
            loc(
                locale,
                "[*] 正在下载 bkcrack 源码并准备编译安装...",
                "[*] Downloading bkcrack source and preparing a local build...",
            )
        )
        _http_download_file(tarball_url, archive_path)
        source_extract_dir = os.path.join(temp_dir, "src")
        _extract_archive(archive_path, source_extract_dir)
        source_root = _find_source_root(source_extract_dir)
        if not source_root:
            return False, loc(locale, "未在源码包中找到 CMakeLists.txt。", "CMakeLists.txt was not found in the downloaded source tree.")

        build_dir = os.path.join(temp_dir, "build")
        if os.path.isdir(current_dir):
            shutil.rmtree(current_dir, ignore_errors=True)
        os.makedirs(managed_root, exist_ok=True)

        for command in (
            ["cmake", "-S", source_root, "-B", build_dir, f"-DCMAKE_INSTALL_PREFIX={current_dir}"],
            ["cmake", "--build", build_dir, "--config", "Release"],
            ["cmake", "--build", build_dir, "--config", "Release", "--target", "install"],
        ):
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                return (
                    False,
                    describe_bkcrack_build_failure(
                        locale,
                        proc.stderr or proc.stdout or str(command),
                        os_info,
                    ),
                )

        installed = _find_bkcrack_in_tree(current_dir)
        if not installed:
            return False, loc(locale, "源码编译已完成，但未找到 bkcrack 可执行文件。", "The source build completed, but the bkcrack executable was not found.")
        probe = probe_bkcrack_executable(installed)
        if not probe["usable"]:
            return (
                False,
                loc(
                    locale,
                    f"源码编译后的 bkcrack 无法正常执行: {probe['error']}",
                    f"The source-built bkcrack could not be executed: {probe['error']}",
                ),
            )
        version = probe["version"] or release.get("tag_name") or "unknown"
        return True, json.dumps(
            {
                "path": installed,
                "version": version,
                "release_tag": release.get("tag_name") or "",
                "sha256": "",
            },
            ensure_ascii=False,
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def prompt_yes_no(
    locale: str,
    zh_prompt: str,
    en_prompt: str,
    *,
    env_name: Optional[str] = None,
) -> bool:
    if env_name:
        env_value = os.environ.get(env_name, "").strip().lower()
        if env_value in ("1", "true", "yes", "y", "on"):
            return True
        if env_value in ("0", "false", "no", "n", "off"):
            return False
    if not sys.stdin.isatty():
        return False

    while True:
        answer = input(timestamped_prompt(loc(locale, zh_prompt, en_prompt))).strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no", ""):
            return False
        print(loc(locale, "[!] 请输入 y 或 n。", "[!] Please answer with y or n."))


def offer_pyzipper_install(locale: str, zip_file: str) -> bool:
    if refresh_pyzipper_state():
        return True

    os_info = detect_os_info()
    archive_has_aes = zip_has_aes_members(zip_file)
    version = get_pyzipper_version()
    if version:
        print(
            loc(
                locale,
                f"[+] 检测到您的系统已安装 pyzipper {version}，自动开启 AES 加密破解支持。",
                f"[+] pyzipper {version} detected. AES-encrypted ZIP support is enabled.",
            )
        )
        return True

    print(
        loc(
            locale,
            f"[!] 未检测到 pyzipper。当前系统: {format_os_label(locale, os_info)}",
            f"[!] pyzipper was not detected. Current OS: {format_os_label(locale, os_info)}",
        )
    )
    if archive_has_aes:
        print(
            loc(
                locale,
                "[*] 当前压缩包检测到 AES 扩展字段；若跳过安装，AES 条目可能无法正确验证或解压。",
                "[*] AES extra fields were detected in this archive. If you skip installation, AES entries may not be verified or extracted correctly.",
            )
        )
    else:
        print(
            loc(
                locale,
                "[*] 当前压缩包未检测到明显的 AES 标记；如果只是传统 ZipCrypto，可以选择跳过安装。",
                "[*] No obvious AES marker was detected in this archive. If you only need legacy ZipCrypto support, you can skip installation.",
            )
        )

    methods = pyzipper_manual_methods(locale, os_info)
    for index, method in enumerate(methods, start=1):
        prefix = "安装方式" if locale != "en" else "Install option"
        print(f"[*] {prefix}{index}: {method}")

    env_value = os.environ.get(PYZIPPER_AUTO_INSTALL_ENV, "").strip().lower()
    if env_value in ("1", "true", "yes", "y", "on"):
        should_install = True
    elif env_value in ("0", "false", "no", "n", "off"):
        should_install = False
    else:
        should_install = prompt_yes_no(
            locale,
            "[?] 是否现在执行 pyzipper 一键自动安装？输入 n 可跳过继续当前任务。 (y/n): ",
            "[?] Install pyzipper now? Enter n to skip and continue the current task. (y/n): ",
        )

    if not should_install:
        print(
            loc(
                locale,
                "[*] 已跳过 pyzipper 安装，继续当前任务。",
                "[*] Skipping pyzipper installation and continuing the current task.",
            )
        )
        return False

    print(
        loc(
            locale,
            "[*] 开始执行 pyzipper 一键自动安装...",
            "[*] Starting one-click pyzipper installation...",
        )
    )
    success, result = auto_install_pyzipper(locale)
    if success:
        print(
            loc(
                locale,
                f"[+] pyzipper 安装成功，当前版本: {result}",
                f"[+] pyzipper installed successfully. Current version: {result}",
            )
        )
        return True

    print(
        loc(
            locale,
            f"[!] pyzipper 一键自动安装失败: {result}",
            f"[!] One-click pyzipper installation failed: {result}",
        )
    )
    print(
        loc(
            locale,
            "[*] 已跳过 pyzipper 安装，继续当前任务。",
            "[*] Skipping pyzipper installation and continuing the current task.",
        )
    )
    return False


def offer_bkcrack_install(locale: str, *, required: bool) -> Optional[str]:
    existing = find_bkcrack_executable()
    if existing:
        return existing

    os_info = detect_os_info()
    raw_existing = shutil.which("bkcrack")
    managed_existing = _find_bkcrack_in_tree(os.path.join(get_managed_bkcrack_root(), "current"))
    incompatible_probe = None
    if raw_existing:
        probe = probe_bkcrack_executable(raw_existing)
        if not probe["usable"]:
            incompatible_probe = probe
    elif managed_existing:
        probe = probe_bkcrack_executable(managed_existing)
        if not probe["usable"]:
            incompatible_probe = probe

    auto_mode = bkcrack_auto_install_mode(os_info)
    managed_root = get_managed_bkcrack_root()
    print(
        loc(
            locale,
            f"[!] 未检测到 bkcrack。当前系统: {format_os_label(locale, os_info)}",
            f"[!] bkcrack was not detected. Current OS: {format_os_label(locale, os_info)}",
        )
    )
    if incompatible_probe:
        print(
            loc(
                locale,
                f"[!] 已发现现有 bkcrack 但不可用: {incompatible_probe['path']}",
                f"[!] Found an existing bkcrack executable, but it is unusable: {incompatible_probe['path']}",
            )
        )
        print(
            loc(
                locale,
                f"[*] 原因: {incompatible_probe['error']}",
                f"[*] Reason: {incompatible_probe['error']}",
            )
        )
    for index, method in enumerate(bkcrack_manual_methods(locale, os_info), start=1):
        print(loc(locale, f"[*] 安装方式{index}: {method}", f"[*] Install option {index}: {method}"))

    if not auto_mode:
        print(
            loc(
                locale,
                "[*] 当前系统暂未提供内置一键安装能力，请按上面的手动方式安装。",
                "[*] A built-in one-click installer is not available for this OS yet. Please use one of the manual installation methods above.",
            )
        )
        return None

    print(
        loc(
            locale,
            f"[*] 一键自动安装会把 bkcrack 安装到本地目录: {managed_root}",
            f"[*] One-click install will place bkcrack under: {managed_root}",
        )
    )
    should_install = prompt_yes_no(
        locale,
        "[?] 是否现在执行一键自动安装并继续当前任务？ (y/n): ",
        "[?] Install bkcrack now and continue the current task? (y/n): ",
        env_name=BKCRACK_AUTO_INSTALL_ENV,
    )
    if not should_install:
        if required:
            print(
                loc(
                    locale,
                    "[!] 当前命令必须依赖 bkcrack。请先完成安装后重试。",
                    "[!] This command requires bkcrack. Please install it and retry.",
                )
            )
        return None

    print(
        loc(
            locale,
            "[*] 开始执行 bkcrack 一键安装...",
            "[*] Starting one-click bkcrack installation...",
        )
    )
    try:
        if auto_mode == "release":
            success, result = _install_bkcrack_from_release(locale, os_info)
        else:
            success, result = _install_bkcrack_from_source(locale)
            if not success and incompatible_probe and os_info.get("system") == "Linux" and not shutil.which("cmake"):
                fallback_ok, fallback_result = _install_bkcrack_from_release(locale, os_info)
                success, result = fallback_ok, fallback_result
    except urllib.error.URLError as exc:
        success = False
        result = str(exc)
    except Exception as exc:
        success = False
        result = str(exc)

    if success:
        try:
            install_meta = json.loads(result)
        except json.JSONDecodeError:
            install_meta = {"path": result, "version": "unknown", "release_tag": "", "sha256": ""}
        version = install_meta.get("version") or install_meta.get("release_tag") or "unknown"
        path = install_meta.get("path") or result
        print(
            loc(
                locale,
                f"[+] bkcrack 安装成功: {path}",
                f"[+] bkcrack installed successfully: {path}",
            )
        )
        print(
            loc(
                locale,
                f"[+] 已安装版本: {version}",
                f"[+] Installed version: {version}",
            )
        )
        if install_meta.get("sha256"):
            print(
                loc(
                    locale,
                    f"[+] 安装包 SHA256 已校验通过: {install_meta['sha256']}",
                    f"[+] Package SHA256 verified: {install_meta['sha256']}",
                )
            )
        if os_info.get("system") == "Windows":
            vc_redist_direct = windows_vc_redist_download_url(os_info)
            print(
                loc(
                    locale,
                    f"[*] 若后续运行提示缺少运行库，请安装 Microsoft Visual C++ Redistributable: 文档 {MSVC_REDIST_URL} ，直链 {vc_redist_direct}",
                    f"[*] If a runtime library error appears later, install Microsoft Visual C++ Redistributable: docs {MSVC_REDIST_URL} , direct download {vc_redist_direct}",
                )
            )
        return path

    print(
        loc(
            locale,
            f"[!] 一键自动安装失败: {describe_bkcrack_install_failure(locale, result, os_info)}",
            f"[!] One-click installation failed: {describe_bkcrack_install_failure(locale, result, os_info)}",
        )
    )
    if required:
        print(
            loc(
                locale,
                "[!] 当前命令必须依赖 bkcrack，请按上面的手动方式安装后重试。",
                "[!] This command requires bkcrack. Please use one of the manual installation methods above and retry.",
            )
        )
    return None


def is_regular_member(info: zipfile.ZipInfo) -> bool:
    return not info.is_dir()


def _has_winzip_aes_extra(info: zipfile.ZipInfo) -> bool:
    extra = info.extra
    i = 0
    while i + 4 <= len(extra):
        tid, ln = struct.unpack("<HH", extra[i : i + 4])
        if tid == 0x9901:
            return True
        i += 4 + ln
    return False


def is_zip_archive(path: str) -> bool:
    try:
        return zipfile.is_zipfile(path)
    except OSError:
        return False


def build_kpa_template_candidates(template_name: str, locale: str) -> list[KnownPlaintextTemplate]:
    template = normalize_kpa_template_name(template_name)
    if template == "png":
        return [
            KnownPlaintextTemplate(
                name="png-header",
                plain_offset=0,
                plaintext_bytes=bytes.fromhex("89504e470d0a1a0a0000000d49484452"),
            ),
            KnownPlaintextTemplate(
                name="png-rgb-idat",
                plain_offset=0,
                plaintext_bytes=bytes.fromhex("89504e470d0a1a0a0000000d49484452"),
                extra_specs=[
                    (24, bytes.fromhex("0802000000")),
                    (37, b"IDAT"),
                ],
            ),
            KnownPlaintextTemplate(
                name="png-rgba-idat",
                plain_offset=0,
                plaintext_bytes=bytes.fromhex("89504e470d0a1a0a0000000d49484452"),
                extra_specs=[
                    (24, bytes.fromhex("0806000000")),
                    (37, b"IDAT"),
                ],
            ),
            KnownPlaintextTemplate(
                name="png-gray-idat",
                plain_offset=0,
                plaintext_bytes=bytes.fromhex("89504e470d0a1a0a0000000d49484452"),
                extra_specs=[
                    (24, bytes.fromhex("0800000000")),
                    (37, b"IDAT"),
                ],
            ),
        ]
    if template == "pcapng":
        return [
            KnownPlaintextTemplate(
                name="pcapng-shb",
                plain_offset=0,
                plaintext_bytes=bytes.fromhex("0a0d0d0a1c0000004d3c2b1a01000000"),
            )
        ]
    if template == "exe":
        return [
            KnownPlaintextTemplate(
                name="exe-mz-prefix",
                plain_offset=0,
                plaintext_bytes=bytes.fromhex("4d5a90000300000004000000ffff0000"),
            ),
            KnownPlaintextTemplate(
                name="exe-dos-stub",
                plain_offset=78,
                plaintext_bytes=b"This program cannot be run in DOS mode.",
                extra_specs=[(0, b"MZ")],
            ),
            KnownPlaintextTemplate(
                name="exe-dos-stub-pe80",
                plain_offset=78,
                plaintext_bytes=b"This program cannot be run in DOS mode.",
                extra_specs=[
                    (0, b"MZ"),
                    (60, bytes.fromhex("80000000")),
                    (128, b"PE\x00\x00"),
                ],
            ),
        ]
    if template == "zip":
        return [
            KnownPlaintextTemplate(
                name="zip-local-header-stored-v20",
                plain_offset=0,
                plaintext_bytes=bytes.fromhex("504b03041400000000000000"),
            ),
            KnownPlaintextTemplate(
                name="zip-local-header-deflated-v20",
                plain_offset=0,
                plaintext_bytes=bytes.fromhex("504b03041400000008000000"),
            ),
            KnownPlaintextTemplate(
                name="zip-local-header-stored-v10",
                plain_offset=0,
                plaintext_bytes=bytes.fromhex("504b03040a00000000000000"),
            ),
            KnownPlaintextTemplate(
                name="zip-local-header-deflated-v10",
                plain_offset=0,
                plaintext_bytes=bytes.fromhex("504b03040a00000008000000"),
            ),
        ]
    raise ValueError(
        loc(
            locale,
            f"不支持的 KPA 模板: {template_name}。可用模板: {', '.join(KPA_TEMPLATE_CHOICES)}",
            f"Unsupported KPA template: {template_name}. Available templates: {', '.join(KPA_TEMPLATE_CHOICES)}",
        )
    )


def guess_kpa_template_for_entry_name(entry_name: str) -> Optional[str]:
    ext = os.path.splitext(entry_name)[1].lower()
    for template_name, extensions in KPA_TEMPLATE_ENTRY_EXTENSIONS.items():
        if ext in extensions:
            return template_name
    return None


def template_candidates_fit_entry_size(
    template_name: str,
    file_size: int,
    locale: str,
) -> bool:
    for candidate in build_kpa_template_candidates(template_name, locale):
        required_size = candidate.plain_offset + len(candidate.plaintext_bytes)
        for extra_offset, extra_bytes in candidate.extra_specs:
            required_size = max(required_size, extra_offset + len(extra_bytes))
        if file_size >= required_size:
            return True
    return False


def template_is_high_confidence_auto_suggestion(
    template_name: str,
    file_size: int,
    locale: str,
) -> bool:
    allowed_names = AUTO_TEMPLATE_CANDIDATE_NAMES.get(template_name, set())
    if not allowed_names:
        return False
    for candidate in build_kpa_template_candidates(template_name, locale):
        if candidate.name not in allowed_names:
            continue
        required_size = candidate.plain_offset + len(candidate.plaintext_bytes)
        for extra_offset, extra_bytes in candidate.extra_specs:
            required_size = max(required_size, extra_offset + len(extra_bytes))
        if file_size >= required_size:
            return True
    return False


def compress_type_label(compress_type: int) -> str:
    mapping = {
        zipfile.ZIP_STORED: "ZIP_STORED",
        zipfile.ZIP_DEFLATED: "ZIP_DEFLATED",
        zipfile.ZIP_BZIP2: "ZIP_BZIP2",
        zipfile.ZIP_LZMA: "ZIP_LZMA",
    }
    return mapping.get(compress_type, str(compress_type))


def shell_quote_for_display(value: str) -> str:
    if platform.system() == "Windows":
        if not value or any(ch.isspace() for ch in value) or '"' in value:
            return '"' + value.replace('"', '\\"') + '"'
        return value
    return shlex.quote(value)


def recommended_python_command() -> str:
    return "python" if platform.system() == "Windows" else "python3"


def format_template_kpa_recommendation_command(
    zip_path: str,
    suggestion: TemplateKpaSuggestion,
) -> str:
    script_name = os.path.basename(sys.argv[0]) or "ZipCracker.py"
    return " ".join(
        [
            recommended_python_command(),
            shell_quote_for_display(script_name),
            shell_quote_for_display(zip_path),
            "--kpa-template",
            suggestion.template_name,
            "-c",
            shell_quote_for_display(suggestion.inner_name),
        ]
    )


def template_is_worth_trying_auto_suggestion(
    template_name: str,
    file_size: int,
    locale: str,
) -> bool:
    if template_name not in ("png", "pcapng", "exe"):
        return False
    if template_name == "exe" and file_size < 128:
        return False
    return template_candidates_fit_entry_size(template_name, file_size, locale)


def detect_template_kpa_suggestions(
    zip_path: str,
    locale: str,
) -> list[TemplateKpaSuggestion]:
    suggestions: list[TemplateKpaSuggestion] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = [info for info in zf.infolist() if is_regular_member(info)]
        for info in infos:
            if info.flag_bits & 0x1 == 0:
                continue
            if _has_winzip_aes_extra(info):
                continue
            template_name = guess_kpa_template_for_entry_name(info.filename)
            if not template_name:
                continue
            is_high_confidence = (
                info.compress_type == zipfile.ZIP_STORED
                and template_is_high_confidence_auto_suggestion(
                    template_name,
                    info.file_size,
                    locale,
                )
            )
            is_worth_trying = template_is_worth_trying_auto_suggestion(
                template_name,
                info.file_size,
                locale,
            )
            if not is_high_confidence and not is_worth_trying:
                continue
            if not template_candidates_fit_entry_size(template_name, info.file_size, locale):
                continue
            reason = (
                loc(
                    locale,
                    "文件后缀、大小与模板特征都比较吻合",
                    "The file extension, size, and template characteristics match well",
                )
                if is_high_confidence
                else loc(
                    locale,
                    "文件类型很像模板题型，虽然不是 ZIP_STORED，但仍值得试一次",
                    "The file type strongly resembles a template KPA case. It is not ZIP_STORED, but it is still worth trying once",
                )
            )
            suggestions.append(
                TemplateKpaSuggestion(
                    inner_name=info.filename,
                    template_name=template_name,
                    file_size=info.file_size,
                    compress_type=info.compress_type,
                    confidence="high" if is_high_confidence else "medium",
                    reason=reason,
                )
            )
    return suggestions


def offer_template_kpa_after_standard_failures(
    zip_path: str,
    out_dir: str,
    locale: str,
) -> bool:
    suggestions = detect_template_kpa_suggestions(zip_path, locale)
    if not suggestions:
        return False

    print(
        loc(
            locale,
            "[*] 常规路径未命中，但检测到压缩包里有条目很像模板化已知明文攻击场景。",
            "[*] Standard attacks did not succeed, but this archive contains entries that look suitable for template-based known-plaintext attacks.",
        )
    )
    for suggestion in suggestions:
        print(
            loc(
                locale,
                f"[*] 候选条目: {suggestion.inner_name} -> 模板 {suggestion.template_name}（文件大小 {suggestion.file_size} 字节，{compress_type_label(suggestion.compress_type)}，置信度 {suggestion.confidence}）",
                f"[*] Candidate entry: {suggestion.inner_name} -> template {suggestion.template_name} (size {suggestion.file_size} bytes, {compress_type_label(suggestion.compress_type)}, confidence {suggestion.confidence})",
            )
        )
        print(loc(locale, f"[*] 原因: {suggestion.reason}", f"[*] Reason: {suggestion.reason}"))
        print(
            loc(
                locale,
                f"[*] 检测到 {suggestion.inner_name} 很像 {suggestion.template_name} 模板题型，推荐尝试 --kpa-template {suggestion.template_name}",
                f"[*] {suggestion.inner_name} looks like a {suggestion.template_name} template KPA case. Recommended option: --kpa-template {suggestion.template_name}",
            )
        )
        print(
            loc(
                locale,
                f"[*] 推荐命令: {format_template_kpa_recommendation_command(zip_path, suggestion)}",
                f"[*] Recommended command: {format_template_kpa_recommendation_command(zip_path, suggestion)}",
            )
        )

    should_try = prompt_yes_no(
        locale,
        "[?] 是否现在自动尝试这些内置 KPA 模板？(y/n): ",
        "[?] Try these built-in KPA templates now? (y/n): ",
    )
    if not should_try:
        print(
            loc(
                locale,
                "[*] 已跳过模板化已知明文攻击。",
                "[*] Skipping template-based known-plaintext attacks.",
            )
        )
        return False

    bk_tool = find_bkcrack_executable()
    if not bk_tool:
        bk_tool = offer_bkcrack_install(locale, required=True)
        if not bk_tool:
            return False

    for index, suggestion in enumerate(suggestions, start=1):
        print(
            loc(
                locale,
                f"[*] 正在尝试模板候选 {index}/{len(suggestions)}: {suggestion.inner_name} -> {suggestion.template_name}",
                f"[*] Trying template candidate {index}/{len(suggestions)}: {suggestion.inner_name} -> {suggestion.template_name}",
            )
        )
        attempts: list[KnownPlaintextAttempt] = []
        try:
            _, attempts, _ = build_known_plaintext_attempts(
                zip_path,
                None,
                locale,
                preferred_entry=suggestion.inner_name,
                template_name=suggestion.template_name,
            )
            if run_bkcrack_known_plaintext_attempts(
                zip_path,
                attempts,
                out_dir,
                locale,
                bk_tool,
            ):
                return True
        finally:
            cleanup_known_plaintext_attempts(attempts)

    print(
        loc(
            locale,
            "[*] 内置 KPA 模板已全部尝试完毕，仍未恢复成功。",
            "[*] All built-in KPA templates were tried, but none recovered the archive.",
        )
    )
    return False


def read_zip_entry_raw_data(zip_path: str, inner_name: str) -> bytes:
    with zipfile.ZipFile(zip_path, "r") as zf:
        info = zf.getinfo(inner_name)
        off = getattr(info, "header_offset", None)
        if off is None:
            raise ValueError("ZIP 条目缺少 header_offset，请使用 Python 3.7+")
        with open(zip_path, "rb") as fp:
            fp.seek(off)
            local = fp.read(30)
            if len(local) < 30 or local[:4] != b"PK\x03\x04":
                raise ValueError("本地文件头损坏或无效")
            fn_len = struct.unpack("<H", local[26:28])[0]
            ex_len = struct.unpack("<H", local[28:30])[0]
            fp.seek(off + 30 + fn_len + ex_len)
            return fp.read(info.compress_size)


def read_zip_entry_ciphertext(zip_path: str, inner_name: str) -> bytes:
    with zipfile.ZipFile(zip_path, "r") as zf:
        info = zf.getinfo(inner_name)
        if info.flag_bits & 0x1 == 0:
            raise ValueError(f"条目 '{inner_name}' 未设置加密标志")
    return read_zip_entry_raw_data(zip_path, inner_name)


def resolve_plaintext_zip_entry_name(
    plain_zip_path: str,
    target_inner_name: str,
    locale: str,
) -> str:
    with zipfile.ZipFile(plain_zip_path, "r") as zf:
        infos = [info for info in zf.infolist() if is_regular_member(info)]
        if not infos:
            raise ValueError(
                loc(
                    locale,
                    f"明文 ZIP '{plain_zip_path}' 中未找到可用文件。",
                    f"No usable file entries were found in plaintext ZIP '{plain_zip_path}'.",
                )
            )
        encrypted_infos = [info.filename for info in infos if info.flag_bits & 0x1]
        if encrypted_infos:
            raise ValueError(
                loc(
                    locale,
                    f"明文 ZIP '{plain_zip_path}' 中的条目仍然是加密的，无法作为已知明文源：{encrypted_infos[0]}",
                    f"Plaintext ZIP '{plain_zip_path}' still contains encrypted entries and cannot be used as a known-plaintext source: {encrypted_infos[0]}",
                )
            )
        names = [info.filename for info in infos]
        if target_inner_name in names:
            return target_inner_name
        if len(names) == 1:
            return names[0]
        basename_matches = [
            name for name in names if os.path.basename(name) == os.path.basename(target_inner_name)
        ]
        if len(basename_matches) == 1:
            return basename_matches[0]
    raise ValueError(
        loc(
            locale,
            f"明文 ZIP '{plain_zip_path}' 中未找到与目标条目 '{target_inner_name}' 对应的文件。若 ZIP 内有多个文件，请确保存在同名条目，或改用单独明文文件。",
            f"Plaintext ZIP '{plain_zip_path}' does not contain a file that matches target entry '{target_inner_name}'. If the ZIP contains multiple files, make sure a matching entry exists or provide a standalone plaintext file instead.",
        )
    )


def list_encrypted_regular_entries(zip_path: str, locale: str) -> list[str]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = [info for info in zf.infolist() if is_regular_member(info)]
        encrypted_infos = [info for info in infos if info.flag_bits & 0x1]
    if not encrypted_infos:
        raise ValueError(
            loc(
                locale,
                f"压缩包 '{zip_path}' 中未找到可用于已知明文攻击的加密文件。",
                f"No encrypted file entry suitable for known-plaintext attack was found in '{zip_path}'.",
            )
        )
    return [info.filename for info in encrypted_infos]


def resolve_kpa_cipher_entry_from_template(
    zip_path: str,
    template_name: str,
    locale: str,
    *,
    preferred_entry: Optional[str] = None,
) -> str:
    encrypted_names = list_encrypted_regular_entries(zip_path, locale)
    if preferred_entry:
        if preferred_entry not in encrypted_names:
            raise ValueError(
                loc(
                    locale,
                    f"指定的 ZIP 条目 '{preferred_entry}' 不存在，或该条目未加密。",
                    f"The specified ZIP entry '{preferred_entry}' does not exist, or it is not encrypted.",
                )
            )
        return preferred_entry
    template = normalize_kpa_template_name(template_name)
    expected_extensions = KPA_TEMPLATE_ENTRY_EXTENSIONS.get(template, ())
    matches = [
        name
        for name in encrypted_names
        if os.path.splitext(name)[1].lower() in expected_extensions
    ]
    if len(matches) == 1:
        return matches[0]
    if len(encrypted_names) == 1:
        return encrypted_names[0]
    raise ValueError(
        loc(
            locale,
            f"无法根据模板 '{template}' 自动判断对应的加密条目。请使用 -c 显式指定 ZIP 内文件名。",
            f"Could not automatically determine which encrypted ZIP entry matches template '{template}'. Use -c to specify the entry name explicitly.",
        )
    )


def resolve_kpa_cipher_entry_without_source(
    zip_path: str,
    locale: str,
    *,
    preferred_entry: Optional[str] = None,
) -> str:
    encrypted_names = list_encrypted_regular_entries(zip_path, locale)
    if preferred_entry:
        if preferred_entry not in encrypted_names:
            raise ValueError(
                loc(
                    locale,
                    f"指定的 ZIP 条目 '{preferred_entry}' 不存在，或该条目未加密。",
                    f"The specified ZIP entry '{preferred_entry}' does not exist, or it is not encrypted.",
                )
            )
        return preferred_entry
    if len(encrypted_names) == 1:
        return encrypted_names[0]
    raise ValueError(
        loc(
            locale,
            "未提供明文文件时，无法自动判断对应的加密条目。请使用 -c 指定 ZIP 内文件名。",
            "Without a plaintext file, the script cannot determine the encrypted target entry automatically. Use -c to specify the ZIP entry.",
        )
    )


def resolve_kpa_cipher_entry_name(
    zip_path: str,
    plaintext_path: str,
    locale: str,
    *,
    preferred_entry: Optional[str] = None,
) -> str:
    encrypted_names = list_encrypted_regular_entries(zip_path, locale)

    if preferred_entry:
        if preferred_entry not in encrypted_names:
            raise ValueError(
                loc(
                    locale,
                    f"指定的 ZIP 条目 '{preferred_entry}' 不存在，或该条目未加密。",
                    f"The specified ZIP entry '{preferred_entry}' does not exist, or it is not encrypted.",
                )
            )
        return preferred_entry

    if is_zip_archive(plaintext_path):
        with zipfile.ZipFile(plaintext_path, "r") as zf:
            plain_infos = [info for info in zf.infolist() if is_regular_member(info)]
            plain_names = [info.filename for info in plain_infos if not (info.flag_bits & 0x1)]
        exact_matches = [name for name in plain_names if name in encrypted_names]
        if len(exact_matches) == 1:
            return exact_matches[0]
        if len(plain_names) == 1:
            plain_basename = os.path.basename(plain_names[0])
            basename_matches = [
                name for name in encrypted_names if os.path.basename(name) == plain_basename
            ]
            if len(basename_matches) == 1:
                return basename_matches[0]

    plain_basename = os.path.basename(plaintext_path)
    if plain_basename in encrypted_names:
        return plain_basename
    basename_matches = [
        name for name in encrypted_names if os.path.basename(name) == plain_basename
    ]
    if len(basename_matches) == 1:
        return basename_matches[0]
    if len(encrypted_names) == 1:
        return encrypted_names[0]
    raise ValueError(
        loc(
            locale,
            f"无法根据明文源 '{plaintext_path}' 自动判断对应的加密条目。请使用 -c 显式指定 ZIP 内文件名。",
            f"Could not automatically determine which encrypted ZIP entry matches plaintext source '{plaintext_path}'. Use -c to specify the entry name explicitly.",
        )
    )


def load_known_plaintext_source(
    target_zip_path: str,
    target_inner_name: str,
    plaintext_path: str,
    locale: str,
) -> dict:
    del target_zip_path
    if is_zip_archive(plaintext_path):
        plain_entry = resolve_plaintext_zip_entry_name(
            plaintext_path,
            target_inner_name,
            locale,
        )
        plaintext_bytes = read_zip_entry_raw_data(plaintext_path, plain_entry)
        return {
            "plaintext_bytes": plaintext_bytes,
            "source_kind": "zip",
            "source_path": plaintext_path,
            "source_entry": plain_entry,
            "display_path": f"{plaintext_path}:{plain_entry}",
        }

    with open(plaintext_path, "rb") as fp:
        plaintext_bytes = fp.read()
    return {
        "plaintext_bytes": plaintext_bytes,
        "source_kind": "file",
        "source_path": plaintext_path,
        "source_entry": "",
        "display_path": plaintext_path,
    }


def build_known_plaintext_attempts(
    zip_path: str,
    plaintext_path: Optional[str],
    locale: str,
    *,
    preferred_entry: Optional[str] = None,
    plain_offset: Optional[int] = None,
    extra_specs: Optional[Sequence[tuple[int, bytes]]] = None,
    template_name: Optional[str] = None,
) -> tuple[str, list[KnownPlaintextAttempt], bool]:
    extra_specs = list(extra_specs or [])
    partial_mode = plain_offset is not None or bool(extra_specs) or bool(template_name)

    if plaintext_path:
        inner_name = resolve_kpa_cipher_entry_name(
            zip_path,
            plaintext_path,
            locale,
            preferred_entry=preferred_entry,
        )
    elif template_name:
        inner_name = resolve_kpa_cipher_entry_from_template(
            zip_path,
            template_name,
            locale,
            preferred_entry=preferred_entry,
        )
    else:
        inner_name = resolve_kpa_cipher_entry_without_source(
            zip_path,
            locale,
            preferred_entry=preferred_entry,
        )

    if not partial_mode and plaintext_path:
        plain_source = load_known_plaintext_source(
            zip_path,
            inner_name,
            plaintext_path,
            locale,
        )
        return (
            inner_name,
            [
                KnownPlaintextAttempt(
                    inner_name=inner_name,
                    plain_source=plain_source,
                    plain_offset=0,
                    extra_specs=[],
                    label=plain_source["display_path"],
                )
            ],
            False,
        )

    attempts: list[KnownPlaintextAttempt] = []
    template_candidates = (
        build_kpa_template_candidates(template_name, locale)
        if template_name
        else [None]
    )

    if plaintext_path:
        base_source = load_known_plaintext_source(
            zip_path,
            inner_name,
            plaintext_path,
            locale,
        )
        for candidate in template_candidates:
            attempt_offset = plain_offset if plain_offset is not None else (
                candidate.plain_offset if candidate else 0
            )
            candidate_extras = list(candidate.extra_specs) if candidate else []
            attempt_extras = candidate_extras + extra_specs
            label = base_source["display_path"]
            if candidate:
                label = f"{label} + template:{candidate.name}"
            attempts.append(
                KnownPlaintextAttempt(
                    inner_name=inner_name,
                    plain_source=base_source,
                    plain_offset=attempt_offset,
                    extra_specs=attempt_extras,
                    label=label,
                    template_name=template_name,
                )
            )
    elif template_name:
        for candidate in template_candidates:
            temp_path = write_temp_known_plaintext_fragment(
                candidate.plaintext_bytes,
                suffix=f"_{candidate.name}.bin",
            )
            temp_source = {
                "plaintext_bytes": candidate.plaintext_bytes,
                "source_kind": "file",
                "source_path": temp_path,
                "source_entry": "",
                "display_path": f"template:{candidate.name}",
            }
            attempt_offset = plain_offset if plain_offset is not None else candidate.plain_offset
            attempt_extras = list(candidate.extra_specs) + extra_specs
            attempts.append(
                KnownPlaintextAttempt(
                    inner_name=inner_name,
                    plain_source=temp_source,
                    plain_offset=attempt_offset,
                    extra_specs=attempt_extras,
                    label=temp_source["display_path"],
                    cleanup_paths=[temp_path],
                    template_name=template_name,
                )
            )
    else:
        attempts.append(
            KnownPlaintextAttempt(
                inner_name=inner_name,
                plain_source=None,
                plain_offset=plain_offset or 0,
                extra_specs=extra_specs,
                label="extra-bytes-only",
            )
        )

    return inner_name, attempts, True


def cleanup_known_plaintext_attempts(attempts: Sequence[KnownPlaintextAttempt]) -> None:
    for attempt in attempts:
        for path in attempt.cleanup_paths:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass


def zipcrypto_plaintext_matches_password(
    password: str, ciphertext: bytes, expected_plaintext: bytes
) -> bool:
    decrypter = _ZipDecrypter(password.encode("utf-8"))
    plain = decrypter(ciphertext)
    return plain[12:] == expected_plaintext


def parse_bkcrack_keys_from_output(text: str) -> Optional[Tuple[str, str, str]]:
    triples = []
    for line in text.splitlines():
        if "Internal representation for password" in line:
            continue
        match = re.search(
            r"\b([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})\b",
            line,
            re.IGNORECASE,
        )
        if match:
            triples.append(
                (
                    match.group(1).lower(),
                    match.group(2).lower(),
                    match.group(3).lower(),
                )
            )
    return triples[-1] if triples else None


def parse_bkcrack_recovered_password(text: str) -> Optional[str]:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("as text:"):
            return stripped.split(":", 1)[1].strip()
    match = re.search(r"^Password:\s*(.+)$", text, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return None


def decompress_zip_member_data(info: zipfile.ZipInfo, data: bytes) -> bytes:
    if info.compress_type == zipfile.ZIP_STORED:
        return data
    if info.compress_type == zipfile.ZIP_DEFLATED:
        return zlib.decompress(data, -15)
    if info.compress_type == zipfile.ZIP_BZIP2:
        return bz2.decompress(data)
    if info.compress_type == zipfile.ZIP_LZMA:
        return lzma.decompress(data)
    raise NotImplementedError(
        f"Unsupported compression method for '{info.filename}': {info.compress_type}"
    )


def extract_with_bkcrack_keys(
    bk: str,
    keys: tuple[str, str, str],
    zip_path: str,
    out_dir: str,
    locale: str,
) -> tuple[bool, list[str] | str]:
    k0, k1, k2 = keys
    _clean_and_create_outdir(out_dir)
    extracted_names: list[str] = []

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = [info for info in zf.infolist() if is_regular_member(info)]
            for info in infos:
                dest_path = os.path.join(out_dir, info.filename)
                parent_dir = os.path.dirname(dest_path)
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)

                if info.flag_bits & 0x1:
                    with tempfile.NamedTemporaryFile(
                        prefix="zipcracker_bkcrack_entry_",
                        suffix=".bin",
                        delete=False,
                    ) as tmp:
                        tmp_path = tmp.name
                    try:
                        proc = subprocess.run(
                            [
                                bk,
                                "-k",
                                k0,
                                k1,
                                k2,
                                "-C",
                                zip_path,
                                "-c",
                                info.filename,
                                "-d",
                                tmp_path,
                            ],
                            capture_output=True,
                            text=True,
                            timeout=None,
                        )
                        if proc.returncode != 0:
                            detail = (proc.stderr or proc.stdout or "").strip()
                            return (
                                False,
                                loc(
                                    locale,
                                    f"bkcrack 无法导出条目 '{info.filename}' 的解密数据: {detail}",
                                    f"bkcrack could not export deciphered data for entry '{info.filename}': {detail}",
                                ),
                            )
                        with open(tmp_path, "rb") as fp:
                            compressed_data = fp.read()
                    finally:
                        if os.path.exists(tmp_path):
                            try:
                                os.remove(tmp_path)
                            except OSError:
                                pass
                    payload = decompress_zip_member_data(info, compressed_data)
                else:
                    payload = zf.read(info.filename)

                with open(dest_path, "wb") as output:
                    output.write(payload)
                extracted_names.append(info.filename)
    except Exception as exc:
        return False, str(exc)

    return True, extracted_names


def _find_first_file_in_zip(zf) -> Optional[str]:
    try:
        for info in zf.infolist():
            if is_regular_member(info):
                return info.filename
    except Exception:
        try:
            for name in zf.namelist():
                if not name.endswith("/"):
                    return name
        except Exception:
            return None
    return None


def find_best_verification_entry(zf) -> Optional[str]:
    try:
        infos = [info for info in zf.infolist() if is_regular_member(info)]
    except Exception:
        return _find_first_file_in_zip(zf)
    if not infos:
        return None

    encrypted_infos = [info for info in infos if info.flag_bits & 0x1]
    candidates = encrypted_infos or infos

    def score(info: zipfile.ZipInfo) -> Tuple[int, int, int, str]:
        non_empty_rank = 0 if info.file_size > 0 else 1
        return (
            non_empty_rank,
            info.file_size,
            info.compress_size,
            info.filename,
        )

    return min(candidates, key=score).filename


def _clean_and_create_outdir(out_dir: str) -> None:
    if os.path.exists(out_dir):
        try:
            shutil.rmtree(out_dir)
        except Exception:
            pass
    os.makedirs(out_dir, exist_ok=True)


def is_zip_encrypted(file_path: str) -> bool:
    with zipfile.ZipFile(file_path) as zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                return True
    return False


def fix_zip_encrypted(file_path: str, temp_path: str) -> None:
    with zipfile.ZipFile(file_path) as zf, zipfile.ZipFile(temp_path, "w") as temp_zf:
        for info in zf.infolist():
            original_flag_bits = info.flag_bits
            try:
                if info.flag_bits & 0x1:
                    info.flag_bits ^= 0x1
                clean_info = copy.copy(info)
                temp_zf.writestr(clean_info, zf.read(info.filename))
            finally:
                info.flag_bits = original_flag_bits


def crack_crc(filename: str, crc: int, size: int, locale: str) -> None:
    """短明文 CRC32 枚举恢复：穷举可打印明文，直至 binascii.crc32 与 ZIP 条目记录一致。"""
    candidates = its.product(string.printable, repeat=size)
    print(
        loc(
            locale,
            "[+] 开始进行短明文 CRC32 枚举恢复······",
            "[+] Running short-plaintext CRC32 enumeration recovery...",
        )
    )
    for item in candidates:
        raw = "".join(item).encode()
        if crc == binascii.crc32(raw):
            print(
                loc(
                    locale,
                    f"[*] 短明文 CRC32 枚举恢复成功。\n[*] {filename} 的内容为：{raw.decode()}",
                    f"[*] Short-plaintext CRC32 enumeration recovery succeeded.\n[*] Content of {filename}: {raw.decode()}",
                )
            )
            break


def get_crc(zip_file: str, zf: zipfile.ZipFile, locale: str) -> bool:
    """若存在 1～6 字节条目，询问是否执行短明文 CRC32 枚举恢复；全部条目均由此完成时跳过字典爆破。"""
    cracked_all = 0
    file_list = [name for name in zf.namelist() if not name.endswith("/")]
    if not file_list:
        return False

    for filename in file_list:
        info = zf.getinfo(filename)
        if 0 < info.file_size <= 6:
            choice = input(
                timestamped_prompt(
                    loc(
                        locale,
                        f'[!] 压缩包 {zip_file} 中的 {filename} 为短明文（{info.file_size} 字节），是否进行短明文 CRC32 枚举恢复？（y/n）',
                        f'[!] "{filename}" in "{zip_file}" is short plaintext ({info.file_size} bytes). Run short-plaintext CRC32 enumeration recovery? (y/n) ',
                    )
                )
            )
            if choice.strip().lower() == "y":
                print(
                    loc(
                        locale,
                        f"[+] {filename} 在 ZIP 中记录的 CRC32：{info.CRC}",
                        f"[+] CRC32 stored in ZIP for {filename}: {info.CRC}",
                    )
                )
                crack_crc(filename, info.CRC, info.file_size, locale)
                cracked_all += 1

    if cracked_all >= len(file_list):
        print(
            loc(
                locale,
                f"[*] {zip_file} 内全部条目均已通过短明文 CRC32 枚举恢复，将跳过字典暴力破解。",
                f"[*] All entries in {zip_file} were recovered via short-plaintext CRC32 enumeration; skipping dictionary attack.",
            )
        )
        return True
    return False


def adjust_thread_count(max_limit: int = 128) -> int:
    raw = os.environ.get("ZIPCRACKER_THREADS", "").strip()
    if raw.isdigit():
        return max(1, min(int(raw), max_limit))
    try:
        cpu_count = multiprocessing.cpu_count() or 4
    except NotImplementedError:
        cpu_count = 4
    return max(1, min(max_limit, cpu_count * 4))


def bkcrack_job_count() -> int:
    raw = os.environ.get("BKCRACK_JOBS", "").strip()
    if raw.isdigit():
        return max(1, min(int(raw), 256))
    try:
        cpu_count = multiprocessing.cpu_count() or 4
    except NotImplementedError:
        cpu_count = 4
    return max(1, min(cpu_count * 2, 64))


def resolve_batch_size(max_workers: int) -> int:
    raw = os.environ.get("ZIPCRACKER_BATCH_SIZE", "").strip()
    if raw.isdigit():
        return max(128, min(int(raw), 65536))
    return max(1024, min(8192, max_workers * 128))


def resolve_prefetch_batches(max_workers: int) -> int:
    raw = os.environ.get("ZIPCRACKER_PREFETCH_BATCHES", "").strip()
    if raw.isdigit():
        return max(1, min(int(raw), 64))
    return max(2, min(16, max_workers))


def should_skip_dict_count() -> bool:
    raw = os.environ.get(ZIPCRACKER_SKIP_DICT_COUNT_ENV, "").strip().lower()
    return raw in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class PasswordBatch:
    passwords: Sequence[str]
    source_bytes_read: int = 0
    source_bytes_total: int = 0
    source_label: str = ""


def count_passwords(file_path: str) -> int:
    total = 0
    last_byte = b""
    with open(file_path, "rb") as fp:
        while True:
            chunk = fp.read(STREAM_READ_CHUNK_SIZE)
            if not chunk:
                break
            total += chunk.count(b"\n")
            last_byte = chunk[-1:]
    if last_byte and last_byte != b"\n":
        total += 1
    return total


def iter_password_file_batches_with_progress(
    file_path: str, batch_size: int
) -> Iterator[PasswordBatch]:
    total_bytes = os.path.getsize(file_path)
    source_label = os.path.basename(file_path) or file_path
    with open(file_path, "rb") as fp:
        batch: list[str] = []
        pending = b""

        while True:
            chunk = fp.read(STREAM_READ_CHUNK_SIZE)
            if not chunk:
                break
            pending += chunk
            lines = pending.split(b"\n")
            pending = lines.pop() if lines else b""
            consumed_bytes = fp.tell() - len(pending)
            for raw_line in lines:
                batch.append(normalize_password_line(raw_line.decode("utf-8", errors="ignore")))
                if len(batch) >= batch_size:
                    yield PasswordBatch(
                        passwords=batch,
                        source_bytes_read=consumed_bytes,
                        source_bytes_total=total_bytes,
                        source_label=source_label,
                    )
                    batch = []

        if pending:
            batch.append(normalize_password_line(pending.decode("utf-8", errors="ignore")))
        if batch:
            yield PasswordBatch(
                passwords=batch,
                source_bytes_read=total_bytes,
                source_bytes_total=total_bytes,
                source_label=source_label,
            )


def iter_password_file_batches(file_path: str, batch_size: int) -> Iterator[list[str]]:
    for batch in iter_password_file_batches_with_progress(file_path, batch_size):
        yield list(batch.passwords)


def batched_iterable(values: Iterable[str], batch_size: int) -> Iterator[list[str]]:
    batch: list[str] = []
    for value in values:
        batch.append(value)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def generate_numeric_passwords() -> Iterator[str]:
    for length in range(1, 7):
        for item in its.product(CHARSET_DIGITS, repeat=length):
            yield "".join(item)


def count_numeric_passwords() -> int:
    return sum(10**length for length in range(1, 7))


def parse_mask(mask: str) -> Tuple[list[Tuple[str, ...]], int]:
    tokens: list[Tuple[str, ...]] = []
    i = 0
    while i < len(mask):
        current = mask[i]
        if current == "?":
            if i + 1 < len(mask):
                placeholder = mask[i + 1]
                if placeholder == "d":
                    tokens.append(tuple(CHARSET_DIGITS))
                elif placeholder == "l":
                    tokens.append(tuple(CHARSET_LOWER))
                elif placeholder == "u":
                    tokens.append(tuple(CHARSET_UPPER))
                elif placeholder == "s":
                    tokens.append(tuple(CHARSET_SYMBOLS))
                elif placeholder == "?":
                    tokens.append(("?",))
                else:
                    tokens.append((mask[i : i + 2],))
                i += 2
            else:
                tokens.append(("?",))
                i += 1
        else:
            tokens.append((current,))
            i += 1

    total = 1
    for token_group in tokens:
        total *= max(1, len(token_group))
    if total == 0:
        total = 1
    return tokens, total


def prepare_kpa_context(
    zip_file: str, inner_name: str, plaintext_path: str, locale: str
) -> dict:
    with zipfile.ZipFile(zip_file, "r") as zf:
        info = zf.getinfo(inner_name)
        if info.flag_bits & 0x1 == 0:
            raise ValueError(
                loc(
                    locale,
                    "该条目未加密，无需已知明文攻击",
                    "This entry is not encrypted; known plaintext is unnecessary.",
                )
            )
        if _has_winzip_aes_extra(info):
            raise ValueError(
                loc(
                    locale,
                    "检测到 WinZip AES 加密；已知明文快速校验仅支持传统 ZipCrypto，请使用 AES 字典/掩码爆破或专用工具",
                    "WinZip AES detected; fast known-plaintext validation only supports legacy ZipCrypto. Use AES dictionary/mask attacks or a dedicated tool.",
                )
            )
        ciphertext = read_zip_entry_ciphertext(zip_file, inner_name)
        payload_len = len(ciphertext) - 12
        plain_source = load_known_plaintext_source(
            zip_file,
            inner_name,
            plaintext_path,
            locale,
        )
        plaintext_bytes = plain_source["plaintext_bytes"]
        if len(plaintext_bytes) != payload_len:
            raise ValueError(
                loc(
                    locale,
                    f"明文长度 ({len(plaintext_bytes)}) 与密文载荷长度 ({payload_len}) 不一致。当前明文来源: {plain_source['display_path']}。若传入的是 ZIP，请确保其中存在与目标条目对应的未加密文件；若传入的是普通文件，请确保它与加密头之后的压缩载荷等长。若你手里只有部分明文，可改用 --kpa-offset、-x/--kpa-extra 或 --kpa-template。",
                    f"Plaintext length ({len(plaintext_bytes)}) does not match ciphertext payload length ({payload_len}). Current plaintext source: {plain_source['display_path']}. If you supplied a ZIP, make sure it contains the matching unencrypted entry; if you supplied a regular file, it must match the encrypted payload after the 12-byte header. If you only have partial plaintext, try --kpa-offset, -x/--kpa-extra, or --kpa-template instead.",
                )
            )
    print(
        loc(
            locale,
            f"[+] 已知明文模式: 条目 '{inner_name}'，明文来源 '{plain_source['display_path']}'，明文载荷 {payload_len} 字节；将使用内存内 ZipCrypto 校验（比反复打开 ZIP 更快）。",
            f"[+] Known-plaintext mode: entry '{inner_name}', plaintext source '{plain_source['display_path']}', payload {payload_len} bytes; using in-memory ZipCrypto validation for faster checks.",
        )
    )
    return {
        "kpa_plaintext_bytes": plaintext_bytes,
        "kpa_ciphertext": ciphertext,
        "kpa_inner_name": inner_name,
    }


def try_fast_password_from_plaintext(
    ciphertext: bytes, plaintext_bytes: bytes
) -> Optional[str]:
    seen: set[str] = set()

    def try_one(password: str) -> Optional[str]:
        if password in seen:
            return None
        seen.add(password)
        if zipcrypto_plaintext_matches_password(password, ciphertext, plaintext_bytes):
            return password
        return None

    if os.path.isfile("password_list.txt"):
        try:
            for batch in iter_password_file_batches("password_list.txt", 4096):
                for password in batch:
                    hit = try_one(password)
                    if hit is not None:
                        return hit
        except OSError:
            pass

    for password in COMMON_EXTRA_PASSWORDS:
        hit = try_one(password)
        if hit is not None:
            return hit

    for password in generate_numeric_passwords():
        hit = try_one(password)
        if hit is not None:
            return hit
    return None


def bkcrack_recover_original_password(
    bk: str,
    jobs: int,
    k0: str,
    k1: str,
    k2: str,
    zip_path: str,
    inner_name: str,
    locale: str,
) -> Optional[str]:
    skip = os.environ.get("ZIPCRACKER_SKIP_BKCRACK_PW", "").strip().lower()
    if skip in ("1", "true", "yes", "on"):
        return None

    timeout_cfg = os.environ.get("BKCRACK_PW_TIMEOUT_SEC", "300").strip().lower()
    if timeout_cfg in ("skip", "no"):
        return None
    if timeout_cfg in ("0", "inf", "none", ""):
        timeout = None
    else:
        try:
            timeout = float(timeout_cfg)
        except ValueError:
            timeout = 300.0

    range_spec = os.environ.get("BKCRACK_PW_RANGE", "4..24").strip() or "4..24"
    charset = os.environ.get("BKCRACK_PW_CHARSET", "?a").strip() or "?a"

    print(
        loc(
            locale,
            f"[*] 尝试用 bkcrack 从内部密钥反推原始 ZIP口令（-r {range_spec} {charset}，限时 {timeout or '无限制'} 秒；跳过设 ZIPCRACKER_SKIP_BKCRACK_PW=1，不限时设 BKCRACK_PW_TIMEOUT_SEC=0）…",
            f"[*] Trying bkcrack password recovery from internal keys (-r {range_spec} {charset}, timeout {timeout or 'unlimited'}s; skip with ZIPCRACKER_SKIP_BKCRACK_PW=1, unlimited with BKCRACK_PW_TIMEOUT_SEC=0)...",
        )
    )

    cmd = [
        bk,
        "-j",
        str(jobs),
        "-k",
        k0,
        k1,
        k2,
        "-r",
        range_spec,
        charset,
        "-C",
        zip_path,
        "-c",
        inner_name,
    ]
    log_path = None
    proc = None
    log = ""
    try:
        fd, log_path = tempfile.mkstemp(prefix="zipcracker_bkcrack_pw_", suffix=".log")
        os.close(fd)
        with open(log_path, "w", encoding="utf-8", errors="replace") as log_fp:
            proc = subprocess.run(
                cmd,
                stdout=log_fp,
                stderr=subprocess.STDOUT,
                timeout=timeout,
            )
        with open(log_path, "r", encoding="utf-8", errors="replace") as log_fp:
            log = log_fp.read()
    except subprocess.TimeoutExpired:
        print(
            loc(
                locale,
                "[!] bkcrack 反推口令超时。可调大 BKCRACK_PW_TIMEOUT_SEC、缩小 BKCRACK_PW_RANGE，或设 BKCRACK_PW_TIMEOUT_SEC=0 不限时。",
                "[!] bkcrack password recovery timed out. Increase BKCRACK_PW_TIMEOUT_SEC, shrink BKCRACK_PW_RANGE, or set BKCRACK_PW_TIMEOUT_SEC=0 for no timeout.",
            )
        )
        return None
    finally:
        if log_path and os.path.exists(log_path):
            try:
                os.remove(log_path)
            except OSError:
                pass

    if proc is None or proc.returncode != 0:
        return None
    return parse_bkcrack_recovered_password(log)


def report_original_zip_password_after_bkcrack(
    bk: str,
    jobs: int,
    k0: str,
    k1: str,
    k2: str,
    zip_path: str,
    inner_name: str,
    plaintext_path: str,
    locale: str,
) -> None:
    skip = os.environ.get(BKCRACK_SKIP_ORIG_PW_RECOVERY_ENV, "").strip().lower()
    if skip in ("1", "true", "yes", "on"):
        print(
            loc(
                locale,
                "[*] 已按环境变量跳过原始 ZIP 密码反推。",
                "[*] Skipping original ZIP password recovery because the environment variable requested it.",
            )
        )
        return

    try:
        ciphertext = read_zip_entry_ciphertext(zip_path, inner_name)
        plain_source = load_known_plaintext_source(
            zip_path,
            inner_name,
            plaintext_path,
            locale,
        )
        plaintext_bytes = plain_source["plaintext_bytes"]
    except (OSError, ValueError) as exc:
        print(
            loc(
                locale,
                f"[*] 无法读取密文/明文以反推口令: {exc}",
                f"[*] Unable to read ciphertext/plaintext for password recovery: {exc}",
            )
        )
        return

    print(
        loc(
            locale,
            f"[*] 已完成解压，接下来会继续尝试反推出原始 ZIP 密码；如只关心解压结果，可先设 {BKCRACK_SKIP_ORIG_PW_RECOVERY_ENV}=1 跳过这一步。",
            f"[*] Extraction is done. The script will now keep trying to recover the original ZIP password; if you only care about extraction, set {BKCRACK_SKIP_ORIG_PW_RECOVERY_ENV}=1 to skip this step.",
        )
    )
    print(
        loc(
            locale,
            "[*] 正在用已知明文快速验证常见口令（字典+弱口令+6位内数字）…",
            "[*] Validating common passwords with known plaintext (dictionary + weak passwords + up to 6 digits)...",
        )
    )
    password = try_fast_password_from_plaintext(ciphertext, plaintext_bytes)
    if password:
        print(loc(locale, f"\n[+] 原始 ZIP 密码为：{password}", f"\n[+] Original ZIP password: {password}"))
        return

    recovered = bkcrack_recover_original_password(
        bk,
        jobs,
        k0,
        k1,
        k2,
        zip_path,
        inner_name,
        locale,
    )
    if recovered:
        print(loc(locale, f"\n[+] 原始 ZIP 密码为：{recovered}", f"\n[+] Original ZIP password: {recovered}"))
        return

    zip_abs = os.path.abspath(zip_path)
    print(
        loc(
            locale,
            f"\n[*] 未能自动反推出原始口令（文件已用内部密钥解压）。可手动执行：\n    bkcrack -k {k0} {k1} {k2} -r 4..32 '?p' -j {jobs} -C \"{zip_abs}\" -c \"{inner_name}\"",
            f"\n[*] Could not automatically recover the original password (the archive has already been decrypted with the recovered keys). You can run:\n    bkcrack -k {k0} {k1} {k2} -r 4..32 '?p' -j {jobs} -C \"{zip_abs}\" -c \"{inner_name}\"",
        )
    )


def run_bkcrack_known_plaintext_attack(
    zip_path: str,
    inner_name: str,
    plaintext_path: str,
    out_dir: str,
    locale: str,
    bk_path: Optional[str] = None,
    *,
    plain_offset: int = 0,
    extra_specs: Optional[Sequence[tuple[int, bytes]]] = None,
    plain_source_override: Optional[dict] = None,
    attempt_label: str = "",
) -> bool:
    bk = bk_path or find_bkcrack_executable()
    if not bk:
        print(
            loc(
                locale,
                "[!] 未找到 bkcrack 可执行文件。已知明文密钥恢复请安装: https://github.com/kimci86/bkcrack",
                "[!] bkcrack executable not found. Install it for known-plaintext key recovery: https://github.com/kimci86/bkcrack",
            )
        )
        return False

    jobs = bkcrack_job_count()
    extra_specs = list(extra_specs or [])
    try:
        if plain_source_override is not None:
            plain_source = plain_source_override
        elif plaintext_path:
            plain_source = load_known_plaintext_source(
                zip_path,
                inner_name,
                plaintext_path,
                locale,
            )
        else:
            plain_source = None
    except (OSError, ValueError) as exc:
        print(
            loc(
                locale,
                f"[!] 无法准备 bkcrack 已知明文源: {exc}",
                f"[!] Failed to prepare the bkcrack known-plaintext source: {exc}",
            )
        )
        return False
    known_total, max_contig = merge_known_plaintext_ranges(
        plain_offset,
        len(plain_source["plaintext_bytes"]) if plain_source else 0,
        extra_specs,
    )
    if attempt_label:
        print(
            loc(
                locale,
                f"[*] 正在尝试 KPA 方案: {attempt_label}",
                f"[*] Trying KPA strategy: {attempt_label}",
            )
        )
    if plain_source:
        print(
            loc(
                locale,
                f"[*] bkcrack 已知明文源: {plain_source['display_path']}，偏移 {plain_offset}，连续已知 {len(plain_source['plaintext_bytes'])} 字节，累计已知 {known_total} 字节。",
                f"[*] bkcrack plaintext source: {plain_source['display_path']}, offset {plain_offset}, contiguous known bytes {len(plain_source['plaintext_bytes'])}, total known bytes {known_total}.",
            )
        )
    else:
        print(
            loc(
                locale,
                f"[*] 当前使用纯附加字节模式，累计已知 {known_total} 字节，最大连续片段 {max_contig} 字节。",
                f"[*] Using extra-bytes-only mode, with {known_total} known bytes total and a longest contiguous fragment of {max_contig} bytes.",
            )
        )
    if known_total < 12 or max_contig < 8:
        print(
            loc(
                locale,
                "[*] 提示: 已知字节通常至少需要 12 字节、且至少 8 字节连续；当前条件较弱，攻击可能直接失败。",
                "[*] Tip: known-plaintext attacks usually need at least 12 known bytes, including 8 contiguous bytes. The current hints are weak, so the attack may fail immediately.",
            )
        )
    print(
        loc(
            locale,
            f"[+] 正在调用 bkcrack 已知明文攻击（-j {jobs} 线程；大量进度输出写入临时文件，避免管道阻塞拖慢攻击）…",
            f"[+] Running bkcrack known-plaintext attack (-j {jobs}; verbose output goes to a temp file to avoid pipe backpressure)...",
        )
    )
    cmd_attack = [
        bk,
        "-j",
        str(jobs),
        "-C",
        zip_path,
        "-c",
        inner_name,
    ]
    if plain_source:
        if plain_source["source_kind"] == "zip":
            cmd_attack.extend(
                [
                    "-P",
                    plain_source["source_path"],
                    "-p",
                    plain_source["source_entry"],
                ]
            )
        else:
            cmd_attack.extend(["-p", plain_source["source_path"]])
        if plain_offset:
            cmd_attack.extend(["-o", str(plain_offset)])
    for extra_offset, extra_bytes in extra_specs:
        cmd_attack.extend(["-x", str(extra_offset), extra_bytes.hex()])
    log_path = None
    proc = None
    combined = ""
    try:
        fd, log_path = tempfile.mkstemp(prefix="zipcracker_bkcrack_", suffix=".log")
        os.close(fd)
        with open(log_path, "w", encoding="utf-8", errors="replace") as log_fp:
            proc = subprocess.run(
                cmd_attack,
                stdout=log_fp,
                stderr=subprocess.STDOUT,
                timeout=None,
            )
        with open(log_path, "r", encoding="utf-8", errors="replace") as log_fp:
            combined = log_fp.read()
    except FileNotFoundError:
        print(loc(locale, "[!] 无法执行 bkcrack。", "[!] Unable to execute bkcrack."))
        return False
    finally:
        if log_path and os.path.exists(log_path):
            try:
                os.remove(log_path)
            except OSError:
                pass

    if proc is None:
        print(
            loc(
                locale,
                "[!] bkcrack 子进程未正常结束。",
                "[!] bkcrack subprocess did not finish correctly.",
            )
        )
        return False
    if proc.returncode != 0:
        print(combined)
        for line in describe_bkcrack_runtime_failure(
            locale,
            proc.returncode,
            combined,
        ):
            print(line)
        return False

    keys = parse_bkcrack_keys_from_output(combined)
    if not keys:
        print(combined)
        print(
            loc(
                locale,
                "[!] 未能从 bkcrack 输出中解析出三组密钥。",
                "[!] Failed to parse the recovered internal keys from bkcrack output.",
            )
        )
        return False

    k0, k1, k2 = keys
    key_tuple = (k0, k1, k2)
    print(
        loc(
            locale,
            f"[+] 已从已知明文恢复内部密钥: {k0} {k1} {k2}",
            f"[+] Recovered internal keys from known plaintext: {k0} {k1} {k2}",
        )
    )
    decrypted_zip = zip_path + ".bkcrack_decrypted.zip"
    try:
        subprocess.run(
            [
                bk,
                "-j",
                str(jobs),
                "-k",
                k0,
                k1,
                k2,
                "-D",
                decrypted_zip,
                "-C",
                zip_path,
            ],
            capture_output=True,
            text=True,
                check=True,
        )
    except subprocess.CalledProcessError as exc:
        print(exc.stderr or exc.stdout or str(exc))
        print(
            loc(
                locale,
                "[!] 使用 bkcrack 写出整包解密副本失败，正在尝试逐条目解密并直接提取文件...",
                "[!] Failed to write a fully decrypted archive with bkcrack. Falling back to per-entry decryption and direct extraction...",
            )
        )
        ok, result = extract_with_bkcrack_keys(
            bk,
            key_tuple,
            zip_path,
            out_dir,
            locale,
        )
        if not ok:
            print(
                loc(
                    locale,
                    f"[!] 逐条目解密提取也失败了: {result}",
                    f"[!] Per-entry decryption and extraction also failed: {result}",
                )
            )
            return False
        names = result
        print(
            loc(
                locale,
                f"\n[*] 已知明文攻击成功，已通过逐条目解密提取到 '{out_dir}': {names}",
                f"\n[*] Known-plaintext attack succeeded. Files were extracted via per-entry decryption to '{out_dir}': {names}",
            )
        )
    else:
        _clean_and_create_outdir(out_dir)
        try:
            with zipfile.ZipFile(decrypted_zip) as zf:
                zf.extractall(path=out_dir)
                names = zf.namelist()
            print(
                loc(
                    locale,
                    f"\n[*] 已知明文攻击成功，已解压到 '{out_dir}': {names}",
                    f"\n[*] Known-plaintext attack succeeded. Extracted to '{out_dir}': {names}",
                )
            )
        except Exception as exc:
            print(
                loc(
                    locale,
                    f"[!] 解压 bkcrack 解密副本失败: {exc}",
                    f"[!] Failed to extract the bkcrack-decrypted copy: {exc}",
                )
            )
            return False
    finally:
        if os.path.exists(decrypted_zip):
            try:
                os.remove(decrypted_zip)
            except OSError:
                pass
    if plain_source and plain_offset == 0 and not extra_specs:
        report_original_zip_password_after_bkcrack(
            bk,
            jobs,
            k0,
            k1,
            k2,
            zip_path,
            inner_name,
            plaintext_path,
            locale,
        )
    else:
        print(
            loc(
                locale,
                "[*] 当前恢复使用了部分明文 / 模板 / 附加字节，跳过原始 ZIP 密码反推。",
                "[*] The current recovery used partial plaintext, templates, or extra bytes, so original ZIP password recovery is being skipped.",
            )
        )
    return True


def run_bkcrack_known_plaintext_attempts(
    zip_path: str,
    attempts: Sequence[KnownPlaintextAttempt],
    out_dir: str,
    locale: str,
    bk_path: Optional[str] = None,
) -> bool:
    bk = bk_path or find_bkcrack_executable()
    if not bk:
        print(
            loc(
                locale,
                "[!] 未找到 bkcrack 可执行文件。已知明文密钥恢复请安装: https://github.com/kimci86/bkcrack",
                "[!] bkcrack executable not found. Install it for known-plaintext key recovery: https://github.com/kimci86/bkcrack",
            )
        )
        return False

    total = len(attempts)
    for index, attempt in enumerate(attempts, start=1):
        if total > 1:
            print(
                loc(
                    locale,
                    f"[*] 已知明文模板正在尝试第 {index}/{total} 组候选...",
                    f"[*] Trying known-plaintext template candidate {index}/{total}...",
                )
            )
        if run_bkcrack_known_plaintext_attack(
            zip_path,
            attempt.inner_name,
            attempt.plain_source["source_path"] if attempt.plain_source else "",
            out_dir,
            locale,
            bk,
            plain_offset=attempt.plain_offset,
            extra_specs=attempt.extra_specs,
            plain_source_override=attempt.plain_source,
            attempt_label=attempt.label,
        ):
            return True
        if total > 1 and index < total:
            print(
                loc(
                    locale,
                    "[*] 当前候选未恢复成功，继续尝试下一组已知明文参数。",
                    "[*] The current candidate did not recover the archive. Trying the next known-plaintext candidate.",
                )
            )
    return False


class PasswordVerifier:
    def __init__(
        self,
        zip_file: str,
        *,
        kpa_ciphertext: Optional[bytes] = None,
        kpa_plaintext_bytes: Optional[bytes] = None,
        kpa_inner_name: Optional[str] = None,
    ) -> None:
        self.zip_file = zip_file
        self.kpa_ciphertext = kpa_ciphertext
        self.kpa_plaintext_bytes = kpa_plaintext_bytes
        self.kpa_inner_name = kpa_inner_name
        self._thread_local = threading.local()

        with zipfile.ZipFile(zip_file, "r") as zf:
            self.verification_entry = find_best_verification_entry(zf)
            self.archive_names = zf.namelist()

    def _open_archive(self):
        if HAS_PYZIPPER:
            return pyzipper.AESZipFile(self.zip_file, "r")
        return zipfile.ZipFile(self.zip_file, "r")

    def _get_thread_archive(self):
        archive = getattr(self._thread_local, "archive", None)
        if archive is None:
            archive = self._open_archive()
            self._thread_local.archive = archive
        return archive

    def close_thread_archive(self) -> None:
        archive = getattr(self._thread_local, "archive", None)
        if archive is not None:
            try:
                archive.close()
            except Exception:
                pass
            self._thread_local.archive = None

    def reset_thread_archive(self) -> None:
        self.close_thread_archive()

    def verify_password(self, password: str) -> bool:
        if self.kpa_ciphertext is not None and self.kpa_plaintext_bytes is not None:
            return zipcrypto_plaintext_matches_password(
                password, self.kpa_ciphertext, self.kpa_plaintext_bytes
            )

        password_bytes = password.encode("utf-8")
        try:
            archive = self._get_thread_archive()
            if self.verification_entry:
                archive.read(self.verification_entry, pwd=password_bytes)
            else:
                archive.testzip(pwd=password_bytes)
            return True
        except RuntimeError:
            return False
        except KeyboardInterrupt:
            raise
        except Exception:
            self.reset_thread_archive()
            return False

    def extract(self, password: str, out_dir: str) -> list[str]:
        _clean_and_create_outdir(out_dir)
        password_bytes = password.encode("utf-8")
        with self._open_archive() as zf:
            zf.extractall(path=out_dir, pwd=password_bytes)
            return zf.namelist()


@dataclass
class ProgressState:
    total_passwords: int = 0
    attempted_passwords: int = 0
    current_password: str = ""
    found_password: Optional[str] = None
    source_label: str = ""
    source_bytes_total: int = 0
    source_bytes_read: int = 0
    stop_event: threading.Event = field(default_factory=threading.Event)
    finished_event: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def reset(
        self,
        total_passwords: int,
        *,
        source_label: str = "",
        source_bytes_total: int = 0,
    ) -> None:
        with self.lock:
            self.total_passwords = total_passwords
            self.attempted_passwords = 0
            self.current_password = ""
            self.found_password = None
            self.source_label = source_label
            self.source_bytes_total = source_bytes_total
            self.source_bytes_read = 0
        self.stop_event.clear()
        self.finished_event.clear()

    def record_attempts(self, attempted: int, last_password: str) -> None:
        with self.lock:
            self.attempted_passwords += attempted
            self.current_password = last_password

    def update_source_progress(
        self,
        *,
        source_bytes_read: int,
        source_bytes_total: int = 0,
        source_label: str = "",
    ) -> None:
        with self.lock:
            if source_label:
                self.source_label = source_label
            if source_bytes_total > 0:
                self.source_bytes_total = source_bytes_total
            if source_bytes_read >= self.source_bytes_read:
                self.source_bytes_read = source_bytes_read

    def mark_success(self, password: str) -> bool:
        with self.lock:
            if self.found_password is not None:
                return False
            self.found_password = password
            self.current_password = password
        self.stop_event.set()
        return True


def format_current_password(password: str, max_chars: int = 48) -> str:
    if len(password) <= max_chars:
        return password
    return password[: max_chars - 3] + "..."


def display_progress(locale: str, state: ProgressState, start_time: float) -> None:
    while not state.finished_event.is_set():
        time.sleep(0.1)
        with state.lock:
            attempted = state.attempted_passwords
            total = state.total_passwords
            current_password = format_current_password(state.current_password)
            source_label = state.source_label
            source_bytes_total = state.source_bytes_total
            source_bytes_read = state.source_bytes_read

        elapsed = max(time.time() - start_time, 1e-9)
        speed = int(attempted / elapsed)
        if total > 0:
            progress = min(100.0, attempted / total * 100)
            remaining = max(total - attempted, 0)
            remain_seconds = remaining / speed if speed > 0 else 0
            remain_text = time.strftime("%H:%M:%S", time.gmtime(remain_seconds))
            line = loc(
                locale,
                f"\r[-] 当前破解进度：{progress:.2f}%，剩余时间：{remain_text}，当前时速：{speed}个/s，正在尝试密码:{current_password:<20}",
                f"\r[-] Progress: {progress:.2f}%, Time Left: {remain_text}, Speed: {speed} pass/s, Trying: {current_password:<20}",
            )
        elif source_bytes_total > 0:
            progress = min(100.0, source_bytes_read / max(source_bytes_total, 1) * 100)
            byte_speed = source_bytes_read / elapsed
            remain_seconds = (
                max(source_bytes_total - source_bytes_read, 0) / byte_speed
                if byte_speed > 0
                else 0
            )
            remain_text = time.strftime("%H:%M:%S", time.gmtime(remain_seconds))
            label_text = source_label or loc(locale, "字典", "dictionary")
            line = loc(
                locale,
                f"\r[-] 流式进度：{progress:.2f}%（{format_bytes(source_bytes_read)}/{format_bytes(source_bytes_total)}，{label_text}），剩余时间：{remain_text}，当前时速：{speed}个/s，文件吞吐：{format_bytes(byte_speed)}/s，正在尝试密码:{current_password:<20}",
                f"\r[-] Streaming progress: {progress:.2f}% ({format_bytes(source_bytes_read)}/{format_bytes(source_bytes_total)}, {label_text}), Time Left: {remain_text}, Speed: {speed} pass/s, File Throughput: {format_bytes(byte_speed)}/s, Trying: {current_password:<20}",
            )
        else:
            line = loc(
                locale,
                f"\r[-] 流式模式：已尝试 {attempted} 个密码，当前时速：{speed}个/s，正在尝试密码:{current_password:<20}",
                f"\r[-] Streaming mode: {attempted} passwords tried, Speed: {speed} pass/s, Trying: {current_password:<20}",
            )

        print(line, end="", flush=True)


def run_parallel_passwords(
    verifier: PasswordVerifier,
    password_batches: Iterable[Sequence[str] | PasswordBatch],
    total_passwords: int,
    out_dir: str,
    locale: str,
    max_workers: int,
    *,
    source_label: str = "",
    source_bytes_total: int = 0,
) -> bool:
    progress = ProgressState()
    progress.reset(
        total_passwords,
        source_label=source_label,
        source_bytes_total=source_bytes_total,
    )
    start_time = time.time()
    display_thread = threading.Thread(
        target=display_progress,
        args=(locale, progress, start_time),
        daemon=True,
    )
    display_thread.start()

    task_queue: queue.Queue[Optional[Sequence[str]]] = queue.Queue(
        maxsize=resolve_prefetch_batches(max_workers)
    )
    workers: list[threading.Thread] = []

    def worker() -> None:
        try:
            while True:
                batch = task_queue.get()
                try:
                    if batch is None:
                        break
                    passwords = batch.passwords if isinstance(batch, PasswordBatch) else batch
                    attempted = 0
                    last_password = ""
                    for password in passwords:
                        if progress.stop_event.is_set():
                            break
                        attempted += 1
                        last_password = password
                        if verifier.verify_password(password):
                            progress.mark_success(password)
                            break
                        if attempted >= 256:
                            progress.record_attempts(attempted, last_password)
                            attempted = 0
                    if attempted:
                        progress.record_attempts(attempted, last_password)
                finally:
                    task_queue.task_done()
        finally:
            verifier.close_thread_archive()

    for _ in range(max_workers):
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        workers.append(thread)

    producer_error: Optional[BaseException] = None
    try:
        for batch in password_batches:
            if progress.stop_event.is_set():
                break
            passwords = batch.passwords if isinstance(batch, PasswordBatch) else batch
            if isinstance(batch, PasswordBatch):
                progress.update_source_progress(
                    source_bytes_read=batch.source_bytes_read,
                    source_bytes_total=batch.source_bytes_total,
                    source_label=batch.source_label,
                )
            if passwords:
                task_queue.put(batch)
    except BaseException as exc:
        producer_error = exc
    finally:
        if source_bytes_total > 0:
            progress.update_source_progress(
                source_bytes_read=source_bytes_total,
                source_bytes_total=source_bytes_total,
                source_label=source_label,
            )
        for _ in workers:
            task_queue.put(None)
        task_queue.join()
        for thread in workers:
            thread.join()
        progress.finished_event.set()
        display_thread.join(timeout=0.2)

    print()

    if producer_error is not None:
        raise producer_error

    if progress.found_password:
        print(
            loc(
                locale,
                f"\n[+] 恭喜您！密码破解成功, 该压缩包的密码为：{progress.found_password}",
                f"\n[+] Success! The password is: {progress.found_password}",
            )
        )
        try:
            names = verifier.extract(progress.found_password, out_dir)
            print(
                loc(
                    locale,
                    f"\n[*] 系统已为您自动提取出 {len(names)} 个文件到 '{out_dir}' 文件夹中: {names}",
                    f"\n[*] Successfully extracted {len(names)} file(s) to '{out_dir}': {names}",
                )
            )
        except Exception as exc:
            print(
                loc(
                    locale,
                    f"\n[!] 密码正确，但解压文件时发生错误: {exc}",
                    f"\n[!] Password is correct, but extraction failed: {exc}",
                )
            )
        return True
    return False


def crack_password_with_mask(
    zip_file: str,
    mask: str,
    verifier: PasswordVerifier,
    locale: str,
    out_dir: str,
) -> bool:
    token_groups, total_passwords = parse_mask(mask)
    if total_passwords > 100_000_000_000:
        choice = input(
            timestamped_prompt(
                loc(
                    locale,
                    f"[!]警告：掩码 '{mask}' 将生成 {total_passwords:,} 种组合，可能需要极长时间。是否继续？ (y/n): ",
                    f"[!] Warning: The mask '{mask}' will generate {total_passwords:,} combinations, which may take a very long time. Continue? (y/n): ",
                )
            )
        )
        if choice.strip().lower() != "y":
            print(loc(locale, "[-] 用户已中止攻击。", "[-] Attack aborted by user."))
            return False

    print(
        loc(
            locale,
            f"\n[+] 开始使用掩码 '{mask}' 进行攻击。",
            f"\n[+] Starting attack with mask '{mask}'.",
        )
    )
    print(
        loc(
            locale,
            f"[+] 需要尝试的密码总数组合为: {total_passwords:,}",
            f"[+] Total password combinations to try: {total_passwords:,}",
        )
    )
    max_threads = adjust_thread_count()
    print(
        loc(
            locale,
            f"[+] 动态调整线程数为: {max_threads}个",
            f"[+] Dynamically adjusted thread count to: {max_threads}",
        )
    )

    password_iter = ("".join(parts) for parts in its.product(*token_groups))
    found = run_parallel_passwords(
        verifier,
        batched_iterable(password_iter, resolve_batch_size(max_threads)),
        total_passwords,
        out_dir,
        locale,
        max_threads,
    )
    if not found:
        print(
            loc(
                locale,
                "\n[-] 非常抱歉，掩码生成的所有密码均已尝试，请检查您的掩码或尝试其他方法！",
                "\n[-] Sorry, all passwords generated by the mask have been tried. Please check your mask or try another method.",
            )
        )
    return found


def crack_password_with_file(
    zip_file: str,
    dict_file: str,
    verifier: PasswordVerifier,
    locale: str,
    out_dir: str,
) -> bool:
    total_passwords = 0
    try:
        dict_size_bytes = os.path.getsize(dict_file)
    except OSError:
        dict_size_bytes = 0
    if not should_skip_dict_count():
        try:
            total_passwords = count_passwords(dict_file)
        except OSError as exc:
            print(
                loc(
                    locale,
                    f"[!] 加载字典文件失败，原因：{exc}",
                    f"[!] Failed to load dictionary file: {exc}",
                )
            )
            return False

    dict_type = (
        loc(locale, "内置字典", "Built-in Dictionary")
        if os.path.basename(dict_file) == "password_list.txt"
        else loc(locale, "用户自定义字典", "Custom Dictionary")
    )
    print(
        loc(
            locale,
            f"\n[+] 加载{dict_type}[{dict_file}]成功！",
            f"\n[+] Successfully loaded {dict_type} [{dict_file}]!",
        )
    )
    if total_passwords > 0:
        print(
            loc(
                locale,
                f"[+] 当前字典总密码数: {total_passwords}",
                f"[+] Total passwords in current dictionary: {total_passwords}",
            )
        )
    else:
        print(
            loc(
                locale,
                f"[*] 已跳过字典总数预统计（设置 {ZIPCRACKER_SKIP_DICT_COUNT_ENV}=1），将直接开始流式爆破。",
                f"[*] Skipping the upfront dictionary line count ({ZIPCRACKER_SKIP_DICT_COUNT_ENV}=1). Starting the streaming attack immediately.",
            )
        )
        if dict_size_bytes > 0:
            print(
                loc(
                    locale,
                    f"[*] 当前字典文件大小: {format_bytes(dict_size_bytes)}；进度条将按文件读取进度实时显示。",
                    f"[*] Current dictionary size: {format_bytes(dict_size_bytes)}. Progress will be shown by streamed file read position.",
                )
            )

    max_threads = adjust_thread_count()
    print(
        loc(
            locale,
            f"[+] 动态调整线程数为: {max_threads}个",
            f"[+] Dynamically adjusted thread count to: {max_threads}",
        )
    )
    try:
        found = run_parallel_passwords(
            verifier,
            iter_password_file_batches_with_progress(
                dict_file,
                resolve_batch_size(max_threads),
            ),
            total_passwords,
            out_dir,
            locale,
            max_threads,
            source_label=os.path.basename(dict_file) or dict_file,
            source_bytes_total=dict_size_bytes,
        )
    except OSError as exc:
        print(
            loc(
                locale,
                f"[!] 加载字典文件失败，原因：{exc}",
                f"[!] Failed to load dictionary file: {exc}",
            )
        )
        return False

    if not found:
        print(
            loc(
                locale,
                f"\n[-] 非常抱歉，字典 {dict_file} 中的所有密码均已尝试完毕。",
                f"\n[-] Sorry, all passwords in the dictionary {dict_file} have been tried.",
            )
        )
    return found


def crack_password_with_file_or_dir(
    zip_file: str,
    dict_file_or_dir: str,
    verifier: PasswordVerifier,
    locale: str,
    out_dir: str,
) -> bool:
    if os.path.isdir(dict_file_or_dir):
        for filename in sorted(os.listdir(dict_file_or_dir)):
            file_path = os.path.join(dict_file_or_dir, filename)
            if crack_password_with_file_or_dir(
                zip_file, file_path, verifier, locale, out_dir
            ):
                return True
        return False

    if os.path.isfile(dict_file_or_dir):
        return crack_password_with_file(
            zip_file,
            dict_file_or_dir,
            verifier,
            locale,
            out_dir,
        )

    print(
        loc(
            locale,
            f"[!] 字典路径无效或文件不存在: {dict_file_or_dir!r}，请检查路径。",
            f"[!] Invalid dictionary path or file not found: {dict_file_or_dir!r}.",
        )
    )
    return False


def crack_with_generated_numeric_dict(
    zip_file: str,
    verifier: PasswordVerifier,
    locale: str,
    out_dir: str,
) -> bool:
    print(
        loc(
            locale,
            "\n[-] 内置字典破解失败或未找到，开始尝试1-6位纯数字字典...",
            "\n[-] Built-in dictionary failed or was not found. Trying the 1-6 digit numeric dictionary...",
        )
    )
    total_passwords = count_numeric_passwords()
    print(
        loc(
            locale,
            f"\n[+] 加载1-6位纯数字字典成功！总密码数: {total_passwords}",
            f"\n[+] Loaded the 1-6 digit numeric dictionary successfully! Total passwords: {total_passwords}",
        )
    )

    max_threads = adjust_thread_count()
    print(
        loc(
            locale,
            f"[+] 动态调整线程数为: {max_threads}个",
            f"[+] Dynamically adjusted thread count to: {max_threads}",
        )
    )

    found = run_parallel_passwords(
        verifier,
        batched_iterable(generate_numeric_passwords(), resolve_batch_size(max_threads)),
        total_passwords,
        out_dir,
        locale,
        max_threads,
    )
    if not found:
        print(
            loc(
                locale,
                "\n[-] 非常抱歉，1-6位纯数字字典中的所有密码均已尝试完毕。",
                "\n[-] Sorry, all passwords from the 1-6 digit numeric dictionary have been tried.",
            )
        )
    return found


def print_banner(locale: str) -> None:
    raw_print(
        loc(
            locale,
            r"""                          
     ______          ____                _   [*]Hx0战队      
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \  | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|   
           |_| |_____|                                 
    #Coded By Asaotomo         Update:2026.04.10 (Core Engine Refactor)
            """,
            r"""                          
     ______          ____                _   [*]Hx0 Team
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \  | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|   
           |_| |_____|                                 
    #Coded By Asaotomo         Update:2026.04.10 (Core Engine Refactor)
            """,
        )
    )


def print_version() -> None:
    raw_print(f"ZipCracker {ZIPCRACKER_VERSION}")


def print_usage(locale: str, script_name: str) -> None:
    if locale == "en":
        raw_print("\n--- Dictionary Attack ---")
        raw_print(f"[*] Usage 1 (Default Sequence): python {script_name} YourZipFile.zip")
        raw_print("         └─ Default order: Tries 'password_list.txt' first, then 1-6 digit numbers.")
        raw_print(f"[*] Usage 2 (Custom Dictionary): python {script_name} YourZipFile.zip YourDict.txt")
        raw_print(f"[*] Usage 3 (Dictionary Directory): python {script_name} YourZipFile.zip YourDictDirectory")
        raw_print("\n--- Mask Attack ---")
        raw_print(f"[*] Usage 4 (Mask): python {script_name} YourZipFile.zip -m 'your?dmask?l'")
        raw_print("[*]  ?d: digits, ?l: lowercase, ?u: uppercase, ?s: symbols, ??: literal '?'")
        raw_print("\n--- Known Plaintext (ZipCrypto) ---")
        raw_print(f"[*] Usage 5 (KPA): python {script_name} enc.zip -kpa plain.txt [ -c path/in/zip ] [dictionary or -m mask]")
        raw_print("         └─ If bkcrack is on PATH, the script first tries dictionary-free recovery automatically.")
        raw_print("         └─ If bkcrack is missing, the script will show OS-specific installation guidance and can offer a one-click local install.")
        raw_print(f"[*] Usage 6 (Partial KPA): python {script_name} enc.zip -kpa part.bin --kpa-offset 78 -x 0 4d5a")
        raw_print(f"[*] Usage 7 (Template KPA): python {script_name} enc.zip --kpa-template png [ -c image.png ]")
        raw_print(f"[*] Usage 8 (bkcrack only): python {script_name} enc.zip -kpa plain.txt [ -c inner ] --bkcrack")
        raw_print("\n--- Optional Arguments ---")
        raw_print(f"[*] Specify Output Directory: python {script_name} ... -o YourOutDir")
        raw_print("[*] KPA offset: --kpa-offset 78")
        raw_print("[*] KPA extra bytes: -x 0 4d5a  (repeatable; also accepts 0:4d5a)")
        raw_print(f"[*] KPA templates: --kpa-template {' | '.join(KPA_TEMPLATE_CHOICES)}")
        raw_print(f"[*] Help / Version: python {script_name} --help | --version")
        return

    raw_print("\n--- 字典攻击 ---")
    raw_print(f"[*] 用法1(内置序列): python {script_name} YourZipFile.zip")
    raw_print("         └─ 默认顺序: 先尝试 password_list.txt 文件, 再尝试1-6位纯数字。")
    raw_print(f"[*] 用法2(自定义字典): python {script_name} YourZipFile.zip YourDict.txt")
    raw_print(f"[*] 用法3(字典目录):   python {script_name} YourZipFile.zip YourDictDirectory")
    raw_print("\n--- 掩码攻击 ---")
    raw_print(f"[*] 用法4(掩码):      python {script_name} YourZipFile.zip -m 'your?dmask?l'")
    raw_print("[*]  ?d: 数字, ?l: 小写字母, ?u: 大写字母, ?s: 特殊符号, ??: 问号自身")
    raw_print("\n--- 已知明文 (ZipCrypto) ---")
    raw_print(f"[*] 用法5(KPA):  python {script_name} enc.zip -kpa plain.txt [ -c path/in/zip ] [字典或 -m 掩码]")
    raw_print("         └─ 若系统 PATH 中有 bkcrack，会先自动尝试无字典恢复；失败则继续字典/掩码（无交互）。")
    raw_print("         └─ 若未检测到 bkcrack，脚本会按当前操作系统给出安装方式，并可交互式执行一键本地安装。")
    raw_print("         └─ 明文须与加密流中 12 字节头之后的载荷一致（STORED 时常与解压后内容相同）。")
    raw_print(f"[*] 用法6(部分明文): python {script_name} enc.zip -kpa part.bin --kpa-offset 78 -x 0 4d5a")
    raw_print(f"[*] 用法7(模板KPA):  python {script_name} enc.zip --kpa-template png [ -c image.png ]")
    raw_print(f"[*] 用法8(仅bkcrack): python {script_name} enc.zip -kpa plain.txt [ -c inner ] --bkcrack")
    raw_print("\n--- 可选参数 ---")
    raw_print(f"[*] 指定输出目录:  python {script_name} ... -o YourOutDir")
    raw_print("[*] KPA 偏移量:    --kpa-offset 78")
    raw_print("[*] KPA 附加字节:  -x 0 4d5a  (可重复；也支持 0:4d5a)")
    raw_print(f"[*] KPA 模板:      --kpa-template {' | '.join(KPA_TEMPLATE_CHOICES)}")
    raw_print(f"[*] 帮助 / 版本:    python {script_name} --help | --version")


def run_cli(locale: str = "zh") -> int:
    try:
        print_banner(locale)

        if len(sys.argv) < 2:
            print_usage(locale, sys.argv[0])
            return 0
        if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
            print_usage(locale, sys.argv[0])
            return 0
        if len(sys.argv) == 2 and sys.argv[1] in ("-v", "--version"):
            print_version()
            return 0

        zip_file = sys.argv[1]
        basic_default_mode = len(sys.argv) == 2
        out_dir = OUT_DIR_DEFAULT
        dict_path_or_mask_flag = None
        mask_value = None
        kpa_plain_path = None
        kpa_inner_name = None
        kpa_offset = None
        kpa_extra_specs: list[tuple[int, bytes]] = []
        kpa_template_name = None
        use_bkcrack_recover = False

        index = 2
        while index < len(sys.argv):
            arg = sys.argv[index]
            if arg in ("-o", "--out"):
                if index + 1 >= len(sys.argv):
                    print(
                        loc(
                            locale,
                            "[!] 错误: -o 参数后未提供目录名。",
                            "[!] Error: No directory name provided after -o.",
                        )
                    )
                    return 1
                out_dir = sys.argv[index + 1]
                index += 2
            elif arg in ("-m", "--mask"):
                if index + 1 >= len(sys.argv):
                    print(
                        loc(
                            locale,
                            "[!] 错误: -m 参数后未提供掩码字符串。",
                            "[!] Error: No mask string provided after -m.",
                        )
                    )
                    return 1
                dict_path_or_mask_flag = "-m"
                mask_value = sys.argv[index + 1]
                index += 2
            elif arg in ("-kpa", "--kpa"):
                if index + 1 >= len(sys.argv):
                    print(
                        loc(
                            locale,
                            "[!] 错误: -kpa 后应提供已知明文文件路径。",
                            "[!] Error: -kpa requires a known plaintext file path.",
                        )
                    )
                    return 1
                kpa_plain_path = sys.argv[index + 1]
                index += 2
            elif arg in ("-c", "--cipher-entry"):
                if index + 1 >= len(sys.argv):
                    print(
                        loc(
                            locale,
                            "[!] 错误: -c 后应提供 ZIP 内条目路径名。",
                            "[!] Error: -c requires an entry name inside the ZIP.",
                        )
                    )
                    return 1
                kpa_inner_name = sys.argv[index + 1]
                index += 2
            elif arg == "--kpa-offset":
                if index + 1 >= len(sys.argv):
                    print(
                        loc(
                            locale,
                            "[!] 错误: --kpa-offset 后应提供一个非负整数。",
                            "[!] Error: --kpa-offset requires a non-negative integer.",
                        )
                    )
                    return 1
                try:
                    kpa_offset = parse_kpa_offset(sys.argv[index + 1], locale)
                except ValueError as exc:
                    print(loc(locale, f"[!] 错误: {exc}", f"[!] Error: {exc}"))
                    return 1
                index += 2
            elif arg in ("-x", "--kpa-extra"):
                if index + 1 >= len(sys.argv):
                    print(
                        loc(
                            locale,
                            "[!] 错误: -x/--kpa-extra 后应提供 offset 和 hex，或使用 offset:hex。",
                            "[!] Error: -x/--kpa-extra requires offset and hex bytes, or offset:hex.",
                        )
                    )
                    return 1
                next_value = sys.argv[index + 1]
                if ":" in next_value and (
                    index + 2 >= len(sys.argv) or sys.argv[index + 2].startswith("-")
                ):
                    offset_text, hex_text = next_value.split(":", 1)
                    step = 2
                else:
                    if index + 2 >= len(sys.argv):
                        print(
                            loc(
                                locale,
                                "[!] 错误: -x/--kpa-extra 需要两个值，例如 -x 0 4d5a。",
                                "[!] Error: -x/--kpa-extra needs two values, for example: -x 0 4d5a.",
                            )
                        )
                        return 1
                    offset_text = sys.argv[index + 1]
                    hex_text = sys.argv[index + 2]
                    step = 3
                try:
                    kpa_extra_specs.append(
                        parse_kpa_extra_spec(offset_text, hex_text, locale)
                    )
                except ValueError as exc:
                    print(loc(locale, f"[!] 错误: {exc}", f"[!] Error: {exc}"))
                    return 1
                index += step
            elif arg == "--kpa-template":
                if index + 1 >= len(sys.argv):
                    print(
                        loc(
                            locale,
                            "[!] 错误: --kpa-template 后应提供模板名。",
                            "[!] Error: --kpa-template requires a template name.",
                        )
                    )
                    return 1
                kpa_template_name = normalize_kpa_template_name(sys.argv[index + 1])
                if kpa_template_name not in KPA_TEMPLATE_CHOICES:
                    print(
                        loc(
                            locale,
                            f"[!] 错误: 不支持的 KPA 模板 '{sys.argv[index + 1]}'。可用模板: {', '.join(KPA_TEMPLATE_CHOICES)}",
                            f"[!] Error: Unsupported KPA template '{sys.argv[index + 1]}'. Available templates: {', '.join(KPA_TEMPLATE_CHOICES)}",
                        )
                    )
                    return 1
                index += 2
            elif arg == "--bkcrack":
                use_bkcrack_recover = True
                index += 1
            else:
                if dict_path_or_mask_flag is None:
                    dict_path_or_mask_flag = arg
                index += 1

        if not os.path.exists(zip_file):
            print(
                loc(
                    locale,
                    f"[!]错误: 文件 '{zip_file}' 未找到。",
                    f"[!] Error: File '{zip_file}' not found.",
                )
            )
            return 1

        kpa_requested = bool(kpa_plain_path or kpa_template_name or kpa_extra_specs)

        if use_bkcrack_recover and not kpa_requested:
            print(
                loc(
                    locale,
                    "[!] --bkcrack 需与已知明文参数同时使用，例如 -kpa / --kpa-template / -x。",
                    "[!] --bkcrack must be used together with known-plaintext arguments such as -kpa / --kpa-template / -x.",
                )
            )
            return 1

        if not kpa_requested and kpa_offset is not None:
            print(
                loc(
                    locale,
                    "[!] --kpa-offset 需要与 -kpa 或 --kpa-template 一起使用。",
                    "[!] --kpa-offset must be used together with -kpa or --kpa-template.",
                )
            )
            return 1

        if kpa_plain_path and not os.path.isfile(kpa_plain_path):
            print(
                loc(
                    locale,
                    f"[!] 已知明文文件不存在: {kpa_plain_path}",
                    f"[!] Known plaintext file does not exist: {kpa_plain_path}",
                )
            )
            return 1

        archive_profile = collect_archive_encryption_profile(zip_file)
        pyzipper_ready = offer_pyzipper_install(locale, zip_file)
        for line in archive_encryption_notice_lines(
            locale,
            archive_profile,
            pyzipper_ready=pyzipper_ready,
        ):
            print(line)
        if not pyzipper_ready and not HAS_PYZIPPER:
            print(
                loc(
                    locale,
                    "[*] 当前仍未启用 pyzipper，因此如果目标条目使用 AES，加密验证或解压可能无法正常完成。",
                    "[*] pyzipper is still unavailable, so AES-encrypted target entries may not verify or extract correctly.",
                )
            )

        is_truly_encrypted = False
        if is_zip_encrypted(zip_file):
            print(
                loc(
                    locale,
                    f"[!] 系统检测到 {zip_file} 的加密标志位已开启，正在尝试进行伪加密修复...",
                    f"[!] Encryption flag detected in {zip_file}. Attempting pseudo-encryption repair...",
                )
            )
            fixed_zip_name = zip_file + ".fixed.tmp"
            try:
                fix_zip_encrypted(zip_file, fixed_zip_name)
                with zipfile.ZipFile(fixed_zip_name) as fixed_zf:
                    fixed_zf.testzip()

                print(
                    loc(
                        locale,
                        f"[*] 伪加密修复成功！文件 '{zip_file}' 无需密码。",
                        f"[*] Pseudo-encryption fixed successfully. File '{zip_file}' does not require a password.",
                    )
                )
                _clean_and_create_outdir(out_dir)
                with zipfile.ZipFile(fixed_zip_name) as fixed_zf:
                    fixed_zf.extractall(path=out_dir)
                    names = fixed_zf.namelist()
                print(
                    loc(
                        locale,
                        f"[*] 系统已为您自动提取出 {len(names)} 个文件到 '{out_dir}' 文件夹中: {names}",
                        f"[*] Successfully extracted {len(names)} file(s) to '{out_dir}': {names}",
                    )
                )
                return 0
            except Exception:
                is_truly_encrypted = True
                print(
                    loc(
                        locale,
                        "[+] 修复尝试失败，该文件为真加密，准备进行暴力破解。",
                        "[+] Repair attempt failed. This is a truly encrypted ZIP. Preparing brute-force attack.",
                    )
                )
            finally:
                if os.path.exists(fixed_zip_name):
                    try:
                        os.remove(fixed_zip_name)
                    except OSError:
                        pass

        if not is_zip_encrypted(zip_file):
            print(
                loc(
                    locale,
                    f"[!] 系统检测到 {zip_file} 不是一个加密的ZIP文件，您可以直接解压！",
                    f"[!] {zip_file} is not an encrypted ZIP file. You can extract it directly.",
                )
            )
            return 0

        if is_truly_encrypted:
            print(
                loc(
                    locale,
                    "[+] 开始对真加密文件进行破解...",
                    "[+] Starting the cracking workflow for the encrypted ZIP...",
                )
            )
            try:
                with zipfile.ZipFile(zip_file) as zf:
                    if not kpa_plain_path and not use_bkcrack_recover:
                        # 短明文 CRC32 枚举恢复；若包内条目全部由此完成则直接结束流程
                        if get_crc(zip_file, zf, locale):
                            return 0
            except zipfile.BadZipFile:
                print(
                    loc(
                        locale,
                        f"[!] '{zip_file}' 可能不是一个有效的 ZIP 文件或已损坏。",
                        f"[!] '{zip_file}' may not be a valid ZIP file or it may be corrupted.",
                    )
                )
                return 1

            kpa_ctx = None
            kpa_inner_resolved = None
            kpa_attempts: list[KnownPlaintextAttempt] = []
            partial_kpa_mode = False
            if kpa_requested:
                try:
                    kpa_inner_resolved, kpa_attempts, partial_kpa_mode = (
                        build_known_plaintext_attempts(
                            zip_file,
                            kpa_plain_path,
                            locale,
                            preferred_entry=kpa_inner_name,
                            plain_offset=kpa_offset,
                            extra_specs=kpa_extra_specs,
                            template_name=kpa_template_name,
                        )
                    )
                    if not partial_kpa_mode and kpa_plain_path:
                        kpa_ctx = prepare_kpa_context(
                            zip_file,
                            kpa_inner_resolved,
                            kpa_plain_path,
                            locale,
                        )
                    elif kpa_attempts:
                        first_attempt = kpa_attempts[0]
                        total_known, max_contig = merge_known_plaintext_ranges(
                            first_attempt.plain_offset,
                            len(first_attempt.plain_source["plaintext_bytes"])
                            if first_attempt.plain_source
                            else 0,
                            first_attempt.extra_specs,
                        )
                        print(
                            loc(
                                locale,
                                f"[+] 已知明文部分模式: 条目 '{kpa_inner_resolved}'，偏移 {first_attempt.plain_offset}，附加字节 {len(first_attempt.extra_specs)} 组，累计已知 {total_known} 字节，最大连续片段 {max_contig} 字节。",
                                f"[+] Partial known-plaintext mode: entry '{kpa_inner_resolved}', offset {first_attempt.plain_offset}, {len(first_attempt.extra_specs)} extra-byte group(s), {total_known} known bytes total, longest contiguous fragment {max_contig} bytes.",
                            )
                        )
                        if kpa_template_name:
                            print(
                                loc(
                                    locale,
                                    f"[*] 当前已启用模板: {kpa_template_name}（将自动尝试常见头部/偏移候选）。",
                                    f"[*] Enabled KPA template: {kpa_template_name} (common header/offset candidates will be tried automatically).",
                                )
                            )
                except Exception as exc:
                    print(
                        loc(
                            locale,
                            f"[!] 已知明文模式初始化失败: {exc}",
                            f"[!] Failed to initialize known-plaintext mode: {exc}",
                        )
                    )
                    return 1

                try:
                    bk_tool = find_bkcrack_executable()
                    if not bk_tool:
                        bk_tool = offer_bkcrack_install(
                            locale,
                            required=bool(use_bkcrack_recover or partial_kpa_mode),
                        )

                    if use_bkcrack_recover:
                        return (
                            0
                            if run_bkcrack_known_plaintext_attempts(
                                zip_file,
                                kpa_attempts,
                                out_dir,
                                locale,
                                bk_tool,
                            )
                            else 1
                        )

                    if bk_tool:
                        version = get_bkcrack_version(bk_tool)
                        print(
                            loc(
                                locale,
                                f"[*] 已检测到 bkcrack{f'（{version}）' if version else ''}，尝试无字典已知明文恢复；失败将自动继续字典/掩码。",
                                f"[*] bkcrack detected{f' ({version})' if version else ''}. Trying dictionary-free known-plaintext recovery first; dictionary/mask attacks will continue on failure.",
                            )
                        )
                        if run_bkcrack_known_plaintext_attempts(
                            zip_file,
                            kpa_attempts,
                            out_dir,
                            locale,
                            bk_tool,
                        ):
                            return 0
                        print(
                            loc(
                                locale,
                                "[*] bkcrack 未恢复成功，继续字典/掩码。",
                                "[*] bkcrack did not recover the archive. Continuing with dictionary/mask attacks.",
                            )
                        )
                    elif partial_kpa_mode:
                        print(
                            loc(
                                locale,
                                "[*] 当前部分明文 / 模板 KPA 依赖 bkcrack；已跳过这一步，继续字典/掩码。",
                                "[*] Partial/template known-plaintext mode requires bkcrack. Skipping it and continuing with dictionary/mask attacks.",
                            )
                        )
                    else:
                        print(
                            loc(
                                locale,
                                "[*] 未检测到 bkcrack，跳过无字典恢复；继续字典/掩码。",
                                "[*] bkcrack not found. Skipping dictionary-free recovery and continuing with dictionary/mask attacks.",
                            )
                        )
                finally:
                    cleanup_known_plaintext_attempts(kpa_attempts)

            verifier = PasswordVerifier(zip_file, **(kpa_ctx or {}))

            if dict_path_or_mask_flag == "-m":
                if not mask_value:
                    print(
                        loc(
                            locale,
                            "[!] 错误: 未提供掩码字符串。",
                            "[!] Error: No mask string was provided.",
                        )
                    )
                    return 1
                return (
                    0
                    if crack_password_with_mask(
                        zip_file, mask_value, verifier, locale, out_dir
                    )
                    else 1
                )

            print(
                loc(
                    locale,
                    "[+] 系统开始进行字典暴力破解······",
                    "[+] Starting dictionary brute-force attack...",
                )
            )

            if dict_path_or_mask_flag:
                return (
                    0
                    if crack_password_with_file_or_dir(
                        zip_file,
                        dict_path_or_mask_flag,
                        verifier,
                        locale,
                        out_dir,
                    )
                    else 1
                )

            found = False
            if os.path.exists("password_list.txt"):
                found = crack_password_with_file(
                    zip_file,
                    "password_list.txt",
                    verifier,
                    locale,
                    out_dir,
                )
            else:
                print(
                    loc(
                        locale,
                        "[!] 未找到内置字典 password_list.txt，将直接尝试纯数字字典。",
                        "[!] Built-in dictionary 'password_list.txt' was not found. Proceeding directly to the numeric dictionary.",
                    )
                )

            if found:
                return 0
            numeric_found = crack_with_generated_numeric_dict(
                zip_file, verifier, locale, out_dir
            )
            if numeric_found:
                return 0
            if basic_default_mode and offer_template_kpa_after_standard_failures(
                zip_file,
                out_dir,
                locale,
            ):
                return 0
            return 1

        return 0

    except FileNotFoundError:
        target = sys.argv[1] if len(sys.argv) > 1 else ""
        print(
            loc(
                locale,
                f"[!] 错误: 文件 '{target}' 未找到。",
                f"[!] Error: File '{target}' not found.",
            )
        )
        return 1
    except KeyboardInterrupt:
        print(loc(locale, "\n[!] 用户已中止操作。", "\n[!] Operation interrupted by user."))
        return 130
    except Exception as exc:
        print(
            loc(
                locale,
                f"\n[!] 发生未知错误: {exc}",
                f"\n[!] An unknown error occurred: {exc}",
            )
        )
        import traceback

        traceback.print_exc()
        return 1
