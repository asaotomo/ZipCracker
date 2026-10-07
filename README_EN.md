### ZipCracker v2.2.0 — User Guide

[中文](./README.md)

**Stable release:** [v2.2.0](https://github.com/asaotomo/ZipCracker/releases/tag/v2.2.0) · [Download the complete ZIP bundle](https://github.com/asaotomo/ZipCracker/releases/download/v2.2.0/ZipCracker-v2.2.0.zip) · [Changelog](./CHANGELOG.md)

**ZipCracker** is a **comprehensive ZIP cracking and recovery tool** developed by **Team Hx0**. It is a strong fit for **common ZIP challenges in CTF**, as well as **authorized security testing** and **recovering your own encrypted backups**. It combines **pseudo-encryption detection and repair, dictionary attacks, mask attacks, short-plaintext CRC32 preimage search, known-plaintext attack (KPA), and nested ZIP recovery** into one workflow, with **fast loading of huge wordlists, multi-threaded scheduling**, and **automatic extraction** after success so you can analyze and recover ZIPs **efficiently**.

**New in v2.2.0:** recursive extraction with `-r`, intermediate cleanup only after complete extraction, backups of colliding output files, and fixes for Windows Unicode output, bundled dictionary lookup, and CRC32 recovery status. Existing commands remain supported.

Use **`ZipCracker_en.py`** for English UI; **`ZipCracker.py`** is the Chinese UI. Both call the same core.

<img  alt="ZipCracker overview" src="https://github.com/user-attachments/assets/240d75b0-16dd-4777-9143-38916fd7253b" />

**Main capabilities at a glance:**

- Pseudo-encryption detection and repair
- Standard dictionary attacks
- Custom wordlist file or directory of wordlists
- Mask attacks
- Short-plaintext recovery via CRC32 enumeration (1–6 byte entries)
- Known-plaintext attack (`-kpa`)
- Nested ZIP extraction (`-r` / `--recursive`)
- Batch mode (`--batch`, answers every interactive prompt automatically)
- Auto-extract after a successful crack

If you are new here, these three sections are enough to get started:

1. [Quick start](#quick-start)
2. [Common usage](#common-usage)
3. [FAQ](#faq)

### Quick start

Typical first commands:

```bash
# 1. Pseudo-encryption check and repair
python3 ZipCracker_en.py test01.zip

# 2. Default dictionary attack
python3 ZipCracker_en.py test02.zip

# 3. Known-plaintext attack
python3 ZipCracker_en.py test05.zip -kpa test05_plain.txt

# 4. Nested ZIP extraction
python3 ZipCracker_en.py outer.zip -r

# 5. Huge wordlist (recommended)
ZIPCRACKER_SKIP_DICT_COUNT=1 python3 ZipCracker_en.py target.zip huge_dict.txt

# 6. Batch mode (answers every interactive prompt automatically)
python3 ZipCracker_en.py test02.zip --batch
```

Download and extract the complete bundle, then run these commands from its `ZipCracker-v2.2.0` directory. Replace `outer.zip`, `target.zip`, and `huge_dict.txt` with your own paths. `test01.zip` through `test05.zip` are bundled examples.

### Runtime environment

| Item     | Notes                                                |
| :------- | :--------------------------------------------------- |
| Python   | Minimum **Python 3.7**; **Python 3.10+** recommended |
| OS       | Linux / macOS / Windows                              |
| Required | Python standard library only                         |
| Optional | `pyzipper` — AES ZIP support                         |
| Optional | `bkcrack` — faster KPA recovery when applicable      |

If you see:

```text
TypeError: 'type' object is not subscriptable
```

your Python is likely too old. Check:

```bash
python --version
```

Upgrade to **Python 3.10+** when possible.

### Optional dependencies

#### 1. `pyzipper`

Used for **AES** ZIP entries.

Behavior:

- If installed, AES support is enabled automatically.
- If missing, the script may prompt to install; you can enter `n` to skip.
- In Chinese UI mode, one-key install prefers the Tsinghua PyPI mirror and falls back to the official index.

Manual install (example):

```bash
python3 -m pip install pyzipper
```

If the archive uses AES, the script also reminds you that:

1. AES verification and extraction are usually **much slower** than legacy ZipCrypto.
2. If you skip installation, traditional ZipCrypto remains available. Genuine AES archives are kept and ineffective attempts stop; install `pyzipper` and run the command again.

#### 2. `bkcrack`

Mainly used for **dictionary-free recovery** during `-kpa` known-plaintext attacks.

Behavior:

- If `bkcrack` is detected, a faster path is tried first.
- If not found, the script suggests how to install it for your OS; `n` skips and other methods continue.
- If you pass **`--bkcrack`**, `bkcrack` is **required**; the program exits if it is not available.

On Windows, if runtime libraries are missing, the program prints:

- Microsoft docs: [Latest supported VC++ Redistributable](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist)
- Direct download links for your architecture

### Common usage

#### 1. Pseudo-encryption detection and repair

```bash
python3 ZipCracker_en.py test01.zip
```

<img width="1558" height="474" alt="267ab0f0-2340-4ed2-a3d5-11a0305753d4" src="https://github.com/user-attachments/assets/401c3f1c-01fb-4912-bd96-df9db397fa83" />

#### 2. Default dictionary attack

```bash
python3 ZipCracker_en.py test02.zip
```

By default it tries, in order:

1. `password_list.txt`
2. Numeric passwords from **1** to **6** digits

The current working directory's `password_list.txt` takes priority. If it is absent, the bundled dictionary next to the script is used, including when launching from another directory. An explicitly supplied wordlist file or directory uses the path you provide.

<img width="2948" height="1436" alt="c0169c6d-83a8-45cc-94e4-6aa849dc3f62" src="https://github.com/user-attachments/assets/f0e6a997-c65c-4a3c-8d40-3787b9fc8f7b" />

If you run:

```bash
python3 ZipCracker_en.py your.zip
```

and the usual paths fail, the tool also looks inside the archive for entries that look like **template KPA** candidates (e.g. `png`, `zip`, `exe`, `pcapng`). When confidence is high enough, it may ask whether to switch to **template KPA** mode automatically.

Example:

```bash
python3 ZipCracker_en.py test06_image.zip
```

<img width="2948" height="1436" alt="5eeb70f3-0dfa-4bdd-a1ac-6ce4232a4c52" src="https://github.com/user-attachments/assets/7cfd4f38-5148-4015-94a6-1417c43da03d" />


#### 3. Custom wordlists

Single file:

```bash
python3 ZipCracker_en.py test02.zip YourDict.txt
```

<img width="1672" height="770" alt="c98b517a-badf-4be7-8f63-cb4d92fedae9" src="https://github.com/user-attachments/assets/a8f493aa-8f9e-4d60-ab24-e525e3acf7b9" />


Directory of wordlists (tried in sequence):

```bash
python3 ZipCracker_en.py test02.zip YourDictDirectory
```

<img width="1814" height="1188" alt="bd70f862-71d0-41ae-b6cc-7614c4bac594" src="https://github.com/user-attachments/assets/6d87acba-fbce-4cf5-a021-c65531203b6c" />


#### 4. Short-plaintext CRC32 enumeration

For ZIP entries **1–6 bytes** long, the tool can enumerate printable plaintexts whose CRC32 matches the stored value. An interactive terminal asks before starting. Only actual candidate matches count as recovered; when all file entries are recovered, their contents are saved to the output directory. CRC32 collisions are possible, so a candidate is not necessarily the unique original plaintext.

```bash
python3 ZipCracker_en.py test03.zip
```

<img width="2034" height="654" alt="fdf63111-adc6-4b5a-9f26-18e053c590c3" src="https://github.com/user-attachments/assets/cd902438-c9e2-4842-811c-3d2ce7fa56e4" />


#### 5. Mask attack

```bash
python3 ZipCracker_en.py test04.zip -m '?uali?s?d?d?d'
```

Mask placeholders:

| Placeholder | Meaning            |
| :---------- | :----------------- |
| `?d`        | Digits `0-9`       |
| `?l`        | Lowercase `a-z`    |
| `?u`        | Uppercase `A-Z`    |
| `?s`        | Special characters |
| `??`        | Literal `?`        |

<img width="1706" height="734" alt="a1eb3022-9ddd-4ed7-a0fa-aa1c5cd17efa" src="https://github.com/user-attachments/assets/ed874fda-e6ce-4d30-bb5c-7dbaa4e1932d" />

#### 6. Known-plaintext attack (`-kpa`)

Tries **`bkcrack` first** when available, then falls back to dictionary/mask flows:

```bash
python3 ZipCracker_en.py test05.zip -kpa test05_plain.txt
```

<img width="2854" height="826" alt="9ec86c17-73db-4f24-8eff-14a5cd66ff23" src="https://github.com/user-attachments/assets/fe82b6d4-04aa-4d1f-a278-949acdc6b43e" />


If you have an **unencrypted reference ZIP** instead of a loose file:

```bash
python3 ZipCracker_en.py C.zip -kpa M.zip
```

<img width="1483" height="500" alt="image" src="https://github.com/user-attachments/assets/90c6dfd0-993c-4a83-970d-bb8f46be995b" />

Notes:

1. After `-kpa` you can pass either a normal file or a **passwordless** ZIP.
2. If you pass a ZIP, the tool prefers an entry **with the same name** as in the target.
3. If you pass a plain file, it still prefers **same-name** matching inside the target ZIP.
4. If the plaintext ZIP contains **only one** normal file, that file is used automatically.

Important:

- In ZIP known-plaintext attacks, “plaintext” means the byte stream **before ZipCrypto encryption**, not necessarily the original extracted file.
- If the target entry is `ZIP_STORED`, the original file can usually be used directly as `-kpa` input.
- If the target entry is `ZIP_DEFLATED` / `ZIP_BZIP2` / `ZIP_LZMA`, the encrypted bytes are usually the compressed data stream. Passing the uncompressed original file may lead to `ciphertext is smaller than plaintext`.
- `--kpa-offset` only describes where known bytes start inside the pre-encryption byte stream; it cannot map an uncompressed file to compressed data.
- See the bilingual note in [`docs/KPA_KNOWN_PLAINTEXT_NOTE.md`](docs/KPA_KNOWN_PLAINTEXT_NOTE.md).

Force a specific entry inside the target ZIP:

```bash
python3 ZipCracker_en.py test05.zip -kpa test05_plain.txt -c test05_plain.txt
```

**Partial plaintext** — offset and extra known bytes:

```bash
python3 ZipCracker_en.py secret.zip -kpa part.bin --kpa-offset 78 -x 0 4d5a
```

Notes:

1. `--kpa-offset` — start offset of this plaintext inside the **target** file.
2. `-x` — extra known bytes: `-x <offset> <hex>` (repeatable).
3. Shorthand: `-x 0:4d5a`.

**Built-in file-header templates:**

```bash
python3 ZipCracker_en.py target.zip --kpa-template png -c image.png
python3 ZipCracker_en.py target.zip --kpa-template exe -c app.exe
python3 ZipCracker_en.py target.zip --kpa-template pcapng -c capture.pcapng
python3 ZipCracker_en.py target.zip --kpa-template zip -c inside.zip
```

Available templates: `png`, `zip`, `exe`, `pcapng`.

**`bkcrack` only:**

```bash
python3 ZipCracker_en.py test05.zip -kpa test05_plain.txt --bkcrack
```

Difference:

- `-kpa` — if `bkcrack` fails, other methods can still run.
- `-kpa --bkcrack` — **only** `bkcrack`; stop if it fails.

#### 7. Output directory

```bash
python3 ZipCracker_en.py test02.zip -o output_dir
```

The default is `unzipped_files`. All extraction modes stage and verify the complete contents before publishing results to the specified output paths. Unrelated existing files are kept. Colliding old files are first saved to a sibling `outputname_backup_random` directory. If the input ZIP is inside the output directory, extraction uses an isolated `archivename_extracted` subdirectory to protect it. Traversal paths and symlink members are rejected.

#### 8. Nested ZIP extraction

```bash
python3 ZipCracker_en.py outer.zip -r
python3 ZipCracker_en.py outer.zip my_dict.txt -r --max-total-size 8GiB --max-archives 10000
```

Only ZIPs produced by the current extraction are processed. Unencrypted layers are extracted directly; encrypted layers reuse the dictionary or mask settings. Each nested archive gets a separate, flat `nested_NNNN_name` directory so long chains do not accumulate long paths. The original input is always kept. Intermediate archives are removed only after **complete, verified extraction**; failed or limited archives are kept and listed.

| Option | Behavior |
| :--- | :--- |
| `-r`, `--recursive` | Enable nested extraction |
| `--max-depth N` | Maximum inner depth; default 2048, outer archive is depth 0 |
| `--max-archives N` | Maximum archive count including the outer archive; default 4096 |
| `--max-total-size SIZE` | Cumulative extracted bytes; default 1GiB; accepts bytes, KiB, MiB, GiB |
| `--keep-nested-zips` | Keep successfully extracted intermediate archives |

Size accounting includes intermediate ZIPs and bytes written by failed attempts. Deleting intermediate ZIPs does not restore the budget. These limits apply to recursive mode only. The outer archive keeps the usual interactive workflow; inner layers do not repeatedly prompt for CRC32 enumeration or dependency installation. KPA plaintext/template settings apply only to the outer archive. Exit status is `0` for complete success and `1` if any inner archive remains unresolved or a limit is reached.

See [Output directory](#7-output-directory) for output and backup behavior.

#### 9. Batch mode (`--batch`)

Modeled after sqlmap's `--batch`: interactive prompts no longer wait for keyboard input and are answered automatically with consent or the safer default:

```bash
python3 ZipCracker_en.py enc.zip --batch
python3 ZipCracker_en.py outer.zip my_dict.txt -r --batch
```

Automatic answers per prompt:

| Prompt | Answer in batch mode |
| :--- | :--- |
| Short-plaintext CRC32 enumeration | Consent automatically (pure local computation) |
| Trying built-in KPA templates | Consent automatically (pure local computation) |
| One-click `pyzipper` / `bkcrack` install | Skip automatically (no environment changes) |
| Masks exceeding 100 billion candidates | Abort automatically (safer; narrow the range and retry) |

Batch mode combines with `-r` for fully unattended multi-layer processing; resource limits (`--max-depth` / `--max-archives` / `--max-total-size`) still apply. Installation prompts can also be forced with the `ZIPCRACKER_AUTO_INSTALL_PYZIPPER` / `ZIPCRACKER_AUTO_INSTALL_BKCRACK` environment variables.

### Non-interactive execution and exit status

When run from scripts, CI, or with redirected input, manual CRC32 enumeration and installation prompts are skipped and available recovery methods continue. Dependency auto-installation can also be configured through the environment variables listed below. Masks exceeding 100 billion candidates require confirmation in an interactive terminal; non-interactive runs stop and ask you to narrow the range. For fully unattended runs add `--batch` explicitly (see [Batch mode](#9-batch-mode--batch)); every prompt is then answered per the table above.

- `0`: the requested operation succeeded; in recursive mode all discovered inner archives were handled
- `1`: failure, including unresolved/corrupt inner archives or archives skipped because of resource limits
- `130`: interrupted by the user

### Version and tests

Current version: `2.2.0`. See [CHANGELOG.md](./CHANGELOG.md). Existing commands, both language entry points, and optional dependency installation remain supported.

```bash
python3 -m unittest discover -s tests -v
```

Tests generate temporary fixtures. Integration tests for `pyzipper`, Info-ZIP `zip`, and `bkcrack` run when those optional tools are installed and are skipped otherwise.

### Huge wordlists

ZipCracker can handle **very large** wordlists without loading the entire file into memory.

For **10GB+** lists, skip the pre-count pass:

```bash
ZIPCRACKER_SKIP_DICT_COUNT=1 python3 ZipCracker_en.py your.zip your_big_dict.txt
```

Windows PowerShell syntax (applies to the current PowerShell session):

```powershell
$env:ZIPCRACKER_SKIP_DICT_COUNT = "1"
python ZipCracker_en.py your.zip your_big_dict.txt
```

<img width="2642" height="692" alt="7ee7fc4c-df6f-4b6f-8d0d-cf09079f016e" src="https://github.com/user-attachments/assets/e34f4e2f-1e2a-48f3-9715-c14564196aa4" />


Benefits:

1. Faster startup
2. Lower, steadier memory use
3. Progress switches to **streaming** mode (by bytes read)

### FAQ

#### 1. Why is AES so slow?

That is **normal**. AES password checks and decryption are usually **much slower** than ZipCrypto. The script warns you when AES is detected.

#### 2. What if `pyzipper` is not installed?

For AES entries, without `pyzipper`:

1. The script may prompt you to install (or skip with `n`).
2. If genuine AES encryption is detected, the archive is kept, a failure status is returned, and ineffective dictionary scans stop. Install the dependency and retry.

Safest approach: install first.

```bash
python3 -m pip install pyzipper
```

#### 3. Windows: `CERTIFICATE_VERIFY_FAILED` when installing `bkcrack`

This is usually **Python HTTPS certificate verification**, not “GitHub is blocked” alone.

The script tries, in order: Python’s downloader, then `curl.exe` on Windows, then PowerShell.

If it still fails, check:

1. System clock accuracy
2. Proxies, gateways, or AV intercepting HTTPS
3. Whether a browser can open the GitHub release page

#### 4. Windows: `bkcrack` exit code `3221225477`

Hex:

```text
0xC0000005
```

This is an **Access Violation** — `bkcrack.exe` crashed. It is usually **not** “wrong password”. Try:

```bat
set BKCRACK_JOBS=1
python ZipCracker_en.py test05.zip -kpa test05_plain.txt
```

Also try:

1. Install or repair **Microsoft Visual C++ Redistributable**
2. Temporarily disable AV or allowlist `bkcrack.exe`
3. If it still crashes, prefer **WSL / Linux** for `bkcrack`

#### 5. Fan still spinning after extraction succeeded?

The script may still be trying to **recover the original ZIP password** after a successful extract.

To skip that:

```bash
ZIPCRACKER_SKIP_ORIG_PW_RECOVERY=1 python3 ZipCracker_en.py test05.zip -kpa test05_plain.txt
```

#### 6. Huge wordlist looks idle at first?

By default the script **counts** total candidates first. For faster startup:

```bash
ZIPCRACKER_SKIP_DICT_COUNT=1 python3 ZipCracker_en.py your.zip your_big_dict.txt
```

<img width="2642" height="692" alt="cf3c32c6-19c8-4aab-bfb1-de0db357e654" src="https://github.com/user-attachments/assets/1cbf3bcc-9553-496d-b651-529a4f8c7076" />


### Common environment variables

| Variable                             | Effect                                                       |
| :----------------------------------- | :----------------------------------------------------------- |
| `ZIPCRACKER_SKIP_DICT_COUNT=1`       | Skip pre-count for huge wordlists                            |
| `ZIPCRACKER_SKIP_ORIG_PW_RECOVERY=1` | After KPA extract, do not keep recovering the original ZIP password |
| `ZIPCRACKER_AUTO_INSTALL_PYZIPPER=0` | Skip automatic `pyzipper` install prompts                    |
| `ZIPCRACKER_AUTO_INSTALL_BKCRACK=0`  | Skip automatic `bkcrack` install prompts                     |
| `BKCRACK_JOBS=1`                     | Lower `bkcrack` thread count (useful on Windows)             |

### Special Acknowledgments

Thanks to **[LANDY](https://github.com/LANDY-LI-2025)** for support and feedback on this project.

### ClawHub AI skill integration (New!)

**ZipCracker** is listed on the [ClawHub skill hub](https://clawhub.ai/asaotomo/zipcracker). In **OpenClaw** you can invoke it with natural language so the assistant builds and runs decrypt/crack flows — handy for CTF and authorized self-checks.

**Skill page:** https://clawhub.ai/asaotomo/zipcracker

**Install:** Set up the [ClawHub](https://clawhub.ai) client, then run:

```bash
clawhub install zipcracker
```

Then you can say things like: “Crack this ZIP with ZipCracker, try a mask of four digits,” and the assistant will construct the right command.

### Disclaimer

Use this tool **only where you have legal permission**, for example:

- CTF / practice ranges
- Recovering **your own** data
- **Authorized** security testing

Do **not** use it for unauthorized access or other illegal purposes.

---

**Support with tips** — The code is open source; every bit of help keeps the project going.

<img width="500" height="400" alt="Tip QR" src="https://github.com/user-attachments/assets/02868aed-357e-4740-983a-d5a8ea05bdbf" />

**Team official account** — Follow for updates.

<img width="318" alt="Team WeChat" src="https://user-images.githubusercontent.com/67818638/149507366-4ada14db-a972-4071-bbb6-197659f61ced.png">

**Team knowledge planet**

<img height="380" alt="Knowledge planet" src="https://github.com/user-attachments/assets/c9999f9c-2f24-4aca-9b42-c6c58f5d4083" />
