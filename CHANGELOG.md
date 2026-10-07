# Changelog

## 2.2.0 — 2026-10-07

- Add iterative nested ZIP recovery with `-r` / `--recursive`, flat layer directories, optional intermediate retention, and configurable depth, archive-count and cumulative-size limits.
- Track actual extraction output across dictionary, mask, pseudo-encryption and bkcrack paths. Existing unrelated archives are never selected for recursive cleanup.
- Stage complete extractions, verify contents, preserve old output in backups on name collisions, and roll back failed output merges. Partial extraction never counts as success or permits deletion of its source archive.
- Report unresolved inner archives and resource limits through the CLI exit status. Keep the original input archive.
- Reject traversal paths and symlink members. Preserve standard duplicate-member last-entry-wins behavior.
- Find the bundled dictionary when launched from another working directory, while preserving the priority of a user-provided `password_list.txt` in the current directory.
- Prevent Chinese/Unicode CLI output from crashing under legacy Windows encodings, including redirected output; preserve explicit encoding choices with escaped fallback for unsupported characters.
- Count CRC32 recovery only when a candidate is actually found; save fully recovered short plaintext files to the output directory.
- Stream large password-verification entries, pseudo-encryption repair, and bkcrack fallback extraction. Correct ZIP LZMA fallback decoding and validate fallback output sizes and CRCs.
- Retain existing dictionary/mask/KPA commands, numeric fallback, streaming dictionary controls, Chinese/English entry points, and optional AES/bkcrack support. Add regression tests and Linux/macOS/Windows CI, including a Python 3.7 compatibility job.

Nested ZIP work builds on the contribution by **@halfcity789** in [#19](https://github.com/asaotomo/ZipCracker/pull/19). The original contribution and author attribution are retained in Git history; extraction integrity, cleanup, compatibility and regression coverage were subsequently revised for this release.
