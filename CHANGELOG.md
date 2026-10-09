# Changelog

## 2.2.1 — 2026-10-09

- Add `--batch` to both language entry points and the shared pipeline, with explicit per-run options instead of global state. Builds on @halfcity789's proposal in [#23](https://github.com/asaotomo/ZipCracker/pull/23).
- Automatically recover bounded 1–4 byte CRC32 plaintexts. Require `--crc-candidates` for ambiguous 5–6 byte preimages, save candidates separately, and never count them as complete recovery or allow source cleanup.
- Directly solve 1–4 byte CRC32 preimages using a cached inverse linear transform, including arbitrary binary bytes. Analyze ambiguous 5–6 byte candidates by enumerating at most 100/10000 printable prefixes and solving the four-byte suffix; budget each solve/prefix as one attempt.
- Try explicit dictionaries/masks before CRC32, read clear short members directly, skip AES CRC32 metadata, and preserve normalized duplicate-member behavior.
- Add per-archive CRC32 candidate/time budgets and a shared automatic-template key-search deadline. Batch default nested recovery can reach built-in templates; outer KPA inputs are not reused on inner archives.
- Skip dependency installation by default in batch mode while honoring explicit installation environment variables; refuse oversized batch masks.
- Add batch safety, scheduling, timeout, candidate-output and recursive-cleanup regressions, with bilingual usage documentation.
- Add `test07.zip`, a CTF fixture combining nested weak-password/pseudo-encrypted archives, short CRC32 flag shards and a real collision trap, with a generator, dictionary, validation guide and five end-to-end regressions.
- Verify the selected entry by archive index rather than filename to handle encrypted/clear duplicate names correctly with both ZIP backends. Cache legacy encryption headers for early rejection while retaining complete entry verification, including after a KPA match.
- Compare known plaintext in 64-byte blocks to reject wrong passwords early, reject empty KPA input, resolve its built-in dictionary outside the project directory, and remove the growing numeric-password deduplication set.
- Propagate password-worker errors, drain queued tasks on failure/interruption, reject invalid UTF-8 surrogate candidates safely, and avoid reporting unread dictionary bytes as completed after an early stop.
- Escape unsupported characters in core API output without changing the caller's stream encoding, including backup messages under Windows cp1252.

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
