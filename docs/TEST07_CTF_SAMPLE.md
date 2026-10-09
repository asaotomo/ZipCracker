# test07.zip：CTF 套娃与 CRC32 验证样例

项目根目录的 `test07.zip` 是专门制作的 CTF 验证题，包含弱口令、ZIP 伪加密、短明文 CRC32 恢复，以及一个真实的 CRC32 碰撞陷阱。共 6 个 ZIP（含最外层），最大内层深度为 3。它验证批量模式和递归处理中的成功判定、计算预算与原包保留，不覆盖 AES 或已知明文攻击。

## 结构与解题目标

```text
test07.zip                         ZipCrypto，口令 password
├── briefing.txt                   题目说明
└── stage1_pseudo.zip               伪加密（本地头和中央目录加密位均置位）
    └── stage2.zip                  普通 ZIP，内含三个并列分支
        ├── 01_crc_shards.zip       ZipCrypto，口令不在内置字典中
        │   └── shards/01.txt～08.txt  每个片段 3～4 字节，拼接得到 flag
        ├── 02_crc_collision.zip    ZipCrypto，口令 123456
        │   └── collision.txt      5 字节，包含 CRC32 碰撞陷阱
        └── 03_clear_checkpoint.zip 普通 ZIP
            └── checkpoint.txt     明文分支验证标记
```

三个真正加密的 ZIP 使用传统 ZipCrypto 和 STORE 压缩方式。短片段分支用于验证无需找到口令也能恢复 1～4 字节明文。随包的 `test07_dict.txt` 只包含外层口令和碰撞分支口令，不包含短片段分支口令。

碰撞陷阱的原文是 `aRQ\,`（十六进制 `6152515c2c`）；候选 `00000`（十六进制 `3030303030`）与它的长度相同，CRC32 都是 `0x4adc54f5`。只有原包实际解密得到的前者才是验证成功的内容。

## 正常验证

在项目根目录执行：

```bash
python3 ZipCracker.py test07.zip -r --batch -o test07_out
```

预期退出码 `0`：无需键盘应答，修复伪加密层，恢复 8 个 flag 片段，用字典解密碰撞分支，解出明文分支。输出中的 5 个中间 ZIP 默认删除，原始 `test07.zip` 始终保留。

递归输出按层放在不同目录中，可这样拼接 flag：

```bash
python3 - <<'PY'
from pathlib import Path
shards = sorted(Path('test07_out').rglob('shards/*.txt'))
assert len(shards) == 8
print(b''.join(path.read_bytes() for path in shards).decode('ascii'))
PY
```

预期得到 `flag{batch_crc32_safe_recovery}`。

显式指定字典也应成功，验证「先尝试指定字典，失败后进行 CRC32 恢复」：

```bash
python3 ZipCracker.py test07.zip test07_dict.txt -r --batch -o test07_dict_out
```

## 碰撞候选不能算成功

制作一个仅能解开外层的字典，再显式启用候选分析：

```bash
python3 -c "from pathlib import Path; Path('test07_outer_only.txt').write_text('password\n', encoding='utf-8')"
python3 ZipCracker.py test07.zip test07_outer_only.txt -r --batch --crc-candidates -o test07_probe
```

预期退出码 `1`：flag 片段仍可恢复，碰撞分支只产生 `00000` 候选，候选写入以 `_crc_candidates` 结尾的单独目录；`02_crc_collision.zip` 必须保留，普通解压目录不能出现伪造的 `collision.txt`。这是有意构造的失败测试，不代表样例损坏。

## 预算与中间包保留

```bash
# CRC32 预算不足：退出码 1，保留 01_crc_shards.zip，不发布部分 flag 片段
python3 ZipCracker.py test07.zip test07_dict.txt -r --batch --crc-max-candidates 1 -o test07_budget

# 正常完成但保留所有 5 个中间 ZIP：退出码 0
python3 ZipCracker.py test07.zip -r --batch --keep-nested-zips -o test07_keep
```

重复运行时已有输出按工具的备份规则保留。上述命令也可将入口替换为 `ZipCracker_en.py`。

## 自动测试与重新生成

```bash
python3 -m unittest discover -s tests -p 'test_test07.py' -v

# 仅重新生成样例需要系统安装 Info-ZIP（zip 命令）
python3 scripts/build_test07.py
```

自动测试覆盖默认批量流程、英文入口的显式字典回退、碰撞候选隔离、CRC32 预算耗尽和保留中间包，并检查源文件 SHA-256 未改变。直接使用已提交样例不需要 `zip` 命令。

生成脚本保存了全部原文和口令，其中短片段口令为 `CTF07-crc-only-a9f!`，便于检查归档是否正确生成。ZipCrypto 加密头含随机数据，重新生成后的文件哈希可能变化，但结构和预期验证结果相同。
