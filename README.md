### ZipCracker v2.2.1 —— 使用说明

**Update:2026.10.09 (v2.2.1)**

[English](./README_EN.md)

**稳定版本：** [v2.2.1](https://github.com/asaotomo/ZipCracker/releases/tag/v2.2.1) · [下载完整 ZIP 包](https://github.com/asaotomo/ZipCracker/releases/download/v2.2.1/ZipCracker-v2.2.1.zip) · [更新日志](./CHANGELOG.md)

**ZipCracker** 是 **Hx0 战队**开发的一款**面向 ZIP 压缩包的综合破解与恢复工具**，非常适用于新手拿来解决 **CTF 常见 ZIP 题型**，也适用于经授权的**安全测试**和**自有加密备份恢复**场景。它将**伪加密识别与修复、字典爆破、掩码猜解、短明文 CRC32 枚举、已知明文攻击、套娃 ZIP 逐层恢复**等常见手段整合为一条完整流程，支持**超大字典快速加载、多线程高并发调度**，并在命中后**自动解压**，帮助用户更**高效**地完成 ZIP 分析与恢复。

**v2.2.1 更新：** 新增 `--batch` 无人值守恢复与 test07 CTF 样例；加速 CRC32 和已知明文口令校验，支持二进制短内容；隔离 CRC32 碰撞候选，修复重名条目密码验证与线程异常挂起。原有命令继续可用。

<img width="3020" height="1574" alt="image" src="https://github.com/user-attachments/assets/240d75b0-16dd-4777-9143-38916fd7253b" />

**ZipCracker上手简单，简单的说主要能力包括：**

- 伪加密识别与修复
- 常规字典爆破
- 自定义字典或字典目录
- 掩码爆破
- 短明文 CRC32 枚举恢复
- 已知明文攻击（`-kpa`）
- 套娃解压（`-r`，递归处理嵌套压缩包）
- 批量模式（`--batch`，自动应答并限制 CRC32 / 自动模板计算）
- 破解成功后自动解压

如果你只是第一次使用，这份 README 看下面 3 个部分就够了：

1. [快速开始](#快速开始)
2. [常见用法](#常见用法)
3. [常见问题](#常见问题)

### 快速开始

首次使用最常见的命令：

```bash
# 1. 伪加密识别与修复
python3 ZipCracker.py test01.zip

# 2. 默认字典爆破
python3 ZipCracker.py test02.zip

# 3. 已知明文攻击
python3 ZipCracker.py test05.zip -kpa test05_plain.txt

# 4. 套娃解压（递归处理嵌套压缩包）
python3 ZipCracker.py outer.zip -r

# 5. 超大字典推荐写法
ZIPCRACKER_SKIP_DICT_COUNT=1 python3 ZipCracker.py target.zip huge_dict.txt

# 6. 无人值守套娃恢复
python3 ZipCracker.py test07.zip -r --batch -o test07_out
```

下载并解压完整 ZIP 包后，在其中的 `ZipCracker-v2.2.1` 目录运行。`outer.zip`、`target.zip` 和 `huge_dict.txt` 为示例路径，请替换成自己的文件；`test01.zip`～`test07.zip` 是随包提供的样例，其中 `test06.zip` 是套娃解压样例（见[套娃解压](#8-套娃解压递归处理嵌套压缩包)），`test07.zip` 是[批量模式与 CRC32 碰撞验证题](docs/TEST07_CTF_SAMPLE.md)。

### 运行环境

| 项目 | 说明 |
| :--- | :--- |
| Python | 最低 `Python 3.7`，推荐 `Python 3.10+` |
| 操作系统 | Linux / macOS / Windows |
| 必需依赖 | Python 标准库 |
| 可选依赖 | `pyzipper`，用于 AES ZIP |
| 可选依赖 | `bkcrack`，用于更快的已知明文恢复 |

如果第一次运行就报：

```text
TypeError: 'type' object is not subscriptable
```

通常表示你的 Python 太旧。先看版本：

```bash
python --version
```

建议直接升级到 `Python 3.10+`。

### 可选依赖

#### 1. `pyzipper`

`pyzipper` 用于处理 AES ZIP。

脚本行为：

- 如果已安装，会自动启用 AES 支持
- 如果未安装，脚本会提示你是否安装
- 输入 `n` 可以跳过
- 中文模式下一键安装会优先使用清华源，失败后自动回退官方源

手动安装：

```bash
python3 -m pip install pyzipper -i https://pypi.tuna.tsinghua.edu.cn/simple
```

如果目标 ZIP 使用 AES，脚本会额外提醒你两件事：

1. AES 本来就比传统 ZipCrypto 更慢
2. 如果跳过安装，传统 ZipCrypto 仍可处理；真正的 AES 加密包会保留原包并停止无效尝试，安装后可重新运行

#### 2. `bkcrack`

`bkcrack` 主要用于 `-kpa` 已知明文攻击时的无字典恢复。

脚本行为：

- 如果检测到 `bkcrack`，会优先尝试更快的恢复方式
- 如果未检测到，会按系统给出安装方式
- 输入 `n` 可以跳过，脚本会继续走字典或掩码流程
- 如果你用了 `--bkcrack`，那就必须安装，否则会直接退出

Windows 下如果提示运行库问题，程序会直接打印：

- Microsoft 官方说明页  
  [Latest supported VC++ Redistributable](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist)
- 对应架构的直链下载地址

### 常见用法

#### 1. 伪加密识别与修复

```bash
python3 ZipCracker.py test01.zip
```
<img width="1330" height="532" alt="3c59ee25-7ea1-4fc0-92ec-1f98b01e9686" src="https://github.com/user-attachments/assets/497b7c48-7a19-495a-a96b-2a54af512044" />

#### 2. 默认字典爆破

```bash
python3 ZipCracker.py test02.zip
```

默认会依次尝试：

1. `password_list.txt`
2. 1 到 6 位纯数字密码

字典优先使用当前工作目录中的 `password_list.txt`；没有时使用脚本旁随包提供的内置字典，因此从其他目录启动也可正常找到它。显式指定字典文件或字典目录时，按你指定的路径处理。

<img width="1460" height="774" alt="785a0b1d-4912-4ab7-b965-fb0b42fc5a85" src="https://github.com/user-attachments/assets/f0ac039b-dcf6-4ee6-bebb-7e3eb4ac3ca4" />

如果你只是直接运行：

```bash
python3 ZipCracker.py your.zip
```

而前面的常规路径都失败了，程序还会额外检查压缩包里是否存在更像 `png / zip / exe / pcapng` 模板明文攻击的条目。  
如果检测到这类候选，并且模板置信度足够高，程序会询问你是否自动切到模板 KPA 模式继续尝试。  

如：

```bash
python3 ZipCracker.py test06_image.zip
```


<img width="2360" height="1712" alt="7f3fa23e-5824-4b81-8e47-a39f6f37e7f8" src="https://github.com/user-attachments/assets/a1bb93d3-c7d6-418a-8306-b253b80e5d92" />


#### 3. 自定义字典

单个字典文件：

```bash
python3 ZipCracker.py test02.zip YourDict.txt
```

<img width="1590" height="770" alt="bb89dfeb-4227-43a7-b532-e6adeea851df" src="https://github.com/user-attachments/assets/3433f90f-a41f-408a-aaab-dbf46b981aea" />

字典目录：

```bash
python3 ZipCracker.py test02.zip YourDictDirectory
```

<img width="1560" height="1194" alt="1e1deee9-cf15-40c5-acb4-789bfb2c80a0" src="https://github.com/user-attachments/assets/b4e8d775-d7c1-4754-8ce5-9b0902179100" />


#### 4. 短明文 CRC32 枚举恢复

对传统 ZIP 加密中长度为 1～4 字节的条目，可按归档记录的 CRC32 直接求解内容；在长度和 CRC32 元数据正确的前提下，这一长度范围的原像唯一。交互终端会先询问；`--batch` 自动尝试。算法使用缓存的 CRC32 线性逆变换，每个条目最多做 32 步消元，不再枚举字符组合，同时支持 `00`、`FF` 等二进制字节。每个包共享默认 100 万次候选/求解尝试、5 秒计算预算；短条目每次求解计一次，达到任一限制就继续后续破解。未加密短条目直接读取，AES 条目跳过 CRC32 恢复。明确提供字典或掩码时，先尝试指定方法，失败后才尝试 CRC32。

5～6 字节可能发生 CRC32 碰撞，默认跳过。需要分析候选时显式加 `--crc-candidates`；候选保存到 `<输出目录>_crc_candidates`，不会覆盖正常提取结果，也不计为成功或允许清理来源包。内层候选目录与对应的 `nested_序号_包名` 目录并列。即使找到候选，程序仍继续密码验证；最终未恢复时退出码为 `1`。候选写入也计入套娃累计解压预算。

5～6 字节候选分析只枚举 1～2 字节的可打印前缀，并直接求解剩余 4 字节，再检查候选是否全部可打印；最多检查 100 / 10000 个前缀，每个前缀计一次预算。该加速不会改变候选的未验证性质。

```bash
python3 ZipCracker.py test03.zip

# 显式分析 5～6 字节候选；可按需增加预算
python3 ZipCracker.py target.zip --batch --crc-candidates --crc-max-candidates 10000000 --crc-timeout 10
```

<img width="1616" height="656" alt="730083af-ad56-4490-be43-770445d26589" src="https://github.com/user-attachments/assets/aacc320b-e473-475e-b290-ed0b885888f0" />

#### 5. 掩码爆破

```bash
python3 ZipCracker.py test04.zip -m '?uali?s?d?d?d'
```

掩码占位符：

| 占位符 | 含义 |
| :--- | :--- |
| `?d` | 数字 `0-9` |
| `?l` | 小写字母 `a-z` |
| `?u` | 大写字母 `A-Z` |
| `?s` | 特殊字符 |
| `??` | 问号 `?` 本身 |


<img width="1614" height="738" alt="de9fb632-e882-4790-9f19-67569bb99f7d" src="https://github.com/user-attachments/assets/4d18fcba-329f-4a53-afa5-e38c28d8eb6e" />


#### 6. 已知明文攻击

自动优先尝试 `bkcrack`，失败后继续字典/掩码：

```bash
python3 ZipCracker.py test05.zip -kpa test05_plain.txt
```

<img width="2262" height="828" alt="acad2042-46d8-44ce-b7e7-61dda1648364" src="https://github.com/user-attachments/assets/62e9b17d-c947-4bcd-8312-b26340284185" />


如果你手里拿到的是“无密码的对照 ZIP”，也可以直接这样：

```bash
python3 ZipCracker.py C.zip -kpa M.zip
```


<img width="2414" height="1098" alt="f4fe2d5e-4e1f-479c-a9fe-66675cd4a4b5" src="https://github.com/user-attachments/assets/33a329c8-97c9-45d3-aeb4-70435e46273d" />


说明：

1. `-kpa` 后面既可以是普通明文文件，也可以是无密码 ZIP
2. 如果传入的是 ZIP，程序会优先寻找与目标条目同名的文件
3. 如果传入的是普通文件，程序也会优先按同名文件自动匹配 ZIP 内条目
4. 如果明文 ZIP 里只有一个普通文件，也会自动使用它

重要说明：

- ZIP 的已知明文攻击中，“明文”指 **ZipCrypto 加密前的数据流**，不一定是解压后的原始文件。
- 如果目标条目是 `ZIP_STORED`，原始文件通常可以直接作为 `-kpa` 输入。
- 如果目标条目是 `ZIP_DEFLATED` / `ZIP_BZIP2` / `ZIP_LZMA`，被加密的通常是压缩后的数据流，直接传入未压缩原文件可能会出现 `ciphertext is smaller than plaintext`。
- `--kpa-offset` 只能表示已知字节在加密前数据流里的起始偏移，不能把未压缩原文件自动对应到压缩后数据。
- 更完整的双语说明见 [`docs/KPA_KNOWN_PLAINTEXT_NOTE.md`](docs/KPA_KNOWN_PLAINTEXT_NOTE.md)。

指定 ZIP 内条目：

```bash
python3 ZipCracker.py test05.zip -kpa test05_plain.txt -c test05_plain.txt
```

如果你手里只有“部分明文”，可以加偏移和附加字节：

```bash
python3 ZipCracker.py secret.zip -kpa part.bin --kpa-offset 78 -x 0 4d5a
```

说明：

1. `--kpa-offset` 表示这段明文在目标文件里的起始偏移
2. `-x` 表示额外已知字节，写法是 `-x 偏移 十六进制`
3. `-x` 可以重复写多次
4. 也支持简写成 `-x 0:4d5a`

如果你只有常见文件头，可以直接用模板：

```bash
python3 ZipCracker.py target.zip --kpa-template png -c image.png
python3 ZipCracker.py target.zip --kpa-template exe -c app.exe
python3 ZipCracker.py target.zip --kpa-template pcapng -c capture.pcapng
python3 ZipCracker.py target.zip --kpa-template zip -c inside.zip
```

可用模板：

- `png`
- `zip`
- `exe`
- `pcapng`

只允许走 `bkcrack`：

```bash
python3 ZipCracker.py test05.zip -kpa test05_plain.txt --bkcrack
```

区别很简单：

- `-kpa`：`bkcrack` 失败后还能继续其他方法
- `-kpa --bkcrack`：只跑 `bkcrack`，失败就结束

#### 7. 指定输出目录

```bash
python3 ZipCracker.py test02.zip -o output_dir
```

默认输出目录为 `unzipped_files`。所有解压流程都会先将内容完整提取到临时目录并验证，再交付到指定输出路径。目录里无关的文件会保留；同名旧文件先备份到输出目录旁的 `目录名_backup_随机串`，然后更新结果。输入 ZIP 位于输出目录内时，结果使用独立的 `包名_extracted` 子目录，保护输入包。路径越界和符号链接条目会被拒绝。

#### 8. 套娃解压（递归处理嵌套压缩包）

有的题目是压缩包套压缩包，一层套一层动辄上百层。加上 `-r` / `--recursive` 后，ZipCracker 会在当前压缩包完整解压成功后，只扫描本次产生的嵌套 ZIP，并复用字典/掩码设置逐层处理：

```bash
python3 ZipCracker.py outer.zip -r
```

行为说明：

1. 未加密的层会直接解压并继续向下扫描
2. 每一层解压到输出目录下独立的 `nested_序号_包名` 目录，避免同名覆盖，也避免上千层链路在 Windows 上触发超长路径问题
3. 只有完整解压成功的中间压缩包才会自动删除；最外层输入包始终保留。想保留所有中间包请加 `--keep-nested-zips`
4. 深度、包数量、累计解压字节数均有上限，达到限制时保留未处理包；内层未完成时退出码为 `1`，全部完成为 `0`
5. 嵌套层不读键盘；`--batch` 可对内层执行有预算的 CRC32 恢复。未指定字典或掩码时，批量模式还会在内层常规恢复失败后尝试内置模板。用户指定的 KPA 明文/条目/模板参数仅作用于最外层
6. 损坏包、部分条目解压失败或密码不一致的包会保留，并在结束时统一列出

随包提供的 `test06.zip` 就是一个五层套娃样例，各层分别走内置字典（最外层、第 2 层）、伪加密修复（第 1 层）、1-6 位纯数字字典（第 3 层）和直接解压（第 4 层）四条不同路径，可用来验证整条递归流程：

```bash
python3 ZipCracker.py test06.zip -r
```

<img width="1547" height="940" alt="image" src="https://github.com/user-attachments/assets/e324f9d7-8309-4b27-8c3a-99cdbdfbc96d" />


可选参数：

| 参数 | 说明 |
| :--- | :--- |
| `-r`, `--recursive` | 启用套娃解压 |
| `--max-depth N` | 最大内层深度，默认 2048；最外层为深度 0 |
| `--max-archives N` | 包数量上限，包含最外层，默认 4096 |
| `--max-total-size SIZE` | 累计解压上限，默认 1GiB；支持字节数、KiB、MiB、GiB |
| `--keep-nested-zips` | 保留已处理成功的中间压缩包 |

例如，处理更大的多层归档：

```bash
python3 ZipCracker.py outer.zip my_dict.txt -r --max-total-size 8GiB --max-archives 10000
```

累计解压量包含各层产生的中间 ZIP，以及失败尝试已写入的字节；删除中间包不会返还预算。上述资源限制仅作用于套娃模式，原有单包用法不受该默认上限影响。

输出目录与备份规则见[指定输出目录](#7-指定输出目录)。

#### 9. 批量模式（`--batch`）

```bash
python3 ZipCracker.py target.zip --batch
python3 ZipCracker.py outer.zip my_dict.txt -r --batch
```

| 操作 | 批量模式行为 |
| :--- | :--- |
| 1～4 字节 CRC32 恢复 | 自动尝试，每包共享候选数和时间预算 |
| 5～6 字节 CRC32 候选 | 默认跳过；`--crc-candidates` 显式启用，单独保存，不计成功 |
| 内置模板 KPA | 默认破解流程失败后自动尝试；无显式字典/掩码的内层也适用 |
| `pyzipper` / `bkcrack` 安装 | 默认跳过；显式安装环境变量仍可覆盖 |
| 超过 1000 亿组合的掩码 | 拒绝执行，返回失败 |

计算预算参数均接受正值，不支持 `0`、`nan` 或 `inf`：

| 参数 | 默认值与范围 |
| :--- | :--- |
| `--crc-max-candidates N` | 每个包所有 CRC32 条目共享 1000000 次候选/求解尝试 |
| `--crc-timeout SEC` | 每个包 CRC32 计算共享 5 秒；每 1024 次检查一次时间，等待确认不计时 |
| `--template-timeout SEC` | 批量模式每个包的自动模板密钥搜索共享 60 秒 |

CRC32 预算也适用于交互模式和显式候选分析。模板密钥搜索超时会结束该搜索并保留原包；显式 `-kpa` / `--kpa-template` 攻击不受自动模板预算影响。依赖探测、提取、字典/掩码及后续口令反推有各自流程，上述参数不是整次运行的总时限。套娃的深度、包数、解压字节限制也继续生效。

项目提供的 `test07.zip` 是一个典型的 CTF 综合样例，包含最外层在内共 6 个 ZIP，最大内层深度为 3。外层走弱口令字典，下一层修复伪加密，再分别处理短明文 flag 片段、CRC32 碰撞陷阱和普通明文 ZIP，可用来验证批量模式与套娃恢复：

```bash
python3 ZipCracker.py test07.zip -r --batch -o test07_out
```

正常运行无需键盘应答，退出码为 `0`，结果保存在 `test07_out`：

1. `01_crc_shards.zip` 中的 8 个片段各为 3～4 字节，通过 CRC32 恢复，按文件名顺序拼接得到 `flag{batch_crc32_safe_recovery}`
2. `02_crc_collision.zip` 中的 5 字节内容默认跳过 CRC32 候选枚举，使用字典口令 `123456` 实际解密，恢复原文 `aRQ\,`
3. 明文分支直接解压；成功处理的 5 个中间 ZIP 默认删除，原始 `test07.zip` 保留

也可以使用项目提供的 `test07_dict.txt` 验证自定义字典与 CRC32 回退流程。该字典只包含外层和碰撞分支的口令，短片段分支仍需通过 CRC32 恢复：

```bash
python3 ZipCracker.py test07.zip test07_dict.txt -r --batch -o test07_dict_out
```

碰撞陷阱中的原文 `aRQ\,` 与候选 `00000` 长度相同、CRC32 相同，但内容不同。仅找到候选不会算作恢复成功，也不会删除来源包。flag 拼接命令、碰撞失败测试和预算限制验证见 [test07 样例说明](docs/TEST07_CTF_SAMPLE.md)。

该功能吸收了 [@halfcity789 的 PR #23](https://github.com/asaotomo/ZipCracker/pull/23) 的批量模式建议，并加入碰撞候选隔离与计算预算。

### 非交互运行与退出码

未加 `--batch` 时，脚本、流水线或重定向输入环境会跳过 CRC32 询问和手动安装，继续可用恢复流程；`--crc-candidates` 可显式启用有预算的候选分析。加 `--batch` 后按上表自动应答。安装环境变量可显式覆盖默认值。超过 1000 亿组合的掩码只允许普通交互模式确认，批量或非交互模式会拒绝。

- `0`：所请求的处理成功；套娃模式下所有发现的内层包均处理完成
- `1`：处理失败，或套娃模式仍有未恢复、损坏或因资源限制而跳过的包
- `130`：用户中断操作

### 版本与测试

当前版本：`2.2.1`。变化见 [CHANGELOG.md](./CHANGELOG.md)。旧命令、两种语言入口及可选依赖方式保持兼容。

```bash
python3 -m unittest discover -s tests -v
```

测试仅生成临时样例。安装 `pyzipper`、Info-ZIP 的 `zip` 和 `bkcrack` 后可运行对应集成测试；未安装时仅跳过对应项目。

### 超大字典怎么用

ZipCracker 可以处理很大的字典，不会一次性把整份字典读进内存。

如果字典很大，比如 `10GB+`，推荐直接跳过预统计：

```bash
ZIPCRACKER_SKIP_DICT_COUNT=1 python3 ZipCracker.py your.zip your_big_dict.txt
```

Windows PowerShell 写法（对当前 PowerShell 会话生效）：

```powershell
$env:ZIPCRACKER_SKIP_DICT_COUNT = "1"
python ZipCracker.py your.zip your_big_dict.txt
```

<img width="2348" height="684" alt="d8f97f4d-6698-4f1d-bb92-1f7d593751c4" src="https://github.com/user-attachments/assets/e23e46dd-2734-4494-af22-79ca381864e9" />


这样做的好处：

1. 启动更快
2. 内存更稳
3. 进度条会改成“流式进度”，按文件读取量显示

### 常见问题

#### 1. 为什么 AES 看起来特别慢？

这是正常现象。

AES 的密码校验和解压本来就通常比传统 ZipCrypto 慢很多。  
如果脚本检测到 AES，它会主动提示你“这会更慢”。

#### 2. 没装 `pyzipper` 会怎样？

如果 ZIP 里有 AES 条目，而当前没装 `pyzipper`：

1. 脚本会先提示你安装
2. 你也可以输入 `n` 跳过
3. 如果确认是真正的 AES 加密，程序会保留原包、返回失败状态并停止无效遍历；安装依赖后重新运行即可

最稳妥的做法还是先安装：

```bash
python3 -m pip install pyzipper -i https://pypi.tuna.tsinghua.edu.cn/simple
```

#### 3. Windows 安装 `bkcrack` 时提示 `CERTIFICATE_VERIFY_FAILED` 是什么情况？

这通常不是单纯“GitHub 访问不了”，而是当前 Python 的 HTTPS 证书校验失败。

脚本现在会自动尝试：

1. Python 默认下载
2. Windows 下回退到 `curl.exe`
3. 再不行回退到 PowerShell

如果还失败，优先检查：

1. 系统时间是否准确
2. 是否有代理、网关、杀软拦截 HTTPS
3. 浏览器是否能正常打开 GitHub release 页面

#### 4. Windows 下 `bkcrack` 退出码 `3221225477` 是什么？

这个值换成十六进制是：

```text
0xC0000005
```

表示 Windows `Access Violation`，也就是 `bkcrack.exe` 自己崩了。

这通常不是密码错误。建议优先尝试：

```bat
set BKCRACK_JOBS=1
python ZipCracker.py test05.zip -kpa test05_plain.txt
```

同时也建议：

1. 安装或修复 Microsoft Visual C++ Redistributable
2. 临时关闭杀软或给 `bkcrack.exe` 加白名单
3. 如果仍崩溃，优先在 WSL / Linux 下使用 `bkcrack`

#### 5. 为什么已经解压成功了，风扇还在转？

通常不是后台僵尸进程没退出，而是脚本还在继续尝试反推出原始 ZIP 密码。

如果你只关心解压结果，可以跳过：

```bash
ZIPCRACKER_SKIP_ORIG_PW_RECOVERY=1 python3 ZipCracker.py test05.zip -kpa test05_plain.txt
```

#### 6. 为什么超大字典刚开始看起来像没动静？

默认模式下脚本会先统计总密码数。  
如果你更在意启动速度，用这条：

```bash
ZIPCRACKER_SKIP_DICT_COUNT=1 python3 ZipCracker.py your.zip your_big_dict.txt
```

### 常用环境变量

一般用户最常用的是下面这几个：

| 变量名 | 作用 |
| :--- | :--- |
| `ZIPCRACKER_SKIP_DICT_COUNT=1` | 跳过超大字典预统计 |
| `ZIPCRACKER_SKIP_ORIG_PW_RECOVERY=1` | KPA 解压后不再继续反推原始 ZIP 密码 |
| `ZIPCRACKER_AUTO_INSTALL_PYZIPPER=0` | 自动跳过 `pyzipper` 安装提示 |
| `ZIPCRACKER_AUTO_INSTALL_BKCRACK=0` | 自动跳过 `bkcrack` 安装提示 |
| `BKCRACK_JOBS=1` | 降低 `bkcrack` 线程数，适合 Windows 排障 |

### 特别鸣谢

感谢 **[@LANDY](https://github.com/LANDY-LI-2025)** 对本项目的支持与建议。


### 🚀 ClawHub AI 技能集成 (New!)

**ZipCracker** 已上线 [ClawHub 技能中心](https://clawhub.ai/asaotomo/zipcracker)。在 **OpenClaw** 中可通过自然语言无缝调用本工具，自动拼接并执行解密 / 破解流程，让 CTF 与安全自查更高效。

**技能主页：** https://clawhub.ai/asaotomo/zipcracker

**安装：** 请先完成 [ClawHub](https://clawhub.ai) 客户端的安装与配置，然后在终端执行：

```bash
clawhub install zipcracker
```

安装完成后，可直接对 AI 助手说例如：「帮我用 ZipCracker 破解这个压缩包，尝试一下掩码攻击，格式是四个数字」，由助手代为构建并执行对应命令。

### 免责声明

请仅在合法授权的场景下使用本工具，例如：

- CTF / 靶场
- 自有数据恢复
- 经授权的安全测试

请勿将本工具用于任何未授权的攻击或非法用途。
---
**【打赏支持❤️】代码传情跨山海，点滴支持皆温暖✨**

虽然代码完全开源，但每杯咖啡都能让我们走得更远 ☕️

<img width="500" height="400" alt="打赏码" src="https://github.com/user-attachments/assets/02868aed-357e-4740-983a-d5a8ea05bdbf" />

**【战队公众号】扫描关注战队公众号，获取最新动态**

<img width="318" alt="image" src="https://user-images.githubusercontent.com/67818638/149507366-4ada14db-a972-4071-bbb6-197659f61ced.png">

**【战队知识星球】福利大放送**

<img height="380" alt="知识星球优惠券" src="https://github.com/user-attachments/assets/5d68553e-0b70-44a4-b26d-a019c9a8d3dd" />
