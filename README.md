### ZipCracker（新版本） —— 使用说明

[English](./README_EN.md)

**ZipCracker** 是 **Hx0 战队**开发的一款**面向 ZIP 压缩包的综合破解与恢复工具**，非常适用于新手拿来解决 **CTF 常见 ZIP 题型**，也适用于经授权的**安全测试**和**自有加密备份恢复**场景。它将**伪加密识别与修复、字典爆破、掩码猜解、短明文 CRC32 枚举、已知明文攻击**等常见手段整合为一条完整流程，支持**超大字典快速加载、多线程高并发调度**，并在命中后**自动解压**，帮助用户更**高效**地完成 ZIP 分析与恢复。

<img width="3020" height="1574" alt="image" src="https://github.com/user-attachments/assets/240d75b0-16dd-4777-9143-38916fd7253b" />

**ZipCracker上手简单，简单的说主要能力包括：**

- 伪加密识别与修复
- 常规字典爆破
- 自定义字典或字典目录
- 掩码爆破
- 短明文 CRC32 枚举恢复
- 已知明文攻击（`-kpa`）
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

# 4. 超大字典推荐写法
ZIPCRACKER_SKIP_DICT_COUNT=1 python3 ZipCracker.py target.zip huge_dict.txt
```

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
2. 如果没装 `pyzipper`，AES 条目的验证或解压可能失败，建议先安装后再试

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

对 ZIP 中长度为 1～6 字节的条目，可按归档记录的 CRC32 对可打印字符内容进行原像枚举；当候选内容计算得到的 CRC32 与记录值一致时，即判定为内容命中（终端会自动询问是否执行）。

```bash
python3 ZipCracker.py test03.zip
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

### 超大字典怎么用

ZipCracker 可以处理很大的字典，不会一次性把整份字典读进内存。

如果字典很大，比如 `10GB+`，推荐直接跳过预统计：

```bash
ZIPCRACKER_SKIP_DICT_COUNT=1 python3 ZipCracker.py your.zip your_big_dict.txt
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
3. 但继续运行时，AES 条目的验证或解压可能失败

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

<img height="380" alt="image" src="https://github.com/user-attachments/assets/c9999f9c-2f24-4aca-9b42-c6c58f5d4083" />



