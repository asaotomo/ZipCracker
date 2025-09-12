### 工具简介

---

[English](./README_EN.md)

***ZipCracker是一款由Hx0战队开发的高性能多并发破解工具，专为破解密码保护的Zip文件而设计。它采用CRC32碰撞、字典攻击及掩码攻击等方式猜测Zip文件的明文或密码，并能成功提取其中的内容。这款工具具备识别"伪加密"Zip文件的能力，并能自动进行修复。因此，它非常适合在CTF比赛中使用。***

<img width="1510" alt="image" src="https://github.com/user-attachments/assets/c698572c-2ea5-4f22-820d-5cf512eb70ec" />


PS：

1.程序会自动检查加密压缩包中的文件大小。对于小于6字节的文件，系统将提示用户是否希望通过CRC32哈希碰撞来尝试破解。

2.程序内置了6,000多个常用密码词典，并自动生成0至6位纯数字的密码列表。此外，用户还可以使用自己的定制字典，即使该字典包含数亿条目的大字典，程序也能高效处理。

3.程序能够根据运行环境自动调整最优线程数量，确保破解过程既快速又稳定。

4.程序不仅支持对采用传统加密算法的压缩包进行解密尝试，还具备对AES加密压缩包的解密能力。

### 使用方法

---

#### 1.伪加密识别及修复
```
python3 ZipCracker.py test01.zip
```
<img width="800" alt="image" src="https://github.com/asaotomo/ZipCracker/assets/67818638/88fd42b5-7b89-452d-a640-77326dc05b4c">

#### 2.暴力破解-内置字典
```
python3 ZipCracker.py test02.zip
```
<img width="800" alt="image" src="https://github.com/asaotomo/ZipCracker/assets/67818638/bcfdc434-3eb2-426f-8f83-7951c9af4b59">

#### 3.暴力破解-用户自定义字典

我们为您提供了2种用户自定义字典的加载方式：

1) 若您仅想加载单个字典，您可以选择直接加载您的自定义字典，如下图所示：

```
python3 ZipCracker.py test02.zip YourDict.txt
```

<img width="800" alt="image" src="https://github.com/asaotomo/ZipCracker/assets/67818638/c11fd091-b4a5-4b5f-ab39-8489604cf57d">

2) 若您有多个字典，也可以选择直接加载您的字典所在目录，脚本会依次加载目录下所有字典，直到找到最终密码，如下图所示：

```
python3 ZipCracker.py test02.zip YourDictDirectory
```

<img width="708" height="65" alt="image" src="https://github.com/user-attachments/assets/e6394f4d-02ec-4afd-8b6f-407ccbe75882" />

<img width="742" height="370" alt="image" src="https://github.com/user-attachments/assets/5dce2f67-61af-402a-9735-57e79432129e" />


#### 4.暴力破解-CRC32碰撞
```
python3 ZipCracker.py test03.zip
```
<img width="800" alt="image" src="https://github.com/asaotomo/ZipCracker/assets/67818638/db48ca5c-3c24-44a6-8a79-0398b1b56222">

#### 5.暴力破解-掩码攻击

当您已知密码的部分结构时（例如，公司名+年份），掩码攻击是最高效的破解方式。您可以使用特殊占位符来定义密码的格式，从而极大地缩小密码搜索范围。

掩码占位符规则:

| 占位符 | 代表的字符集 |
| :--- | :----------- |
| `?d` | 数字 (0-9) |
| `?l` | 小写字母 (a-z) |
| `?u` | 大写字母 (A-Z) |
| `?s` | 特殊符号 (!@#$等) |
| `??` | 问号 `?` 自身 |

```
python3 ZipCracker.py test04.zip -m '?uali?s?d?d?d'
```

上述命令会尝试破解密码结构为: 一个大写字母 + 'ali' + 一个特殊符号 + 三个数字 (例如 Kali@123,  Bali#756 等) 的ZIP文件。

<img width="818" height="266" alt="image" src="https://github.com/user-attachments/assets/37abb6a2-6ba7-4fed-937b-e62ceab6e378" />


---

**本工具仅提供给安全测试人员进行安全自查使用**，**用户滥用造成的一切后果与作者无关**，**使用者请务必遵守当地法律** **本程序不得用于商业用途，仅限学习交流。**

---

**扫描关注战队公众号，获取最新动态**

<img width="318" alt="image" src="https://user-images.githubusercontent.com/67818638/149507366-4ada14db-a972-4071-bbb6-197659f61ced.png">

**【知识星球】福利大放送**

<img width="318" alt="image" src="https://github.com/user-attachments/assets/94849d79-bcac-4a43-9221-3e2718225cb6">


