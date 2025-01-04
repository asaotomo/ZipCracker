### 工具简介

---

[English](./README_EN.md)

***ZipCracker是一款由Hx0战队开发的高性能多并发破解工具，专为破解密码保护的Zip文件而设计。它采用CRC32碰撞和字典攻击方式猜测Zip文件的明文或密码，并能成功提取其中的内容。这款工具具备识别"伪加密"Zip文件的能力，并能自动进行修复。因此，它非常适合在CTF比赛中使用。***

PS：

1.程序会自动检查加密压缩包中的文件大小。对于小于6字节的文件，系统将提示用户是否希望通过CRC32哈希碰撞来尝试破解。

2.程序内置了6,000个常用密码词典，并自动生成0至6位纯数字的密码列表。此外，用户还可以使用自己的定制字典，即使该字典包含数千万条目，程序也能高效处理。

3.程序能够根据运行环境自动调整最优线程数量，确保破解过程既快速又稳定。

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
```
python3 ZipCracker.py test02.zip MyDict.txt
```
<img width="800" alt="image" src="https://github.com/asaotomo/ZipCracker/assets/67818638/c11fd091-b4a5-4b5f-ab39-8489604cf57d">

#### 4.暴力破解-CRC32碰撞
```
python3 ZipCracker.py test03.zip
```
<img width="800" alt="image" src="https://github.com/asaotomo/ZipCracker/assets/67818638/db48ca5c-3c24-44a6-8a79-0398b1b56222">

---

**本工具仅提供给安全测试人员进行安全自查使用**，**用户滥用造成的一切后果与作者无关**，**使用者请务必遵守当地法律** **本程序不得用于商业用途，仅限学习交流。**

---

**扫描关注战队公众号，获取最新动态**

<img width="318" alt="image" src="https://user-images.githubusercontent.com/67818638/149507366-4ada14db-a972-4071-bbb6-197659f61ced.png">

**【知识星球】福利大放送**

<img width="318" alt="image" src="https://github.com/asaotomo/ZipCracker/assets/67818638/659b508c-12ad-47a9-8df5-f2c36403c02b">


