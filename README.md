### 工具简介

---

ZipCracker是一款由Hx0战队开发的高性能多并发破解工具，专为破解密码保护的Zip文件而设计。它采用CRC32碰撞和字典攻击方式猜测Zip文件的明文或密码，并能成功提取其中的内容。这款工具具备识别"伪加密"Zip文件的能力，并能自动进行修复。因此，它非常适合在CTF比赛中使用。

PS：
1.程序会自动检查加密压缩包中的文件大小，若小于6字节，会主动询问用户是否使用CRC32进行Hash碰撞。

2.程序自带6000个常用的爆破字典，同时还会生成0-6位的纯数字字典。

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

![image](https://github.com/asaotomo/ZipCracker/assets/67818638/76fd25ca-a098-41bc-968e-c758b2848c73)

**【知识星球】福利大放送**

![image](https://github.com/asaotomo/ZipCracker/assets/67818638/acb99c55-9fcb-4e1f-9258-26b313cb81e2)


