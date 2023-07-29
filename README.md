### 工具简介

---

ZipCracker是由Hx0战队开发的用于破解密码保护Zip文件的高性能Python工具。它使用字典攻击来猜测 Zip 文件的密码并提取其中的内容。该程序支持识别"伪加密"的 Zip 文件，并能够自动修复它，非常适合在CTF比赛中使用它。
程序自带6000个常用的爆破字典，同时还会生成0-6位的纯数字字典。
### 使用方法

---

#### 1.伪加密识别及修复
```
python3 ZipCracker.py test01.zip
```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/12839102/1690651786768-5237b9f1-0a9a-409a-b066-1bc5082b5d00.png#averageHue=%23242423&clientId=u500e3439-6fb6-4&from=paste&height=186&id=u2ba0e02d&originHeight=372&originWidth=1140&originalType=binary&ratio=2&rotation=0&showTitle=false&size=174601&status=done&style=none&taskId=u72dc9c6f-e921-4b09-8286-d0637c7dfbc&title=&width=570)
#### 2.暴力破解-内置字典
```
python3 ZipCracker.py test02.zip
```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/12839102/1690652249133-7e59d15b-9078-4785-b6c1-fa20274d3664.png#averageHue=%23262524&clientId=u1aad30e8-7651-4&from=paste&height=268&id=u6c0181c9&originHeight=536&originWidth=1252&originalType=binary&ratio=2&rotation=0&showTitle=false&size=302962&status=done&style=none&taskId=uf26eaff1-d2cd-49ce-baa8-3a14e8a7e38&title=&width=626)
#### 3.暴力破解-用户自定义字典
```
python3 ZipCracker.py test02.zip MyDict.txt
```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/12839102/1690652050989-0d168c89-a163-4813-b900-d31580ffd86f.png#averageHue=%23181818&clientId=u1aad30e8-7651-4&from=paste&height=765&id=u84611a0c&originHeight=1530&originWidth=1632&originalType=binary&ratio=2&rotation=0&showTitle=false&size=102947&status=done&style=none&taskId=ueaec19a7-6c1f-49b6-a26a-3bca91128d3&title=&width=816)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/12839102/1690652206786-631ddc3c-30ba-49b7-bfc9-3dc8eb89df59.png#averageHue=%23252423&clientId=u1aad30e8-7651-4&from=paste&height=267&id=ub0ef5056&originHeight=534&originWidth=1290&originalType=binary&ratio=2&rotation=0&showTitle=false&size=307030&status=done&style=none&taskId=uc5d09303-e693-4fac-b0d2-9c490e48d68&title=&width=645)

---

**本工具仅提供给安全测试人员进行安全自查使用**，**用户滥用造成的一切后果与作者无关**，**使用者请务必遵守当地法律** **本程序不得用于商业用途，仅限学习交流。**

---

**扫描关注战队公众号，获取最新动态**

[![](https://cdn.nlark.com/yuque/0/2023/png/12839102/1690652630290-1f2276f2-6938-464f-8817-7381aafc0398.png#averageHue=%23a5a5a5&clientId=u1aad30e8-7651-4&from=paste&id=u743b2692&originHeight=1440&originWidth=1440&originalType=url&ratio=2&rotation=0&showTitle=false&status=done&style=none&taskId=u4325de4f-9472-465a-a2d4-01fd56d4fd0&title=)](https://user-images.githubusercontent.com/67818638/149507366-4ada14db-a972-4071-bbb6-197659f61ced.png)
**【知识星球】福利大放送**

[![](https://cdn.nlark.com/yuque/0/2023/png/12839102/1690652630207-4de5d67e-3f41-4407-9350-22ccde6bc098.png#averageHue=%23e9706d&clientId=u1aad30e8-7651-4&from=paste&id=u67284c29&originHeight=958&originWidth=580&originalType=url&ratio=2&rotation=0&showTitle=false&status=done&style=none&taskId=u53ae5c6a-b528-45a9-b232-ff068d444bf&title=)](https://user-images.githubusercontent.com/67818638/210543877-95b791f0-c677-4019-bb6e-504eefd8164e.png)

