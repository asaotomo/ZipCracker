### Tool Introduction

------

[中文](./README.md)

ZipCracker is a high-performance multi-threaded cracking tool developed by the Hx0 team, designed specifically for breaking password-protected Zip files. It uses CRC32 collision and dictionary attack methods to guess the plaintext or password of Zip files and successfully extract their contents. This tool has the ability to identify "pseudo-encrypted" Zip files and can automatically repair them, making it particularly suitable for use in CTF competitions.

**Note:**

1. The program automatically checks the file size in encrypted compressed files. If it is less than 6 bytes, it will prompt the user whether to use CRC32 for hash collision.
2. The program includes 6000 common cracking dictionaries and generates pure numeric dictionaries from 0 to 6 digits.
3. The program automatically adjusts the number of threads based on the runtime environment, providing extremely fast cracking speeds.

### Usage

------

#### 1. Pseudo-Encryption Identification and Repair

```
python3 ZipCracker.py test01.zip  
```

![image](https://github.com/asaotomo/ZipCracker/assets/67818638/88fd42b5-7b89-452d-a640-77326dc05b4c)

#### 2. Brute Force Cracking - Built-in Dictionary

```
python3 ZipCracker.py test02.zip  
```

![image](https://github.com/asaotomo/ZipCracker/assets/67818638/bcfdc434-3eb2-426f-8f83-7951c9af4b59)

#### 3. Brute Force Cracking - Custom Dictionary

```
python3 ZipCracker.py test02.zip MyDict.txt  
```

![image](https://github.com/asaotomo/ZipCracker/assets/67818638/c11fd091-b4a5-4b5f-ab39-8489604cf57d)

#### 4. Brute Force Cracking - CRC32 Collision

```
python3 ZipCracker.py test03.zip  
```

![image](https://github.com/asaotomo/ZipCracker/assets/67818638/db48ca5c-3c24-44a6-8a79-0398b1b56222)

------

This tool is provided for security testers for self-assessment purposes only. The author is not responsible for any misuse or consequences caused by users. Users must comply with local laws. This program should not be used for commercial purposes and is intended for learning and education purposes only.

------

**Scan and follow the team's official account for the latest updates.**

![image](https://user-images.githubusercontent.com/67818638/149507366-4ada14db-a972-4071-bbb6-197659f61ced.png)

**【Knowledge Planet】Big Giveaway**

![image](https://github.com/asaotomo/ZipCracker/assets/67818638/659b508c-12ad-47a9-8df5-f2c36403c02b)