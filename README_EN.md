### Tool Introduction

------

[中文](./README.md)

***ZipCracker is a high-performance multi-threaded cracking tool developed by the Hx0 team, designed specifically for breaking password-protected Zip files. It uses CRC32 collision and dictionary attack methods to guess the plaintext or password of Zip files and successfully extract their contents. This tool has the ability to identify "pseudo-encrypted" Zip files and can automatically repair them, making it particularly suitable for use in CTF competitions.***

**Note:**

1.The program automatically checks the file size within encrypted archives. For files smaller than 6 bytes, the system will prompt the user to choose whether to attempt cracking via CRC32 hash collision.

2.The program includes a built-in dictionary of 6,000 common passwords and automatically generates a list of numeric passwords ranging from 0 to 6 digits. Additionally, users can utilize their own custom dictionaries, and the program can efficiently handle even large dictionaries containing hundreds of millions of entries.

3.The program can automatically adjust the optimal number of threads based on the runtime environment, ensuring that the cracking process is both fast and stable.

### Usage

------

#### 1. Pseudo-Encryption Identification and Repair

```
python3 ZipCracker_en.py test01.zip  
```

<img width="1240" alt="image" src="https://github.com/user-attachments/assets/b6e2b0ea-9c93-42b4-acf3-888909d7365b">


#### 2. Brute Force Cracking - Built-in Dictionary

```
python3 ZipCracker_en.py test02.zip  
```

<img width="1240" alt="image" src="https://github.com/user-attachments/assets/fb00a9a8-a197-4df6-bac6-89868862135f">


#### 3. Brute Force Cracking - Custom Dictionary

```
python3 ZipCracker_en.py test02.zip MyDict.txt  
```

<img width="1240" alt="image" src="https://github.com/user-attachments/assets/4db49d4c-1d82-4461-91b5-cbbc2e0a1d53">



#### 4. Brute Force Cracking - CRC32 Collision

```
python3 ZipCracker.py test03.zip  
```

<img width="1240" alt="image" src="https://github.com/user-attachments/assets/6ce39b87-a603-441e-8af5-ee993b567bce">

------

This tool is provided for security testers for self-assessment purposes only. The author is not responsible for any misuse or consequences caused by users. Users must comply with local laws. This program should not be used for commercial purposes and is intended for learning and education purposes only.

------

**Scan and follow the team's official account for the latest updates.**

<img width="318" alt="image" src="https://user-images.githubusercontent.com/67818638/149507366-4ada14db-a972-4071-bbb6-197659f61ced.png">

**【Knowledge Planet】Big Giveaway**

<img width="318" alt="image" src="https://github.com/asaotomo/ZipCracker/assets/67818638/659b508c-12ad-47a9-8df5-f2c36403c02b">
