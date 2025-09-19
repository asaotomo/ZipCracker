### Tool Introduction

------

[中文](./README.md)

***ZipCracker is a high-performance, multi-threaded cracking tool developed by Team Hx0, designed specifically for cracking password-protected Zip files. It uses methods such as CRC32 collision, dictionary attacks, and mask attacks to guess the plaintext or password of a Zip file and successfully extract its contents. This tool can also identify and automatically repair "pseudo-encrypted" Zip files, making it highly suitable for use in CTF competitions.***

<img width="1510" alt="image" src="https://github.com/user-attachments/assets/c698572c-2ea5-4f22-820d-5cf512eb70ec" />

**Note:**

1.The program automatically checks the file size within encrypted archives. For files smaller than 6 bytes, the system will prompt the user to choose whether to attempt cracking via CRC32 hash collision.

2.The program comes with more than 6,000 common password dictionaries and automatically generates numeric passwords from 0 to 6 digits. In addition, users can supply custom dictionaries — even very large dictionaries containing hundreds of millions of entries — and the program will handle them efficiently.

3.The program can automatically adjust the optimal number of threads based on the runtime environment, ensuring that the cracking process is both fast and stable.

4.The program not only supports attempting to decrypt compressed packages encrypted with traditional encryption algorithms but also has the capability to decrypt compressed packages encrypted with AES.

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

We provide two ways to load custom dictionaries:

1) If you want to load a single dictionary file, specify your custom dictionary directly, for example:

```
python3 ZipCracker.py test02.zip YourDict.txt
```
<img width="1240" alt="image" src="https://github.com/user-attachments/assets/4db49d4c-1d82-4461-91b5-cbbc2e0a1d53">

2) If you have multiple dictionary files, you can point the script to the directory containing them; the script will load each dictionary in sequence until the correct password is found, for example:

```
python3 ZipCracker_en.py test02.zip YourDictDirectory
```

<img width="680" height="62" alt="image" src="https://github.com/user-attachments/assets/db99f730-fc79-46c0-949c-83f83f07a2a8" />

<img width="706" height="366" alt="image" src="https://github.com/user-attachments/assets/dd0a54ce-db87-4724-b965-55ec1680bb7d" />

#### 4. Brute Force Cracking - CRC32 Collision

```
python3 ZipCracker_en.py test03.zip  
```

<img width="1240" alt="image" src="https://github.com/user-attachments/assets/6ce39b87-a603-441e-8af5-ee993b567bce">

#### 5. Brute Force Cracking - Mask Attack
When you know the partial structure of the password (e.g., company name + year), a mask attack is the most efficient method. You can use special placeholders to define the password's format, significantly narrowing the search space.

Mask Placeholder Rules:

| Placeholder | Character Set Represented |
| :--- | :----------- |
| `?d` | Digits (0-9) |
| `?l` | Lowercase Letters (a-z) |
| `?u` | Uppercase Letters (A-Z) |
| `?s` | Special Symbols (!@#$etc.) |
| `??` | The `?` character itself |

```
python3 ZipCracker_en.py test04.zip -m '?uali?s?d?d?d'
```

The command above will attempt to crack a password with the structure: an uppercase letter + 'ali' + a special symbol + three digits (e.g., Kali@123, Bali#756, etc.).

<img width="743" height="267" alt="image" src="https://github.com/user-attachments/assets/060265e3-fe54-47cb-99f3-43b6dcf41409" />


------

This tool is provided for security testers for self-assessment purposes only. The author is not responsible for any misuse or consequences caused by users. Users must comply with local laws. This program should not be used for commercial purposes and is intended for learning and education purposes only.

------
**【Support with Tips ❤️】 Code Connects Hearts Across Mountains and Seas, Every Bit of Support Warms Like Sunshine ✨**

While our code is fully open-source, every cup of coffee fuels our journey to go further ☕️

<img width="500" height="400" alt="打赏码" src="https://github.com/user-attachments/assets/02868aed-357e-4740-983a-d5a8ea05bdbf" />

**【Team Official Account】Scan and follow the team's official account for the latest updates.**

<img width="318" alt="image" src="https://user-images.githubusercontent.com/67818638/149507366-4ada14db-a972-4071-bbb6-197659f61ced.png">

**【Team Knowledge Planet】Big Giveaway**

<img width="318" alt="image" src="https://github.com/user-attachments/assets/94849d79-bcac-4a43-9221-3e2718225cb6">
