import os
import shutil
import sys
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import zipfile
import binascii
import string
import itertools as its
import multiprocessing


def is_zip_encrypted(file_path):
    """
    Check if the zip file has false encryption.
    """
    with zipfile.ZipFile(file_path) as zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                return True
    return False


def fix_zip_encrypted(file_path):
    """
    Fix a zip file with false encryption.
    """
    temp_path = file_path + ".tmp"
    with zipfile.ZipFile(file_path) as zf, zipfile.ZipFile(temp_path, "w") as temp_zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                info.flag_bits ^= 0x1  # 清除加密标记
            temp_zf.writestr(info, zf.read(info.filename))
    fix_zip_name = os.path.join(os.path.dirname(file_path), "fix_" + os.path.basename(file_path)) 
    try:
        shutil.move(temp_path, fix_zip_name)
    except:
        os.remove(fix_zip_name)
        shutil.move(temp_path, fix_zip_name)
    return fix_zip_name


def crack_password(zip_file, password, status):
    global success
    if status["stop"]:
        return False
    try:
        zf = zipfile.ZipFile(zip_file)
        zf.setpassword(password.encode())
        zf.extractall()
        print(f'\n[*]Congratulations! Password cracking successful, the password for this archive is: {password}')
        success = True
        filenames = zf.namelist()
        print(f"[*]The system has automatically extracted {len(filenames)} files: {filenames}")
        status["stop"] = True
        os._exit(0)
    except:
        with status["lock"]:
            status["tried_passwords"].append(password)
    return False


def get_crc(zip_file, fz):
    key = 0
    for filename in fz.namelist():
        if filename.endswith('/'):  # Skip directories
            continue
        size = fz.getinfo(filename).file_size
        if size <= 6:
            switch = input(
                f'[!]The system detects that the size of the file {filename} in the archive {zip_file} is {size} bytes, '
                f'do you want to attempt to crack the content of this file directly through a CRC32 collision? (y/n)')
            if switch in ['y', 'Y']:
                crc = fz.getinfo(filename).CRC
                print(f'[+]{filename} has a CRC value of: {crc}')
                crack_crc(filename, crc, size)
                key += 1
    if key >= len([name for name in fz.namelist() if not name.endswith('/')]):  # Only count files, not directories
        print(f'[*]The system detected that all files in {zip_file} have been cracked through CRC32 collisions, '
              f'no brute force with a dictionary will be used!')
        exit()


def crack_crc(filename, crc, size):
    dic = its.product(string.printable, repeat=size)
    print(f"[+]The system starts CRC32 collision cracking...")
    for s in dic:
        s = ''.join(s).encode()
        if crc == (binascii.crc32(s)):
            print(f'[*]Congratulations, cracking successful!\n[*]The content of the file {filename} is: ' + str(
                s.decode()))
            break


def display_progress(status, total_passwords, start_time):
    while not status["stop"]:
        time.sleep(0.0167)  # Update progress every 0.0167 seconds
        with status["lock"]:
            passwords_cracked = len(status["tried_passwords"])
            current_time = time.time()
            elapsed_time = current_time - start_time
            avg_cracked = int(passwords_cracked / elapsed_time) if elapsed_time > 0 else 0
            remaining_time = (total_passwords - passwords_cracked) / avg_cracked if avg_cracked > 0 else 0
            remaining_time_str = time.strftime('%H:%M:%S', time.gmtime(remaining_time))
            print("\r[-]Current cracking progress: {:.2f}%, remaining time: {}, current speed: {} per second, "
                  "trying password: {:<20}".format(
                passwords_cracked / total_passwords * 100,
                remaining_time_str,
                avg_cracked,
                status["tried_passwords"][-1] if passwords_cracked > 0 else ""),
                end="", flush=True)


def adjust_thread_count(max_limit=128):  
    cpu_count = multiprocessing.cpu_count()  
    # Use 4 times the number of logical CPUs as the thread count, but do not exceed the maximum limit  
    max_threads = min(max_limit, cpu_count * 4)  
    return max_threads


if __name__ == '__main__':
    try:
        print("""                          
     ______          ____                _   [*]Hx0 Team      
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \  | |   | '__/ _` |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|   
           |_| |_____|                                 
    #Coded By Asaotomo               Update:2024.12.31
            """)
        if len(sys.argv) == 1:
            print(
                "[*]Usage 1 (built-in dictionary): Python3 Hx0_Zip_Cracker.py YourZipFile.zip \n"
                "[*]Usage 2 (custom dictionary): Python3 Hx0_Zip_Cracker.py YourZipFile.zip YourDict.txt")
            os._exit(0)
        zip_file = sys.argv[1]
        if is_zip_encrypted(zip_file):
            print(f'[!]The system detects that {zip_file} is an encrypted ZIP file')
            zf = zipfile.ZipFile(zip_file)
            try:
                fixed_zip_name = fix_zip_encrypted(zip_file)
                print(fixed_zip_name)
                zf = zipfile.ZipFile(fixed_zip_name)
                zf.testzip()
                zf.extractall(path=os.path.dirname(fixed_zip_name))
                filenames = zf.namelist()
                print(
                    f"[*]The archive {zip_file} has false encryption, the system has generated a repaired archive "
                    f"({fixed_zip_name}) for you, and automatically extracted {len(filenames)} files: {filenames}")
                os._exit(0)
            except Exception as e:
                os.remove(zip_file + ".tmp")
                zf = zipfile.ZipFile(zip_file)
                print(f'[+]The archive {zip_file} is not falsely encrypted, preparing to attempt brute force cracking')
                # CRC32 collision
                get_crc(zip_file, zf)
                # Cracking the encrypted zip file
                password_list = []
                if len(sys.argv) > 2:  # Check if a custom dictionary file is specified
                    dict_file = sys.argv[2]
                    dict_type = "User-defined dictionary"
                else:
                    dict_file = 'password_list.txt'
                    dict_type = "System built-in dictionary"
                try:
                    with open(dict_file, 'r') as f:
                        password_list += [line.strip() for line in f.readlines()]
                    print(f'[+]Loading {dict_type} [{dict_file}] successful!')
                except Exception as e:
                    print(f'[!]Failed to load {dict_type}, reason: {e}')
                    exit(0)
                for length in range(1, 7):
                    password_list += [f'{i:0{length}d}' for i in range(10 ** length)]
                print(f'[+]Loading pure numeric dictionary of 0-6 digits successful!')
                password_list = list(OrderedDict.fromkeys(password_list))
                total_passwords = len(password_list)
                print(f"[+]Total number of passwords in the current brute force dictionary: {total_passwords}")
                print(f"[+]The system starts brute force cracking...")
                success = False
                status = {
                    "stop": False,
                    "tried_passwords": [],
                    "lock": threading.Lock()
                }

                start_time = time.time()
                display_thread = threading.Thread(target=display_progress, args=(status, total_passwords, start_time))
                display_thread.start()
                max_threads = adjust_thread_count()
                print(f"[+]Dynamically adjusted thread count to: {max_threads}")

                # Control virtual memory usage
                threading.stack_size(65536)
                with ThreadPoolExecutor(max_workers=max_threads) as executor:  # Dynamically set maximum thread count
                    future_to_password = {executor.submit(crack_password, zip_file, password, status): password for
                                          password in password_list}
                    for future in as_completed(future_to_password):
                        if future.result():
                            success = True
                            break

                status["stop"] = True
                display_thread.join()

                if not success:
                    print('\n[-]Unfortunately, all passwords in the dictionary have been attempted, please try '
                          'another dictionary or use more advanced cracking methods!')
                else:
                    print(
                        f'[!]The system detects that {zip_file} is not an encrypted ZIP file, you can extract it directly!')
    except Exception as e:
        print(f'[!]An error occurred: {e}')
