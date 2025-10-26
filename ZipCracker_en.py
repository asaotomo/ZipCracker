#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import zipfile
import binascii
import string
import itertools as its
import multiprocessing
from typing import Optional

# --- Added: Attempt to import pyzipper for AES support ---
try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    pyzipper = None
    HAS_PYZIPPER = False
# -----------------------------------------

# --- Added: Character set definitions for mask attack ---
CHARSET_DIGITS = string.digits
CHARSET_LOWER = string.ascii_lowercase
CHARSET_UPPER = string.ascii_uppercase
CHARSET_SYMBOLS = string.punctuation
# ------------------------------------

OUT_DIR_DEFAULT = "unzipped_files"


def is_zip_encrypted(file_path):
    """
    Check if the zip file is pseudo-encrypted.
    """
    with zipfile.ZipFile(file_path) as zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                return True
    return False


def fix_zip_encrypted(file_path, temp_path):
    """
    Attempt to fix a pseudo-encrypted zip file and write the result to temp_path.
    This function will raise an exception due to a CRC error if it encounters a truly encrypted file.
    """
    with zipfile.ZipFile(file_path) as zf, zipfile.ZipFile(temp_path, "w") as temp_zf:
        for info in zf.infolist():
            # Key operation: clear the encryption flag bit
            clean_info = info
            if clean_info.flag_bits & 0x1:
                clean_info.flag_bits ^= 0x1
            
            # Key operation: read content from the source and write to the new file
            # If the source file is truly encrypted, zf.read will raise an exception due to CRC check failure
            temp_zf.writestr(clean_info, zf.read(info.filename))


def get_crc(zip_file, fz):
    """
    Calculate the CRC value of a file.
    """
    key = 0
    file_list = [name for name in fz.namelist() if not name.endswith('/')]
    if not file_list: return

    for filename in file_list:
        getSize = fz.getinfo(filename).file_size
        if getSize > 0 and getSize <= 6:
            sw = input(
                f'[!] File "{filename}" in "{zip_file}" is {getSize} bytes. Attempt CRC32 collision attack to find its content? (y/n) ')
            if sw.lower() == 'y':
                getCrc = fz.getinfo(filename).CRC
                print(f'[+] CRC32 value for {filename} is: {getCrc}')
                crack_crc(filename, getCrc, getSize)
                key += 1
    if key >= len(file_list):
        print(f'[*] All small files in {zip_file} have been cracked via CRC32 collision. The dictionary attack will be skipped.')
        exit()


def crack_crc(filename, crc, size):
    """
    Perform a collision attack based on the CRC value.
    """
    dic = its.product(string.printable, repeat=size)
    print(f"[+] Starting CRC32 collision attack...")
    for s in dic:
        s = ''.join(s).encode()
        if crc == (binascii.crc32(s)):
            print(f'[*] Congratulations, crack successful!\n[*] The content of {filename} is: ' + str(s.decode()))
            break


# --- Added: Helper functions referenced from 4.py ---
def _find_first_file_in_zip(zf) -> Optional[str]:
    """Returns the name of the first non-directory file in a zipfile/pyzipper object, or None if empty."""
    try:
        for info in zf.infolist():
            if not info.filename.endswith('/'):
                return info.filename
    except Exception:
        try: # Fallback method
            for name in zf.namelist():
                if not name.endswith('/'):
                    return name
        except Exception:
            return None
    return None

def _clean_and_create_outdir(out_dir: str):
    """Cleans and creates the output directory."""
    if os.path.exists(out_dir):
        try:
            shutil.rmtree(out_dir)
        except Exception:
            pass
    os.makedirs(out_dir, exist_ok=True)
# -----------------------------------------


# --- Rewritten: Core cracking function with added AES support ---
def crack_password(zip_file: str, password: str, status: dict, out_dir: str):
    """
    Attempt to crack a ZIP file with the specified password (supports both AES and ZipCrypto).
    """
    if status["stop"]:
        return False

    pwd_bytes = password.encode('utf-8')
    is_correct = False

    try:
        # Prioritize pyzipper as it supports both AES and legacy encryption
        if HAS_PYZIPPER:
            with pyzipper.AESZipFile(zip_file, 'r') as zf:
                first_file = _find_first_file_in_zip(zf)
                if first_file:
                    # Reading the first file is the most reliable way to verify the password
                    zf.read(first_file, pwd=pwd_bytes)
                else: # If the archive is empty or contains only directories, use testzip
                    zf.testzip(pwd=pwd_bytes)
                is_correct = True
        # Fallback to the standard library if pyzipper is not available (only supports legacy encryption)
        else:
            with zipfile.ZipFile(zip_file, 'r') as zf:
                first_file = _find_first_file_in_zip(zf)
                if first_file:
                    zf.read(first_file, pwd=pwd_bytes)
                else:
                    zf.testzip(pwd=pwd_bytes)
                is_correct = True

    # An incorrect password will raise a RuntimeError
    except RuntimeError:
        is_correct = False
    # Other possible exceptions
    except (zipfile.BadZipFile, Exception):
        is_correct = False

    if is_correct:
        with status["lock"]:
            if status["stop"]: return # Double-check to prevent multiple threads from succeeding at once
            status["stop"] = True

        print(f'\n\n[+] Success! The password is: {password}')
        
        try:
            _clean_and_create_outdir(out_dir)
            if HAS_PYZIPPER:
                with pyzipper.AESZipFile(zip_file, 'r') as zf:
                    zf.extractall(path=out_dir, pwd=pwd_bytes)
            else:
                with zipfile.ZipFile(zip_file, 'r') as zf:
                    zf.extractall(path=out_dir, pwd=pwd_bytes)
            
            with zipfile.ZipFile(zip_file) as zf_info:
                filenames = zf_info.namelist()
                print(f"\n[*] Successfully extracted {len(filenames)} file(s) to the '{out_dir}' directory: {filenames}")
        except Exception as e:
            print(f"\n[!] Password is correct, but an error occurred during extraction: {e}")

        os._exit(0) # Forcefully terminate all threads
    else:
        with status["lock"]:
            status["tried_passwords"].append(password)
        return False

# -----------------------------------------

def generate_numeric_dict():
    """
    Generate a dictionary containing 1 to 6-digit numbers.
    """
    numeric_dict = []
    for length in range(1, 7):  # 1-6 digits
        for num in its.product(string.digits, repeat=length):
            numeric_dict.append(''.join(num))
    return numeric_dict, len(numeric_dict)


def display_progress(status, start_time):
    """
    Display the cracking progress in real-time.
    """
    while not status["stop"]:
        time.sleep(0.1)
        with status["lock"]:
            passwords_cracked = len(status["tried_passwords"])
            total_passwords = status["total_passwords"]
            current_time = time.time()
            elapsed_time = current_time - start_time
            avg_cracked = int(passwords_cracked / elapsed_time) if elapsed_time > 0 else 0

            if total_passwords > 0:
                progress = passwords_cracked / total_passwords * 100
                remaining_time = (total_passwords - passwords_cracked) / avg_cracked if avg_cracked > 0 else 0
                remaining_time_str = time.strftime('%H:%M:%S', time.gmtime(remaining_time))
            else:
                progress = 0.0
                remaining_time_str = "N/A"

            current_password = status["tried_passwords"][-1] if passwords_cracked > 0 else ""
            print(f"\r[-] Progress: {progress:.2f}%, Time Left: {remaining_time_str}, "
                  f"Speed: {avg_cracked} pass/s, Trying: {current_password:<20}",
                  end="", flush=True)


def adjust_thread_count(max_limit=128):
    """
    Dynamically adjust the number of threads.
    """
    try:
        cpu_count = multiprocessing.cpu_count()
        max_threads = min(max_limit, cpu_count * 4)
    except NotImplementedError:
        max_threads = 16 # Default value
    return max_threads


def count_passwords(file_path):
    """
    Count the total number of passwords in a dictionary file.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except Exception as e:
        print(f"[!] Failed to load dictionary file: {e}")
        exit(0)


def load_passwords_in_chunks(file_path, chunk_size=1000000):
    """
    Load passwords in chunks to save memory.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            chunk = []
            for line in f:
                chunk.append(line.strip())
                if len(chunk) >= chunk_size:
                    yield chunk
                    chunk = []
            if chunk:
                yield chunk
    except Exception as e:
        print(f"[!] Failed to load dictionary file: {e}")
        exit(0)


def parse_mask(mask):
    """
    Parse the mask string and return a list of charsets and the total number of combinations (Bugfixed version).
    """
    charsets = []
    i = 0
    while i < len(mask):
        char = mask[i]
        if char == '?':
            if i + 1 < len(mask):
                placeholder = mask[i+1]
                if placeholder == 'd':
                    charsets.append(CHARSET_DIGITS)
                elif placeholder == 'l':
                    charsets.append(CHARSET_LOWER)
                elif placeholder == 'u':
                    charsets.append(CHARSET_UPPER)
                elif placeholder == 's':
                    charsets.append(CHARSET_SYMBOLS)
                elif placeholder == '?':
                    charsets.append('?')  # Represents a literal question mark
                else:
                    # Treat undefined placeholders like ?a, ?b as literal strings "?a"
                    charsets.append(mask[i:i+2])
                i += 2
            else:  # '?' at the end of the mask
                charsets.append('?')
                i += 1
        else:
            # Normal character
            charsets.append(char)
            i += 1
            
    # Recalculate total combinations from the parsed charsets for robustness
    total_combinations = 1
    for charset in charsets:
        # Any charset with non-zero length will be correctly calculated
        if len(charset) > 0:
            total_combinations *= len(charset)
            
    # Prevent division by zero error for empty or invalid masks
    if total_combinations == 0:
        total_combinations = 1

    return charsets, total_combinations


def crack_password_with_mask(zip_file, mask, status, out_dir):
    """
    Perform a brute-force attack using a mask.
    """
    charsets, total_passwords = parse_mask(mask)
    if total_passwords > 100_000_000_000:
        choice = input(f"[!] Warning: The mask '{mask}' will generate {total_passwords:,} combinations, which could take a very long time. Continue? (y/n): ")
        if choice.lower() != 'y':
            print("[-] Attack aborted by user.")
            return

    print(f"\n[+] Starting attack with mask '{mask}'.")
    print(f"[+] Total password combinations to try: {total_passwords:,}")
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = []

    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] Dynamically adjusted thread count to: {max_threads}")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.daemon = True
    display_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            password_generator = (''.join(p) for p in its.product(*charsets))
            while not status["stop"]:
                chunk = list(its.islice(password_generator, 100000))
                if not chunk: break
                
                futures = {executor.submit(crack_password, zip_file, p, status, out_dir) for p in chunk}
                for future in as_completed(futures):
                    if status["stop"]: break
    finally:
        if not status["stop"]:
             print('\n[-] Sorry, all passwords generated by the mask have been tried. Please check your mask or try another method.')


def crack_password_with_file_or_dir(zip_file, dict_file_or_dir, status, out_dir):
    """
    Recursively process all dictionary files in a file or directory.
    """
    if os.path.isdir(dict_file_or_dir):
        for filename in sorted(os.listdir(dict_file_or_dir)):
            if status["stop"]: return
            file_path = os.path.join(dict_file_or_dir, filename)
            crack_password_with_file_or_dir(zip_file, file_path, status, out_dir)
    elif os.path.isfile(dict_file_or_dir):
        dict_type = "Custom Dictionary" if dict_file_or_dir != 'password_list.txt' else "Built-in Dictionary"
        crack_password_with_file(zip_file, dict_file_or_dir, status, dict_type, out_dir)


def crack_with_generated_numeric_dict(zip_file, status, out_dir):
    """
    Perform a brute-force attack using the generated 1-6 digit numeric dictionary.
    """
    print("\n[-] Built-in dictionary failed or not found. Trying 1-6 digit numeric dictionary...")
    numeric_dict, total_passwords = generate_numeric_dict()
    print(f'\n[+] Successfully loaded 1-6 digit numeric dictionary! Total passwords: {total_passwords}')
    
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = []
    
    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] Dynamically adjusted thread count to: {max_threads}")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.daemon = True
    display_thread.start()
    
    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(crack_password, zip_file, p, status, out_dir) for p in numeric_dict}
            for future in as_completed(futures):
                if status["stop"]: break
    finally:
        if not status["stop"]:
            print('\n[-] Sorry, all passwords from the 1-6 digit numeric dictionary have been tried.')


def crack_password_with_file(zip_file, dict_file, status, dict_type, out_dir):
    """
    Perform a brute-force attack using a specified dictionary file.
    """
    total_passwords = count_passwords(dict_file)
    print(f"\n[+] Successfully loaded {dict_type} [{dict_file}]!")
    print(f"[+] Total passwords in current dictionary: {total_passwords}")
    
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = []

    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] Dynamically adjusted thread count to: {max_threads}")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.daemon = True
    display_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            for chunk in load_passwords_in_chunks(dict_file):
                if status["stop"]: break
                futures = {executor.submit(crack_password, zip_file, p, status, out_dir) for p in chunk}
                for future in as_completed(futures):
                    if status["stop"]: break
    finally:
        if not status["stop"]:
            print(f'\n[-] Sorry, all passwords in the dictionary {dict_file} have been tried.')


if __name__ == '__main__':
    try:
        print(r"""                          
     ______          ____                _   [*]Hx0 Team
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \  | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|   
           |_| |_____|                                 
    #Coded By Asaotomo         Update:2025.09.12 (AES Support)
            """)
        
        # --- Argument parsing section remains unchanged ---
        if len(sys.argv) < 2:
            print("\n--- Dictionary Attack ---")
            print(f"[*] Usage 1 (Default Sequence): python {sys.argv[0]} YourZipFile.zip")
            print("         └─ Default order: Tries 'password_list.txt' first, then 1-6 digit numbers.")
            print(f"[*] Usage 2 (Custom Dictionary): python {sys.argv[0]} YourZipFile.zip YourDict.txt")
            print(f"[*] Usage 3 (Dictionary Directory): python {sys.argv[0]} YourZipFile.zip YourDictDirectory")
            print("\n--- Mask Attack ---")
            print(f"[*] Usage 4 (Mask): python {sys.argv[0]} YourZipFile.zip -m 'your?dmask?l'")
            print("[*]  ?d: digits, ?l: lowercase, ?u: uppercase, ?s: symbols, ??: literal '?'")
            print("\n--- Optional Arguments ---")
            print(f"[*] Usage 5 (Specify Output): python {sys.argv[0]} ... -o YourOutDir")
            os._exit(0)

        zip_file = sys.argv[1]
        out_dir = OUT_DIR_DEFAULT
        dict_path_or_mask_flag = None
        mask_value = None
        
        i = 2
        while i < len(sys.argv):
            if sys.argv[i] in ['-o', '--out']:
                if i + 1 < len(sys.argv):
                    out_dir = sys.argv[i+1]
                    i += 2
                else:
                    print("[!] Error: No directory name provided after -o argument.")
                    os._exit(1)
            elif sys.argv[i] in ['-m', '--mask']:
                if i + 1 < len(sys.argv):
                    dict_path_or_mask_flag = '-m'
                    mask_value = sys.argv[i+1]
                    i += 2
                else:
                    print("[!] Error: No mask string provided after -m argument.")
                    os._exit(1)
            else:
                if dict_path_or_mask_flag is None:
                    dict_path_or_mask_flag = sys.argv[i]
                i += 1

        if not os.path.exists(zip_file):
            print(f"[!] Error: File '{zip_file}' not found.")
            os._exit(1)

        if HAS_PYZIPPER:
            print("[+] pyzipper library detected. AES encryption support is enabled.")
        else:
            print("[*] pyzipper library not found. AES encrypted ZIP files may not be decrypted correctly. To enable AES support, please install it: pip3 install pyzipper")
        
        # --- Revised pseudo-encryption handling logic ---
        is_truly_encrypted = False
        if is_zip_encrypted(zip_file):
            print(f'[!] Encryption flag detected in {zip_file}. Attempting to fix potential pseudo-encryption...')
            fixed_zip_name = file_path = zip_file + ".fixed.tmp"
            try:
                # Move the potentially failing function call into the try block
                fix_zip_encrypted(zip_file, fixed_zip_name)
                
                with zipfile.ZipFile(fixed_zip_name) as fixed_zf:
                    fixed_zf.testzip()
                
                print(f"[*] Pseudo-encryption fixed successfully! File '{zip_file}' does not require a password.")
                _clean_and_create_outdir(out_dir)
                with zipfile.ZipFile(fixed_zip_name) as fixed_zf:
                    fixed_zf.extractall(path=out_dir)
                    filenames = fixed_zf.namelist()
                    print(f"[*] Successfully extracted {len(filenames)} file(s) to the '{out_dir}' directory: {filenames}")
                os.remove(fixed_zip_name)
                os._exit(0)

            except Exception:
                is_truly_encrypted = True
                print(f'[+] Fix attempt failed. This is a truly encrypted file. Preparing for brute-force attack.')
                if os.path.exists(fixed_zip_name):
                    os.remove(fixed_zip_name)
        
        if not is_zip_encrypted(zip_file):
             print(f'[!] {zip_file} is not an encrypted ZIP file. You can extract it directly.')
             os._exit(0)
        
        # Only truly encrypted files proceed to the cracking workflow
        if is_truly_encrypted:
            print(f'[+] Starting crack process for the truly encrypted file...')
            try:
                with zipfile.ZipFile(zip_file) as zf:
                    get_crc(zip_file, zf)
            except zipfile.BadZipFile:
                print(f"[!] '{zip_file}' may not be a valid ZIP file or it might be corrupted.")
                os._exit(1)
            
            status = { "stop": False, "tried_passwords": [], "lock": threading.Lock(), "total_passwords": 0 }

            if dict_path_or_mask_flag == '-m':
                crack_password_with_mask(zip_file, mask_value, status, out_dir)
            else:
                print(f"[+] Starting dictionary brute-force attack...")
                if dict_path_or_mask_flag:
                    crack_password_with_file_or_dir(zip_file, dict_path_or_mask_flag, status, out_dir)
                else:
                    if os.path.exists('password_list.txt'):
                        crack_password_with_file(zip_file, 'password_list.txt', status, "Built-in Dictionary", out_dir)
                    else:
                        print("[!] Built-in dictionary 'password_list.txt' not found. Will proceed with the numeric dictionary.")
                    if not status["stop"]:
                        crack_with_generated_numeric_dict(zip_file, status, out_dir)

    except FileNotFoundError:
        print(f"[!] Error: File '{sys.argv[1]}' not found.")
    except Exception as e:
        print(f'\n[!] An unknown error occurred: {e}')
        import traceback
        traceback.print_exc()
