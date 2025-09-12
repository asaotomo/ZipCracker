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


# --- Character sets for the mask attack feature ---
CHARSET_DIGITS = string.digits
CHARSET_LOWER = string.ascii_lowercase
CHARSET_UPPER = string.ascii_uppercase
CHARSET_SYMBOLS = string.punctuation
# ------------------------------------

def is_zip_encrypted(file_path):
    """
    Checks if a ZIP file is encrypted.
    """
    with zipfile.ZipFile(file_path) as zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                return True
    return False


def fix_pseudo_encrypted_zip(file_path):
    """
    Fixes a ZIP file with pseudo-encryption.
    """
    temp_path = file_path + ".tmp"
    with zipfile.ZipFile(file_path) as zf, zipfile.ZipFile(temp_path, "w") as temp_zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                info.flag_bits ^= 0x1  # Clear the encryption flag
            temp_zf.writestr(info, zf.read(info.filename))
    fix_zip_name = os.path.join(os.path.dirname(file_path), "fixed_" + os.path.basename(file_path))
    try:
        shutil.move(temp_path, fix_zip_name)
    except Exception:
        os.remove(fix_zip_name)
        shutil.move(temp_path, fix_zip_name)
    return fix_zip_name


def check_crc_collision(zip_file, zf_obj):
    """
    Checks for small files within the ZIP to attempt a CRC32 collision attack.
    """
    cracked_count = 0
    file_list = [name for name in zf_obj.namelist() if not name.endswith('/')]
    
    for filename in file_list:
        info = zf_obj.getinfo(filename)
        file_size = info.file_size
        
        if 0 < file_size <= 6:
            choice = input(
                f"[!] The file '{filename}' in '{zip_file}' is {file_size} bytes. "
                f"Attempt to crack its content directly using CRC32 collision? (y/n): "
            )
            if choice.lower() == 'y':
                crc_val = info.CRC
                print(f"[+] CRC32 value for '{filename}': {crc_val}")
                if crack_crc(filename, crc_val, file_size):
                    cracked_count += 1

    if cracked_count > 0 and cracked_count == len(file_list):
        print(f"[*] All files in '{zip_file}' have been cracked via CRC32 collision. The dictionary attack will be skipped.")
        exit()


def crack_crc(filename, crc, size):
    """
    Performs a CRC32 collision attack on a file's content.
    Returns True on success, False otherwise.
    """
    chars = string.ascii_letters + string.digits + string.punctuation + " "
    combinations = its.product(chars, repeat=size)
    print(f"[+] Starting CRC32 collision attack for '{filename}'...")
    for combo in combinations:
        content = ''.join(combo).encode()
        if crc == binascii.crc32(content):
            print(f"[*] Success! The content of '{filename}' is: {content.decode(errors='ignore')}")
            return True
    print(f"[-] CRC32 attack failed for '{filename}'.")
    return False

# <<< CORRECTED FUNCTION >>>
def crack_password(zip_file, password, status):
    """
    Attempts to crack the ZIP file with a given password.
    """
    if status["stop"]:
        return
    try:
        with zipfile.ZipFile(zip_file) as zf:
            # The correct, robust order: test, then extract, then print success.
            zf.setpassword(password.encode('utf-8', 'ignore'))
            zf.testzip()      # Step 1: Test the password. Can raise RuntimeError.
            zf.extractall()   # Step 2: Try to extract. This is the definitive test.

            # Step 3: Only if both above succeed, declare success and terminate.
            status["stop"] = True
            print(f"\n[*] Success! The password for the archive is: {password}")
            filenames = zf.namelist()
            print(f"[*] Automatically extracted {len(filenames)} file(s): {filenames}")
            os._exit(0) # Exit immediately upon success
            
    except Exception:
        # If any step fails, silently add the password to the tried list.
        with status["lock"]:
            status["tried_passwords"].append(password)


def generate_numeric_dict():
    """
    Generates a dictionary of 1- to 6-digit numbers.
    """
    numeric_dict = []
    for length in range(1, 7):  # 1-6 digits
        for num in its.product(string.digits, repeat=length):
            numeric_dict.append(''.join(num))
    return numeric_dict, len(numeric_dict)


def display_progress(status, start_time):
    """
    Displays the cracking progress in real-time.
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
                remaining_time = (total_passwords - passwords_cracked) / avg_cracked if avg_cracked > 0 else 0
                remaining_time_str = time.strftime('%H:%M:%S', time.gmtime(remaining_time))
                progress = passwords_cracked / total_passwords * 100
            else:
                remaining_time_str = "N/A"
                progress = 0.0

            current_password = status["tried_passwords"][-1] if passwords_cracked > 0 else ""
            print(f"\r[-] Progress: {progress:.2f}%, "
                  f"Time Left: {remaining_time_str}, "
                  f"Speed: {avg_cracked} pass/s, "
                  f"Trying: {current_password:<20}",
                  end="", flush=True)


def adjust_thread_count(max_limit=128):
    """
    Dynamically adjusts the thread count based on CPU cores.
    """
    try:
        cpu_count = multiprocessing.cpu_count()
        max_threads = min(max_limit, cpu_count * 4)
    except NotImplementedError:
        max_threads = 16
    return max_threads


def count_passwords(file_path):
    """
    Counts the total number of passwords in a dictionary file.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except Exception as e:
        print(f"\n[!] Failed to load dictionary file: {e}")
        return 0


def load_passwords_in_chunks(file_path, chunk_size=1000000):
    """
    Loads passwords in chunks to save memory.
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
        print(f"\n[!] Failed to load dictionary file: {e}")


def parse_mask(mask):
    """
    Parses the mask string and returns a list of charsets and the total number of combinations.
    """
    charsets = []
    total_combinations = 1
    i = 0
    while i < len(mask):
        if mask[i] == '?':
            if i + 1 < len(mask):
                placeholder = mask[i+1]
                if placeholder == 'd':
                    charsets.append(CHARSET_DIGITS)
                    total_combinations *= len(CHARSET_DIGITS)
                elif placeholder == 'l':
                    charsets.append(CHARSET_LOWER)
                    total_combinations *= len(CHARSET_LOWER)
                elif placeholder == 'u':
                    charsets.append(CHARSET_UPPER)
                    total_combinations *= len(CHARSET_UPPER)
                elif placeholder == 's':
                    charsets.append(CHARSET_SYMBOLS)
                    total_combinations *= len(CHARSET_SYMBOLS)
                elif placeholder == '?':
                    charsets.append('?')
                else:
                    charsets.append(mask[i:i+2])
                i += 2
            else:
                charsets.append('?')
                i += 1
        else:
            charsets.append(mask[i])
            i += 1
    return charsets, total_combinations


def crack_password_with_mask(zip_file, mask, status):
    """
    Performs a bruteforce attack using a character mask.
    """
    charsets, total_passwords = parse_mask(mask)
    if total_passwords > 100_000_000_000:
        choice = input(f"\n[!] Warning: The mask '{mask}' will generate {total_passwords:,} combinations and may take a very long time. Continue? (y/n): ")
        if choice.lower() != 'y':
            print("[-] Attack aborted by user.")
            return

    print(f"\n[+] Starting mask attack with '{mask}'.")
    print(f"[+] Total password combinations to try: {total_passwords:,}")
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = []

    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] Dynamically adjusting thread count to: {max_threads}")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.daemon = True
    display_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            password_generator = (''.join(p) for p in its.product(*charsets))
            while not status["stop"]:
                chunk = list(its.islice(password_generator, 100000))
                if not chunk:
                    break
                
                futures = [executor.submit(crack_password, zip_file, password, status) for password in chunk]
                for future in as_completed(futures):
                    if status["stop"]:
                        break
                if status["stop"]:
                    break
    finally:
        time.sleep(0.2)
        if not status["stop"]:
            print('\n[-] Sorry, all passwords generated by the mask have been tried.')


def crack_password_with_file_or_dir(zip_file, dict_path, status):
    """
    Recursively processes all dictionary files in a given file or directory.
    """
    if os.path.isdir(dict_path):
        for filename in sorted(os.listdir(dict_path)):
            if status["stop"]: return
            file_path = os.path.join(dict_path, filename)
            crack_password_with_file_or_dir(zip_file, file_path, status)
    elif os.path.isfile(dict_path):
        dict_type = "user-defined dictionary" if dict_path != 'password_list.txt' else "built-in dictionary"
        crack_password_with_file(zip_file, dict_path, status, dict_type)


def crack_with_generated_numeric_dict(zip_file, status):
    """
    Performs a bruteforce attack using the generated 1-6 digit numeric dictionary.
    """
    print("\n[-] Built-in dictionary failed. Starting 1-6 digit numeric dictionary attack...")
    numeric_dict, total_passwords = generate_numeric_dict()
    print(f'[+] Loaded 1-6 digit numeric dictionary. Total passwords: {total_passwords}')
    
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = []
    
    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] Dynamically adjusting thread count to: {max_threads}")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.daemon = True
    display_thread.start()
    
    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(crack_password, zip_file, password, status) for password in numeric_dict]
            for future in as_completed(futures):
                if status["stop"]:
                    break
    finally:
        time.sleep(0.2)
        if not status["stop"]:
            print('\n[-] Sorry, all passwords from the 1-6 digit numeric dictionary have been tried.')


def crack_password_with_file(zip_file, dict_file, status, dict_type):
    """
    Performs a bruteforce attack using a specified dictionary file.
    """
    total_passwords = count_passwords(dict_file)
    if total_passwords == 0:
        return

    print(f"\n[+] Successfully loaded {dict_type} [{dict_file}].")
    print(f"[+] Total passwords in current dictionary: {total_passwords}")
    
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = [] 

    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] Dynamically adjusting thread count to: {max_threads}")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.daemon = True
    display_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            for chunk in load_passwords_in_chunks(dict_file):
                if status["stop"]: break
                futures = [executor.submit(crack_password, zip_file, password, status) for password in chunk]
                for future in as_completed(futures):
                    if status["stop"]:
                        break
    finally:
        time.sleep(0.2)
        if not status["stop"]:
            print(f'\n[-] Sorry, all passwords in the dictionary \'{dict_file}\' have been tried.')


if __name__ == '__main__':
    try:
        print("""                          
     ______          ____                _   [*] Team Hx0      
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \  | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|   
           |_| |_____|                                 
    #Coded By Asaotomo               Update: 2025.09.12
            """)
        
        if len(sys.argv) < 2:
            print("\n--- Dictionary Attack ---")
            print("[*] Usage 1 (Default Sequence): python3 ZipCracker.py YourZipFile.zip")
            print("   └─ Default Order: Tries 'password_list.txt' first, then 1-6 digit numbers.")
            print("[*] Usage 2 (Custom Dictionary): python3 ZipCracker.py YourZipFile.zip YourDict.txt")
            print("[*] Usage 3 (Dictionary Folder):   python3 ZipCracker.py YourZipFile.zip YourDictDirectory")
            print("\n--- Mask Attack ---")
            print("[*] Usage 4 (Mask):      python3 ZipCracker.py YourZipFile.zip -m 'your?dmask?l'")
            print("   ?d: digits, ?l: lowercase, ?u: uppercase, ?s: symbols, ??: literal '?'")
            sys.exit(0)

        zip_file = sys.argv[1]
        if not os.path.exists(zip_file):
            print(f"[!] Error: File '{zip_file}' not found.")
            sys.exit(1)

        if is_zip_encrypted(zip_file):
            print(f"[!] '{zip_file}' is detected as an encrypted ZIP file.")
            try:
                with zipfile.ZipFile(zip_file) as zf:
                    fixed_zip_name = fix_pseudo_encrypted_zip(zip_file)
                    try:
                        with zipfile.ZipFile(fixed_zip_name) as fixed_zf:
                            fixed_zf.testzip()
                            fixed_zf.extractall(path=os.path.dirname(fixed_zip_name))
                            filenames = fixed_zf.namelist()
                            print(f"[*] '{zip_file}' was pseudo-encrypted. A fixed archive ({fixed_zip_name}) has been created and {len(filenames)} file(s) have been extracted.")
                            os.remove(fixed_zip_name)
                            sys.exit(0)
                    except Exception:
                        os.remove(fixed_zip_name)
                        print(f"[+] '{zip_file}' is not pseudo-encrypted. Preparing for bruteforce attack.")
                        check_crc_collision(zip_file, zf)
            except Exception as e:
                print(f"[+] '{zip_file}' is not pseudo-encrypted. Preparing for bruteforce attack.")
                with zipfile.ZipFile(zip_file) as zf:
                    check_crc_collision(zip_file, zf)

            status = {
                "stop": False,
                "tried_passwords": [],
                "lock": threading.Lock(),
                "total_passwords": 0
            }

            attack_mode = "dictionary"
            if len(sys.argv) > 2 and sys.argv[2].lower() in ['-m', '--mask']:
                attack_mode = "mask"

            if attack_mode == "mask":
                if len(sys.argv) < 4:
                    print("[!] Error: No mask string provided after the -m argument.")
                    sys.exit(1)
                mask = sys.argv[3]
                crack_password_with_mask(zip_file, mask, status)
            else:
                print(f"[+] Starting dictionary bruteforce attack...")
                if len(sys.argv) > 2:
                    dict_path = sys.argv[2]
                    crack_password_with_file_or_dir(zip_file, dict_path, status)
                else:
                    if os.path.exists('password_list.txt'):
                        crack_password_with_file(zip_file, 'password_list.txt', status, "built-in dictionary")
                    else:
                        print("[!] Built-in dictionary 'password_list.txt' not found. Proceeding directly to the numeric dictionary.")
                    
                    if not status["stop"]:
                        crack_with_generated_numeric_dict(zip_file, status)
        else:
            print(f"[!] '{zip_file}' is not an encrypted ZIP file. You can extract it directly.")
    except FileNotFoundError:
        print(f"[!] Error: File '{sys.argv[1]}' not found.")
    except Exception as e:
        print(f'\n[!] An unknown error occurred: {e}')
