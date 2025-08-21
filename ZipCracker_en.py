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


# --- Definitions for the new Mask Attack feature ---
CHARSET_DIGITS = string.digits
CHARSET_LOWER = string.ascii_lowercase
CHARSET_UPPER = string.ascii_uppercase
CHARSET_SYMBOLS = string.punctuation
# ----------------------------------------------------

def is_zip_encrypted(file_path):
    """
    Check if the zip file has fake encryption.
    """
    with zipfile.ZipFile(file_path) as zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                return True
    return False


def fix_zip_encrypted(file_path):
    """
    Fix a zip file with fake encryption.
    """
    temp_path = file_path + ".tmp"
    with zipfile.ZipFile(file_path) as zf, zipfile.ZipFile(temp_path, "w") as temp_zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                info.flag_bits ^= 0x1  # Clear the encryption flag
            temp_zf.writestr(info, zf.read(info.filename))
    fixed_zip_name = os.path.join(os.path.dirname(file_path), "fixed_" + os.path.basename(file_path))
    try:
        shutil.move(temp_path, fixed_zip_name)
    except Exception:
        os.remove(fixed_zip_name)
        shutil.move(temp_path, fixed_zip_name)
    return fixed_zip_name


def get_crc(zip_file, zf):
    """
    Calculate the CRC32 checksum for files within the archive.
    """
    key = 0
    for filename in zf.namelist():
        if filename.endswith('/'):  # Skip directories
            continue
        file_size = zf.getinfo(filename).file_size
        if file_size <= 6:
            choice = input(
                f'[!] The system detected that {filename} in the archive {zip_file} is {file_size} bytes. '
                'Would you like to attempt a CRC32 collision attack on this file? (y/n)')
            if choice.lower() == 'y':
                crc_value = zf.getinfo(filename).CRC
                print(f'[+] The CRC value of {filename} is: {crc_value}')
                crack_crc(filename, crc_value, file_size)
                key += 1
    if key >= len([name for name in zf.namelist() if not name.endswith('/')]):  # Count only files, not directories
        print(f'[*] All files in {zip_file} have been successfully cracked using CRC32 collisions, no need for dictionary attacks!')
        exit()


def crack_crc(filename, crc, size):
    """
    Attempt a CRC32 collision.
    """
    dic = its.product(string.printable, repeat=size)
    print(f"[+] Starting CRC32 collision attack...")
    for s in dic:
        s = ''.join(s).encode()
        if crc == binascii.crc32(s):
            print(f'[*] Congratulations, the content of {filename} is: ' + str(s.decode()))
            break


def crack_password(zip_file, password, status):
    """
    Try to extract the ZIP file using a specified password.
    """
    if status["stop"]:
        return False
    try:
        with zipfile.ZipFile(zip_file) as zf:
            zf.setpassword(password.encode())
            zf.testzip()
            zf.extractall()
            print(f'\n[*] Success! The password for the archive {zip_file} is: {password}')
            filenames = zf.namelist()
            print(f"[*] Extracted {len(filenames)} files from the archive: {filenames}")
            status["stop"] = True
            os._exit(0)
    except Exception:
        with status["lock"]:
            status["tried_passwords"].append(password)
    return False


def generate_numeric_dict():
    """
    Generate a dictionary of numeric passwords from 1 to 6 digits.
    """
    numeric_dict = []
    for length in range(1, 7):  # 1-6 digits
        for num in its.product(string.digits, repeat=length):
            numeric_dict.append(''.join(num))
    return numeric_dict, len(numeric_dict)


def display_progress(status, start_time):
    """
    Display cracking progress in real-time.
    """
    while not status["stop"]:
        time.sleep(0.0835)  # Update progress every 0.0835 seconds
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
            print("\r[-] Progress: {:.2f}%, Time left: {}, Speed: {} p/s, Trying password:{:<20}".format(
                progress, remaining_time_str, avg_cracked, current_password),
                end="", flush=True)


def adjust_thread_count(max_limit=128):
    """
    Dynamically adjust the number of threads.
    """
    cpu_count = multiprocessing.cpu_count()
    max_threads = min(max_limit, cpu_count * 4)  # Use 4 times the logical CPU count, up to the maximum limit
    return max_threads


def count_passwords(file_path):
    """
    Count the total number of passwords in the dictionary file.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except Exception as e:
        print(f"[!] Failed to load dictionary file, reason: {e}")
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
        print(f"[!] Failed to load dictionary file, reason: {e}")
        exit(0)

# --- New Feature: Mask Attack ---

def parse_mask(mask):
    """
    Parse the mask string, return a list of charsets and the total number of combinations.
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
                    charsets.append('?') # Represents a literal question mark
                else:
                    # Unknown placeholder, treat as a literal string
                    charsets.append(mask[i:i+2])
                i += 2
            else: # Trailing '?'
                charsets.append('?')
                i += 1
        else:
            charsets.append(mask[i])
            i += 1
    return charsets, total_combinations


def crack_password_with_mask(zip_file, mask, status):
    """
    Perform brute-force attack using a mask.
    """
    charsets, total_passwords = parse_mask(mask)
    if total_passwords > 100_000_000_000: # Warn the user if combinations exceed 100 billion
        choice = input(f"[!] Warning: The mask '{mask}' generates {total_passwords:,} combinations, which may take a very long time. Continue? (y/n): ")
        if choice.lower() != 'y':
            print("[-] Attack aborted by user.")
            return

    print(f"\n[+] Starting mask attack with '{mask}'.")
    print(f"[+] Total password combinations to try: {total_passwords:,}")
    status["total_passwords"] = total_passwords

    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] Adjusted thread count to: {max_threads}")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Create a password generator to avoid loading all combinations into memory at once
            password_generator = (''.join(p) for p in its.product(*charsets))
            
            # Get passwords in chunks from the generator and submit them to the thread pool
            while not status["stop"]:
                chunk = list(its.islice(password_generator, 100000)) # Process 100,000 passwords at a time
                if not chunk: # Generator is exhausted
                    break
                
                future_to_password = {executor.submit(crack_password, zip_file, password, status): password for password in chunk}
                for future in as_completed(future_to_password):
                    if future.result() or status["stop"]:
                        status["stop"] = True
                        break # Inner loop
                if status["stop"]:
                    break # Outer loop

    finally:
        status["stop"] = True
        display_thread.join()

    if "Success!" not in status:
         print('\n[-] Sorry, all passwords generated by the mask have been tried. Please check your mask or try other methods!')

# --- Dictionary attack functions modified for the new main logic ---

def crack_password_with_file_or_dir(zip_file, dict_file_or_dir, status):
    if os.path.isdir(dict_file_or_dir):
        for filename in sorted(os.listdir(dict_file_or_dir)): # Sort by filename
            file_path = os.path.join(dict_file_or_dir, filename)
            if os.path.isfile(file_path):
                crack_password_with_chunks(zip_file, file_path, status, "Custom Dictionary")
            else:
                crack_password_with_file_or_dir(zip_file, file_path, status)
    else:
        crack_password_with_chunks(zip_file, dict_file_or_dir, status, "Custom Dictionary")


def crack_password_with_chunks(zip_file, dict_file, status, dict_type):
    """
    Perform brute force attack using dictionary loaded in chunks.
    """
    numeric_dict_num = 0
    if dict_file == 'password_list.txt':
        numeric_dict_num = len(generate_numeric_dict()[0])
        total_passwords = numeric_dict_num
        print(f'[+] Loaded 0-6 digit numeric dictionary successfully! Total passwords: {total_passwords}')
    else:
        total_passwords = count_passwords(dict_file)
        print(f"\n[+] Loaded {dict_type}[{dict_file}] successfully!")
        print(f"[+] Total number of passwords in the current dictionary: {total_passwords}")
    
    status["total_passwords"] += total_passwords

    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] Adjusted thread count to: {max_threads}")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Process the dictionary file
            if dict_file != 'password_list.txt':
                for chunk in load_passwords_in_chunks(dict_file):
                    if status["stop"]: break
                    future_to_password = {executor.submit(crack_password, zip_file, password, status): password for password in chunk}
                    for future in as_completed(future_to_password):
                        if future.result() or status["stop"]:
                            status["stop"] = True
                            break
            
            # Process the built-in numeric dictionary
            if not status["stop"] and dict_file == 'password_list.txt':
                numeric_dict, _ = generate_numeric_dict()
                future_to_password = {executor.submit(crack_password, zip_file, password, status): password for password in numeric_dict}
                for future in as_completed(future_to_password):
                    if future.result() or status["stop"]:
                        status["stop"] = True
                        break
    finally:
        status["stop"] = True
        display_thread.join()

    if "Success!" not in status:
        print('\n[-] Sorry, all passwords in the dictionary have been tried.')


if __name__ == '__main__':
    try:
        print("""
     ______          ____                _   [*]Hx0 Team      
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \  | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|   
           |_| |_____|                                 
    #Coded By Asaotomo               Update:2025.08.21
            """)
        
        # --- Modified main logic to differentiate between attack modes ---
        if len(sys.argv) < 2:
            print("\n[*] --- Dictionary Attack ---")
            print("[*] Usage 1 (built-in dict): python3 ZipCracker_en.py YourZipFile.zip")
            print("[*] Usage 2 (custom dict):   python3 ZipCracker_en.py YourZipFile.zip YourDict.txt")
            print("[*] Usage 3 (dict folder):   python3 ZipCracker_en.py YourZipFile.zip YourDictDirectory")
            print("\n[*] --- Mask Attack ---")
            print("[*] Usage 4 (mask):          python3 ZipCracker_en.py YourZipFile.zip -m 'your?dmask?l'")
            print("[*]   ?d: digit, ?l: lower, ?u: upper, ?s: symbol, ??: literal '?'")
            os._exit(0)

        zip_file = sys.argv[1]
        if not os.path.exists(zip_file):
            print(f"[!] Error: Zip file '{zip_file}' not found.")
            os._exit(1)

        if is_zip_encrypted(zip_file):
            print(f'[!] Detected that {zip_file} is an encrypted ZIP file.')
            try:
                with zipfile.ZipFile(zip_file) as zf:
                    # First, try to fix fake encryption
                    fixed_zip_name = fix_zip_encrypted(zip_file)
                    try:
                        with zipfile.ZipFile(fixed_zip_name) as fixed_zf:
                            fixed_zf.testzip()
                            fixed_zf.extractall(path=os.path.dirname(fixed_zip_name))
                            filenames = fixed_zf.namelist()
                            print(f"[*] The archive {zip_file} had fake encryption. A fixed archive ({fixed_zip_name}) has been generated and {len(filenames)} files extracted.")
                            os.remove(fixed_zip_name) # Clean up the fixed file
                            os._exit(0)
                    except Exception:
                        os.remove(fixed_zip_name) # Fix failed, clean up the temp file
                        print(f'[+] Archive {zip_file} is not falsely encrypted, preparing for brute force attack.')
                        get_crc(zip_file, zf) # Perform CRC32 collision check
            except Exception as e:
                print(f'[+] Archive {zip_file} is not falsely encrypted, preparing for brute force attack.')
                with zipfile.ZipFile(zip_file) as zf:
                    get_crc(zip_file, zf)

            # Initialize the shared status dictionary
            status = {
                "stop": False,
                "tried_passwords": [],
                "lock": threading.Lock(),
                "total_passwords": 0
            }

            # Determine the attack mode
            attack_mode = "dictionary"
            if len(sys.argv) > 2 and sys.argv[2] in ['-m', '--mask']:
                attack_mode = "mask"

            if attack_mode == "mask":
                if len(sys.argv) < 4:
                    print("[!] Error: Mask string not provided after -m flag.")
                    os._exit(1)
                mask = sys.argv[3]
                crack_password_with_mask(zip_file, mask, status)
            else: # Default to dictionary attack
                if len(sys.argv) > 2:
                    dict_path = sys.argv[2]
                    crack_password_with_file_or_dir(zip_file, dict_path, status)
                else: # Use the built-in dictionary
                    crack_password_with_chunks(zip_file, 'password_list.txt', status, "Built-in Dictionary")
        else:
            print(f'[!] Detected that {zip_file} is not an encrypted ZIP file, you can unzip it directly!')
    except FileNotFoundError:
        print(f"[!] Error: The file '{sys.argv[1]}' was not found.")
    except Exception as e:
        print(f'\n[!] An error occurred: {e}')
