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

# --- 新增：尝试导入 pyzipper 以支持 AES ---
try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    pyzipper = None
    HAS_PYZIPPER = False
# -----------------------------------------

# --- 为掩码攻击功能新增的字符集定义 ---
CHARSET_DIGITS = string.digits
CHARSET_LOWER = string.ascii_lowercase
CHARSET_UPPER = string.ascii_uppercase
CHARSET_SYMBOLS = string.punctuation
# ------------------------------------

OUT_DIR_DEFAULT = "unzipped_files"


def is_zip_encrypted(file_path):
    """
    检查zip文件是否存在伪加密
    """
    with zipfile.ZipFile(file_path) as zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                return True
    return False


def fix_zip_encrypted(file_path, temp_path):
    """
    尝试修复伪加密的zip文件，将结果写入 temp_path。
    如果遇到真加密文件，此函数会因为 CRC 错误而抛出异常。
    """
    with zipfile.ZipFile(file_path) as zf, zipfile.ZipFile(temp_path, "w") as temp_zf:
        for info in zf.infolist():
            # 关键操作：清除加密标志位
            clean_info = info
            if clean_info.flag_bits & 0x1:
                clean_info.flag_bits ^= 0x1
            
            # 关键操作：读取源文件内容并写入新文件
            # 如果源文件是真加密，zf.read 会因 CRC 校验失败而抛出异常
            temp_zf.writestr(clean_info, zf.read(info.filename))


def get_crc(zip_file, fz):
    """
    计算文件crc值
    """
    key = 0
    file_list = [name for name in fz.namelist() if not name.endswith('/')]
    if not file_list: return

    for filename in file_list:
        getSize = fz.getinfo(filename).file_size
        if getSize > 0 and getSize <= 6:
            sw = input(
                f'[!] 系统监测到压缩包 {zip_file} 中的 {filename} 文件大小为{getSize}字节，是否尝试通过CRC32碰撞的方式直接爆破该文件内容？（y/n）')
            if sw.lower() == 'y':
                getCrc = fz.getinfo(filename).CRC
                print(f'[+]{filename} 文件的CRC值为：{getCrc}')
                crack_crc(filename, getCrc, getSize)
                key += 1
    if key >= len(file_list):
        print(f'[*] 系统检测到 {zip_file} 中的所有文件均已通过CRC32碰撞破解完成，将不再使用字典进行暴力破解！')
        exit()


def crack_crc(filename, crc, size):
    """
    根据crc值进行碰撞
    """
    dic = its.product(string.printable, repeat=size)
    print(f"[+] 系统开始进行CRC32碰撞破解······")
    for s in dic:
        s = ''.join(s).encode()
        if crc == (binascii.crc32(s)):
            print(f'[*] 恭喜您，破解成功！\n[*] {filename} 文件的内容为：' + str(s.decode()))
            break


# --- 新增：从 4.py 参考而来的辅助函数 ---
def _find_first_file_in_zip(zf) -> Optional[str]:
    """返回 zipfile/pyzipper 对象中第一个非目录文件的名字，若没有则返回 None。"""
    try:
        for info in zf.infolist():
            if not info.filename.endswith('/'):
                return info.filename
    except Exception:
        try: # 备用方法
            for name in zf.namelist():
                if not name.endswith('/'):
                    return name
        except Exception:
            return None
    return None

def _clean_and_create_outdir(out_dir: str):
    """清理并创建输出目录"""
    if os.path.exists(out_dir):
        try:
            shutil.rmtree(out_dir)
        except Exception:
            pass
    os.makedirs(out_dir, exist_ok=True)
# -----------------------------------------


# --- 重写：核心破解函数，增加 AES 支持 ---
def crack_password(zip_file: str, password: str, status: dict, out_dir: str):
    """
    尝试使用指定密码破解ZIP文件（支持 AES 和 ZipCrypto）。
    """
    if status["stop"]:
        return False

    pwd_bytes = password.encode('utf-8')
    is_correct = False

    try:
        # 优先使用 pyzipper，它同时支持 AES 和传统加密
        if HAS_PYZIPPER:
            with pyzipper.AESZipFile(zip_file, 'r') as zf:
                first_file = _find_first_file_in_zip(zf)
                if first_file:
                    # 通过读取第一个文件来验证密码，这是最可靠的方法
                    zf.read(first_file, pwd=pwd_bytes)
                else: # 如果压缩包为空或只有目录，则使用 testzip
                    zf.testzip(pwd=pwd_bytes)
                is_correct = True
        # 如果没有 pyzipper，回退到标准库（仅支持传统加密）
        else:
            with zipfile.ZipFile(zip_file, 'r') as zf:
                first_file = _find_first_file_in_zip(zf)
                if first_file:
                    zf.read(first_file, pwd=pwd_bytes)
                else:
                    zf.testzip(pwd=pwd_bytes)
                is_correct = True

    # 密码错误会引发 RuntimeError
    except RuntimeError:
        is_correct = False
    # 其他可能的异常
    except (zipfile.BadZipFile, Exception):
        is_correct = False

    if is_correct:
        with status["lock"]:
            if status["stop"]: return # 双重检查，避免多个线程同时成功
            status["stop"] = True

        print(f'\n\n[+] 恭喜您！密码破解成功, 该压缩包的密码为：{password}')
        
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
                print(f"\n[*] 系统已为您自动提取出 {len(filenames)} 个文件到 '{out_dir}' 文件夹中: {filenames}")
        except Exception as e:
            print(f"\n[!] 密码正确，但解压文件时发生错误: {e}")

        os._exit(0) # 强制终止所有线程
    else:
        with status["lock"]:
            status["tried_passwords"].append(password)
        return False

# -----------------------------------------

def generate_numeric_dict():
    """
    生成一个包含1到6位纯数字的字典
    """
    numeric_dict = []
    for length in range(1, 7):  # 1-6位
        for num in its.product(string.digits, repeat=length):
            numeric_dict.append(''.join(num))
    return numeric_dict, len(numeric_dict)


def display_progress(status, start_time):
    """
    实时显示破解进度
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
            print(f"\r[-] 当前破解进度：{progress:.2f}%，剩余时间：{remaining_time_str}，"
                  f"当前时速：{avg_cracked}个/s，正在尝试密码:{current_password:<20}",
                  end="", flush=True)


def adjust_thread_count(max_limit=128):
    """
    动态调整线程数
    """
    try:
        cpu_count = multiprocessing.cpu_count()
        max_threads = min(max_limit, cpu_count * 4)
    except NotImplementedError:
        max_threads = 16 # 默认值
    return max_threads


def count_passwords(file_path):
    """
    统计字典文件中的总密码数量
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except Exception as e:
        print(f"[!] 加载字典文件失败，原因：{e}")
        exit(0)


def load_passwords_in_chunks(file_path, chunk_size=1000000):
    """
    分块加载密码以节省内存
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
        print(f"[!] 加载字典文件失败，原因：{e}")
        exit(0)


def parse_mask(mask):
    """
    解析掩码字符串，返回字符集列表和总组合数。(已修复 Bug 版本)
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
                    charsets.append('?')  # 代表一个真实的问号
                else:
                    # 对于未定义的占位符如 ?a, ?b 等，将其作为普通字符串 "?a" 对待
                    charsets.append(mask[i:i+2])
                i += 2
            else:  # 末尾的 '?'
                charsets.append('?')
                i += 1
        else:
            # 普通字符
            charsets.append(char)
            i += 1
            
    # 从解析出的字符集列表重新计算总组合数，更加健壮
    total_combinations = 1
    for charset in charsets:
        # 任何非 0 长度的字符集都会被正确计算
        if len(charset) > 0:
            total_combinations *= len(charset)
            
    # 防止因空掩码或无效掩码导致总数为0，从而引发除零错误
    if total_combinations == 0:
        total_combinations = 1

    return charsets, total_combinations


def crack_password_with_mask(zip_file, mask, status, out_dir):
    """
    使用掩码攻击执行爆破。
    """
    charsets, total_passwords = parse_mask(mask)
    if total_passwords > 100_000_000_000:
        choice = input(f"[!]警告：掩码 '{mask}' 将生成 {total_passwords:,} 种组合，可能需要极长时间。是否继续？ (y/n): ")
        if choice.lower() != 'y':
            print("[-] 用户已中止攻击。")
            return

    print(f"\n[+] 开始使用掩码 '{mask}' 进行攻击。")
    print(f"[+] 需要尝试的密码总数组合为: {total_passwords:,}")
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = []

    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] 动态调整线程数为: {max_threads}个")

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
             print('\n[-] 非常抱歉，掩码生成的所有密码均已尝试，请检查您的掩码或尝试其他方法！')


def crack_password_with_file_or_dir(zip_file, dict_file_or_dir, status, out_dir):
    """
    递归地处理文件或目录中的所有字典文件
    """
    if os.path.isdir(dict_file_or_dir):
        for filename in sorted(os.listdir(dict_file_or_dir)):
            if status["stop"]: return
            file_path = os.path.join(dict_file_or_dir, filename)
            crack_password_with_file_or_dir(zip_file, file_path, status, out_dir)
    elif os.path.isfile(dict_file_or_dir):
        dict_type = "用户自定义字典" if dict_file_or_dir != 'password_list.txt' else "内置字典"
        crack_password_with_file(zip_file, dict_file_or_dir, status, dict_type, out_dir)


def crack_with_generated_numeric_dict(zip_file, status, out_dir):
    """
    使用生成的1-6位纯数字字典进行暴力破解
    """
    print("\n[-] 内置字典破解失败或未找到，开始尝试1-6位纯数字字典...")
    numeric_dict, total_passwords = generate_numeric_dict()
    print(f'\n[+] 加载1-6位纯数字字典成功！总密码数: {total_passwords}')
    
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = []
    
    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] 动态调整线程数为: {max_threads}个")

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
            print('\n[-] 非常抱歉，1-6位纯数字字典中的所有密码均已尝试完毕。')


def crack_password_with_file(zip_file, dict_file, status, dict_type, out_dir):
    """
    使用指定字典文件进行暴力破解
    """
    total_passwords = count_passwords(dict_file)
    print(f"\n[+] 加载{dict_type}[{dict_file}]成功！")
    print(f"[+] 当前字典总密码数: {total_passwords}")
    
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = []

    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+] 动态调整线程数为: {max_threads}个")

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
            print(f'\n[-] 非常抱歉，字典 {dict_file} 中的所有密码均已尝试完毕。')


if __name__ == '__main__':
    try:
        print(r"""                          
     ______          ____                _   [*]Hx0战队      
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \  | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|   
           |_| |_____|                                 
    #Coded By Asaotomo         Update:2025.09.12 (AES Support)
            """)
        
        # --- 参数解析部分保持不变 ---
        if len(sys.argv) < 2:
            print("\n--- 字典攻击 ---")
            print(f"[*] 用法1(内置序列): python {sys.argv[0]} YourZipFile.zip")
            print("         └─ 默认顺序: 先尝试 password_list.txt 文件, 再尝试1-6位纯数字。")
            print(f"[*] 用法2(自定义字典): python {sys.argv[0]} YourZipFile.zip YourDict.txt")
            print(f"[*] 用法3(字典目录):   python {sys.argv[0]} YourZipFile.zip YourDictDirectory")
            print("\n--- 掩码攻击 ---")
            print(f"[*] 用法4(掩码):      python {sys.argv[0]} YourZipFile.zip -m 'your?dmask?l'")
            print("[*]  ?d: 数字, ?l: 小写字母, ?u: 大写字母, ?s: 特殊符号, ??: 问号自身")
            print("\n--- 可选参数 ---")
            print(f"[*] 用法5(指定输出):  python {sys.argv[0]} ... -o YourOutDir")
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
                    print("[!] 错误: -o 参数后未提供目录名。")
                    os._exit(1)
            elif sys.argv[i] in ['-m', '--mask']:
                if i + 1 < len(sys.argv):
                    dict_path_or_mask_flag = '-m'
                    mask_value = sys.argv[i+1]
                    i += 2
                else:
                    print("[!] 错误: -m 参数后未提供掩码字符串。")
                    os._exit(1)
            else:
                if dict_path_or_mask_flag is None:
                    dict_path_or_mask_flag = sys.argv[i]
                i += 1

        if not os.path.exists(zip_file):
            print(f"[!]错误: 文件 '{zip_file}' 未找到。")
            os._exit(1)

        if HAS_PYZIPPER:
            print("[+] 检测到您的系统已安装 pyzipper 库，自动开启 AES 加密破解支持。")
        else:
            print("[*] 检测到您的系统未安装 pyzipper 库，因此 AES 加密的 ZIP 可能无法正常解密。若需进行解密，建议安装该库: pip3 install pyzipper")
        
        # --- 这里是再次修正后的伪加密处理逻辑 ---
        is_truly_encrypted = False
        if is_zip_encrypted(zip_file):
            print(f'[!] 系统检测到 {zip_file} 的加密标志位已开启，正在尝试进行伪加密修复...')
            fixed_zip_name = file_path = zip_file + ".fixed.tmp"
            try:
                # 将可能出错的修复函数调用移入 try 块
                fix_zip_encrypted(zip_file, fixed_zip_name)
                
                with zipfile.ZipFile(fixed_zip_name) as fixed_zf:
                    fixed_zf.testzip()
                
                print(f"[*] 伪加密修复成功！文件 '{zip_file}' 无需密码。")
                _clean_and_create_outdir(out_dir)
                with zipfile.ZipFile(fixed_zip_name) as fixed_zf:
                    fixed_zf.extractall(path=out_dir)
                    filenames = fixed_zf.namelist()
                    print(f"[*] 系统已为您自动提取出 {len(filenames)} 个文件到 '{out_dir}' 文件夹中: {filenames}")
                os.remove(fixed_zip_name)
                os._exit(0)

            except Exception:
                is_truly_encrypted = True
                print(f'[+] 修复尝试失败，该文件为真加密，准备进行暴力破解。')
                if os.path.exists(fixed_zip_name):
                    os.remove(fixed_zip_name)
        
        if not is_zip_encrypted(zip_file):
             print(f'[!] 系统检测到 {zip_file} 不是一个加密的ZIP文件，您可以直接解压！')
             os._exit(0)
        
        # 只有真加密文件才能进入后续爆破流程
        if is_truly_encrypted:
            print(f'[+] 开始对真加密文件进行破解...')
            try:
                with zipfile.ZipFile(zip_file) as zf:
                    get_crc(zip_file, zf)
            except zipfile.BadZipFile:
                print(f"[!] '{zip_file}' 可能不是一个有效的 ZIP 文件或已损坏。")
                os._exit(1)
            
            status = { "stop": False, "tried_passwords": [], "lock": threading.Lock(), "total_passwords": 0 }

            if dict_path_or_mask_flag == '-m':
                crack_password_with_mask(zip_file, mask_value, status, out_dir)
            else:
                print(f"[+] 系统开始进行字典暴力破解······")
                if dict_path_or_mask_flag:
                    crack_password_with_file_or_dir(zip_file, dict_path_or_mask_flag, status, out_dir)
                else:
                    if os.path.exists('password_list.txt'):
                        crack_password_with_file(zip_file, 'password_list.txt', status, "内置字典", out_dir)
                    else:
                        print("[!] 未找到内置字典 password_list.txt，将直接尝试纯数字字典。")
                    if not status["stop"]:
                        crack_with_generated_numeric_dict(zip_file, status, out_dir)

    except FileNotFoundError:
        print(f"[!] 错误: 文件 '{sys.argv[1]}' 未找到。")
    except Exception as e:
        print(f'\n[!] 发生未知错误: {e}')
        import traceback
        traceback.print_exc()
