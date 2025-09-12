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


# --- 为掩码攻击功能新增的字符集定义 ---
CHARSET_DIGITS = string.digits
CHARSET_LOWER = string.ascii_lowercase
CHARSET_UPPER = string.ascii_uppercase
CHARSET_SYMBOLS = string.punctuation
# ------------------------------------

def is_zip_encrypted(file_path):
    """
    检查zip文件是否存在伪加密
    """
    with zipfile.ZipFile(file_path) as zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                return True
    return False


def fix_zip_encrypted(file_path):
    """
    修复伪加密的zip文件
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
    except Exception:
        os.remove(fix_zip_name)
        shutil.move(temp_path, fix_zip_name)
    return fix_zip_name


def get_crc(zip_file, fz):
    """
    计算文件crc值
    """
    key = 0
    for filename in fz.namelist():
        if filename.endswith('/'):  # 跳过目录
            continue
        getSize = fz.getinfo(filename).file_size
        if getSize <= 6:
            sw = input(
                f'[!]系统监测到压缩包 {zip_file} 中的 {filename} 文件大小为{getSize}字节，是否尝试通过CRC32碰撞的方式直接爆破该文件内容？（y/n）')
            if sw.lower() == 'y':
                getCrc = fz.getinfo(filename).CRC
                print(f'[+]{filename} 文件的CRC值为：{getCrc}')
                crack_crc(filename, getCrc, getSize)
                key += 1
    if key >= len([name for name in fz.namelist() if not name.endswith('/')]):  # 只计算文件
        print(f'[*]系统检测到 {zip_file} 中的所有文件均已通过CRC32碰撞破解完成，将不再使用字典进行暴力破解！')
        exit()


def crack_crc(filename, crc, size):
    """
    根据crc值进行碰撞
    """
    dic = its.product(string.printable, repeat=size)
    print(f"[+]系统开始进行CRC32碰撞破解······")
    for s in dic:
        s = ''.join(s).encode()
        if crc == (binascii.crc32(s)):
            print(f'[*]恭喜您，破解成功！\n[*]{filename} 文件的内容为：' + str(s.decode()))
            break


def crack_password(zip_file, password, status):
    """
    尝试使用指定密码破解ZIP文件
    """
    if status["stop"]:
        return False
    try:
        with zipfile.ZipFile(zip_file) as zf:
            zf.setpassword(password.encode())
            zf.testzip()
            zf.extractall()
            print(f'\n[*]恭喜您！密码破解成功,该压缩包的密码为：{password}')
            filenames = zf.namelist()
            print(f"[*]系统已为您自动提取出{len(filenames)}个文件：{filenames}")
            status["stop"] = True
            os._exit(0)
    except Exception:
        with status["lock"]:
            status["tried_passwords"].append(password)
    return False


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
        time.sleep(0.0835)  # 每0.0835秒更新一次进度
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
            print("\r[-]当前破解进度：{:.2f}%，剩余时间：{}，当前时速：{}个/s，正在尝试密码:{:<20}".format(
                progress, remaining_time_str, avg_cracked, current_password),
                end="", flush=True)


def adjust_thread_count(max_limit=128):
    """
    动态调整线程数
    """
    cpu_count = multiprocessing.cpu_count()
    max_threads = min(max_limit, cpu_count * 4)  # 使用逻辑CPU数的4倍作为线程数，但不超过最大限制
    return max_threads


def count_passwords(file_path):
    """
    统计字典文件中的总密码数量
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except Exception as e:
        print(f"[!]加载字典文件失败，原因：{e}")
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
        print(f"[!]加载字典文件失败，原因：{e}")
        exit(0)

# --- 新增功能：掩码攻击 (Mask Attack) ---

def parse_mask(mask):
    """
    解析掩码字符串，返回字符集列表和总组合数。
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
                    charsets.append('?') # 代表一个真实的问号
                else:
                    # 未知占位符，当作普通字符处理
                    charsets.append(mask[i:i+2])
                i += 2
            else: # 末尾的 '?'
                charsets.append('?')
                i += 1
        else:
            charsets.append(mask[i])
            i += 1
    return charsets, total_combinations


def crack_password_with_mask(zip_file, mask, status):
    """
    使用掩码攻击执行爆破。
    """
    charsets, total_passwords = parse_mask(mask)
    if total_passwords > 100_000_000_000: # 超过一千亿种组合，提醒用户
        choice = input(f"[!]警告：掩码 '{mask}' 将生成 {total_passwords:,} 种组合，可能需要极长时间。是否继续？ (y/n): ")
        if choice.lower() != 'y':
            print("[-]用户已中止攻击。")
            return

    print(f"\n[+]开始使用掩码 '{mask}' 进行攻击。")
    print(f"[+]需要尝试的密码总数组合为: {total_passwords:,}")
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = [] # 重置计数器

    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+]动态调整线程数为: {max_threads}个")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            password_generator = (''.join(p) for p in its.product(*charsets))
            
            while not status["stop"]:
                chunk = list(its.islice(password_generator, 100000))
                if not chunk:
                    break
                
                future_to_password = {executor.submit(crack_password, zip_file, password, status): password for password in chunk}
                for future in as_completed(future_to_password):
                    if future.result() or status["stop"]:
                        status["stop"] = True
                        break
                if status["stop"]:
                    break

    finally:
        status["stop"] = True
        display_thread.join()

    if "Success!" not in status:
         print('\n[-]非常抱歉，掩码生成的所有密码均已尝试，请检查您的掩码或尝试其他方法！')

# --- 字典攻击相关函数 ---

def crack_password_with_file_or_dir(zip_file, dict_file_or_dir, status):
    """
    递归地处理文件或目录中的所有字典文件
    """
    if os.path.isdir(dict_file_or_dir):
        # 按文件名排序，确保破解顺序可预测
        for filename in sorted(os.listdir(dict_file_or_dir)):
            if status["stop"]: return # 如果已经破解成功，则提前退出
            file_path = os.path.join(dict_file_or_dir, filename)
            # 递归调用
            crack_password_with_file_or_dir(zip_file, file_path, status)
    elif os.path.isfile(dict_file_or_dir):
        # 确定字典类型用于显示
        dict_type = "用户自定义字典" if dict_file_or_dir != 'password_list.txt' else "内置字典"
        crack_password_with_file(zip_file, dict_file_or_dir, status, dict_type)


# <<< 新增函数: 专门用于处理1-6位纯数字字典 >>>
def crack_with_generated_numeric_dict(zip_file, status):
    """
    使用生成的1-6位纯数字字典进行暴力破解
    """
    print("\n[-]内置字典破解失败，开始尝试1-6位纯数字字典...")
    numeric_dict, total_passwords = generate_numeric_dict()
    print(f'[+]加载1-6位纯数字字典成功！总密码数: {total_passwords}')
    
    # 重置状态以进行新一轮破解
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = []
    
    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+]动态调整线程数为: {max_threads}个")

    # 为新的破解阶段重启进度显示线程
    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.start()
    
    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_password = {executor.submit(crack_password, zip_file, password, status): password for password in numeric_dict}
            for future in as_completed(future_to_password):
                if future.result() or status["stop"]:
                    status["stop"] = True
                    break
    finally:
        # 确保显示线程在函数结束时停止
        # 临时将stop设置为True，以便join可以退出
        temp_stop = status["stop"]
        status["stop"] = True
        display_thread.join()
        status["stop"] = temp_stop # 恢复状态

    if not status["stop"]:
        print('\n[-]非常抱歉，1-6位纯数字字典中的所有密码均已尝试完毕。')


# <<< 修改后的函数: 现在只负责从单个文件中加载密码 >>>
def crack_password_with_file(zip_file, dict_file, status, dict_type):
    """
    使用指定字典文件进行暴力破解
    """
    total_passwords = count_passwords(dict_file)
    print(f"\n[+]加载{dict_type}[{dict_file}]成功！")
    print(f"[+]当前字典总密码数: {total_passwords}")
    
    status["total_passwords"] = total_passwords
    status["tried_passwords"] = [] # 重置密码尝试列表和总数

    start_time = time.time()
    max_threads = adjust_thread_count()
    print(f"[+]动态调整线程数为: {max_threads}个")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # 分块加载字典文件
            for chunk in load_passwords_in_chunks(dict_file):
                if status["stop"]: break
                future_to_password = {executor.submit(crack_password, zip_file, password, status): password for password in chunk}
                for future in as_completed(future_to_password):
                    if future.result() or status["stop"]:
                        status["stop"] = True
                        break
    finally:
        # 确保显示线程在函数结束时停止
        # 临时将stop设置为True，以便join可以退出
        temp_stop = status["stop"]
        status["stop"] = True
        display_thread.join()
        status["stop"] = temp_stop # 恢复状态


    if not status["stop"]:
        print(f'\n[-]非常抱歉，字典 {dict_file} 中的所有密码均已尝试完毕。')


if __name__ == '__main__':
    try:
        print("""                          
     ______          ____                _   [*]Hx0战队      
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \  | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|   
           |_| |_____|                                 
    #Coded By Asaotomo               Update:2025.08.21
            """)
        
        if len(sys.argv) < 2:
            print("\n--- 字典攻击 ---")
            print("[*]用法1(内置序列): python3 ZipCracker.py YourZipFile.zip")
            print("         └─ 默认顺序: 先尝试 password_list.txt 文件, 再尝试1-6位纯数字。")
            print("[*]用法2(自定义字典): python3 ZipCracker.py YourZipFile.zip YourDict.txt")
            print("[*]用法3(字典目录):   python3 ZipCracker.py YourZipFile.zip YourDictDirectory")
            print("\n--- 掩码攻击 ---")
            print("[*]用法4(掩码):      python3 ZipCracker.py YourZipFile.zip -m 'your?dmask?l'")
            print("[*]  ?d: 数字, ?l: 小写字母, ?u: 大写字母, ?s: 特殊符号, ??: 问号自身")
            os._exit(0)

        zip_file = sys.argv[1]
        if not os.path.exists(zip_file):
            print(f"[!]错误: 文件 '{zip_file}' 未找到。")
            os._exit(1)

        if is_zip_encrypted(zip_file):
            print(f'[!]系统检测到 {zip_file} 是一个加密的ZIP文件。')
            try:
                with zipfile.ZipFile(zip_file) as zf:
                    fixed_zip_name = fix_zip_encrypted(zip_file)
                    try:
                        with zipfile.ZipFile(fixed_zip_name) as fixed_zf:
                            fixed_zf.testzip()
                            fixed_zf.extractall(path=os.path.dirname(fixed_zip_name))
                            filenames = fixed_zf.namelist()
                            print(f"[*]压缩包 {zip_file} 为伪加密，系统已为您生成修复后的压缩包({fixed_zip_name})，并自动提取出{len(filenames)}个文件。")
                            os.remove(fixed_zip_name)
                            os._exit(0)
                    except Exception:
                        os.remove(fixed_zip_name)
                        print(f'[+]压缩包 {zip_file} 不是伪加密，准备尝试暴力破解。')
                        get_crc(zip_file, zf)
            except Exception as e:
                print(f'[+]压缩包 {zip_file} 不是伪加密，准备尝试暴力破解。')
                with zipfile.ZipFile(zip_file) as zf:
                    get_crc(zip_file, zf)

            status = {
                "stop": False,
                "tried_passwords": [],
                "lock": threading.Lock(),
                "total_passwords": 0
            }

            attack_mode = "dictionary"
            if len(sys.argv) > 2 and sys.argv[2] in ['-m', '--mask']:
                attack_mode = "mask"

            if attack_mode == "mask":
                if len(sys.argv) < 4:
                    print("[!]错误: -m 参数后未提供掩码字符串。")
                    os._exit(1)
                mask = sys.argv[3]
                crack_password_with_mask(zip_file, mask, status)
            else:
                print(f"[+]系统开始进行字典暴力破解······")
                if len(sys.argv) > 2:
                    dict_path = sys.argv[2]
                    crack_password_with_file_or_dir(zip_file, dict_path, status)
                else:
                    # <<< 修改后的默认破解逻辑 >>>
                    # 1. 尝试内置字典文件 password_list.txt
                    if os.path.exists('password_list.txt'):
                        crack_password_with_file(zip_file, 'password_list.txt', status, "内置字典")
                    else:
                        print("[!]未找到内置字典 password_list.txt，将直接尝试纯数字字典。")
                    
                    # 2. 如果没找到密码，继续尝试1-6位纯数字
                    if not status["stop"]:
                        crack_with_generated_numeric_dict(zip_file, status)

        else:
            print(f'[!]系统检测到 {zip_file} 不是一个加密的ZIP文件，您可以直接解压！')
    except FileNotFoundError:
        print(f"[!]错误: 文件 '{sys.argv[1]}' 未找到。")
    except Exception as e:
        print(f'\n[!]发生未知错误: {e}')
