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
    except:
        os.remove(fix_zip_name)
        shutil.move(temp_path, fix_zip_name)
    return fix_zip_name


def get_crc(zip_file, fz):
    """
    计算文件crc值
    """
    key = 0
    for filename in fz.namelist():
        if filename.endswith('/'):  # skip directories
            continue
        getSize = fz.getinfo(filename).file_size
        if getSize <= 6:
            sw = input(
                f'[!]系统监测到压缩包 {zip_file} 中的 {filename} 文件大小为{getSize}字节，是否尝试通过CRC32碰撞的方式直接爆破该文件内容？（y/n）')
            if sw in ['y', 'Y']:
                getCrc = fz.getinfo(filename).CRC
                print(f'[+]{filename} 文件的CRC值为：{getCrc}')
                crack_crc(filename, getCrc, getSize)
                key += 1
    if key >= len([name for name in fz.namelist() if not name.endswith('/')]):  # only count files, not directories
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
        zf = zipfile.ZipFile(zip_file)
        zf.setpassword(password.encode())
        zf.testzip()
        zf.extractall()
        print(f'\n[*]恭喜您！密码破解成功,该压缩包的密码为：{password}')
        filenames = zf.namelist()
        print(f"[*]系统已为您自动提取出{len(filenames)}个文件：{filenames}")
        status["stop"] = True
        os._exit(0)
    except:
        with status["lock"]:
            status["tried_passwords"].append(password)
    return False


def generate_numeric_dict():
    """
    生成一个包含0到6位纯数字的字典
    """
    numeric_dict = []
    for length in range(1, 7):  # 0-6位
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
            total_passwords = status["total_passwords"]  # 从 status 中获取实时值
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
    分块加载密码
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


def crack_password_with_chunks(zip_file, numeric_dict, dict_file, status):
    """
    使用分块加载字典进行暴力破解
    """
    success = False
    start_time = time.time()

    max_threads = adjust_thread_count()
    print(f"[+]动态调整线程数为：{max_threads}个")

    display_thread = threading.Thread(target=display_progress, args=(status, start_time))
    display_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            for chunk in load_passwords_in_chunks(dict_file):
                future_to_password = {executor.submit(crack_password, zip_file, password, status): password for password
                                      in chunk}
                for future in as_completed(future_to_password):
                    if future.result():
                        success = True
                        status["stop"] = True
                        break
                if success:
                    break
            if numeric_dict != []:
                future_to_password = {executor.submit(crack_password, zip_file, password, status): password for password
                                      in numeric_dict}
                for future in as_completed(future_to_password):
                    if future.result():
                        success = True
                        status["stop"] = True
                        break
    finally:
        status["stop"] = True
        display_thread.join()

    if not success:
        print('\n[-]非常抱歉，字典中的所有密码均已尝试，请尝试其他字典或使用更高级的破解方法！')


if __name__ == '__main__':
    try:
        print("""                          
     ______          ____                _   [*]Hx0战队      
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \  | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|   
           |_| |_____|                                 
    #Coded By Asaotomo               Update:2025.01.17
            """)
        if len(sys.argv) == 1:
            print(
                "[*]用法1(内置字典):Python3 ZipCracker.py YourZipFile.zip \n[*]用法2(自定义字典):Python3 ZipCracker.py  YourZipFile.zip  YourDict.txt")
            os._exit(0)
        zip_file = sys.argv[1]
        if is_zip_encrypted(zip_file):
            print(f'[!]系统检测到 {zip_file} 是一个加密的ZIP文件')
            zf = zipfile.ZipFile(zip_file)
            try:
                fixed_zip_name = fix_zip_encrypted(zip_file)
                zf = zipfile.ZipFile(fixed_zip_name)
                zf.testzip()
                zf.extractall(path=os.path.dirname(fixed_zip_name))
                filenames = zf.namelist()
                print(
                    f"[*]压缩包 {zip_file} 为伪加密，系统已为您生成修复后的压缩包({fixed_zip_name})，并自动提取出{len(filenames)}个文件：{filenames}")
                os._exit(0)
            except Exception as e:
                os.remove(zip_file + ".tmp")
                zf = zipfile.ZipFile(zip_file)
                print(f'[+]压缩包 {zip_file} 不是伪加密，准备尝试暴力破解')
                # crc32碰撞
                get_crc(zip_file, zf)
                # 破解加密的zip文件
                if len(sys.argv) > 2:  # 检查是否指定了自定义字典文件
                    dict_file = sys.argv[2]
                    dict_type = "用户自定义字典"
                    numeric_dict_num = 0
                    numeric_dict = []
                else:
                    dict_file = 'password_list.txt'
                    dict_type = "系统内置字典"
                    print(f'[+]加载0-6位纯数字字典成功！')
                    numeric_dict, numeric_dict_num = generate_numeric_dict()
                total_passwords = count_passwords(dict_file) + numeric_dict_num  # 统计总密码数
                print(f"[+]加载{dict_type}[{dict_file}]成功！")
                print(f"[+]当前爆破字典总数:{total_passwords}个")

                status = {
                    "stop": False,
                    "tried_passwords": [],
                    "lock": threading.Lock(),
                    "total_passwords": total_passwords  # 初始化总密码数
                }

                print(f"[+]系统开始进行暴力破解······")
                crack_password_with_chunks(zip_file, numeric_dict, dict_file, status)
        else:
            print(f'[!]系统检测到 {zip_file} 不是一个加密的ZIP文件，您可以直接解压！')
    except Exception as e:
        print(f'[!]发生错误：{e}')
