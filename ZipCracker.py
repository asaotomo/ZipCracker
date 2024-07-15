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
    fix_zip_name = "fix_" + file_path
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
        print(f'\n[*]恭喜您！密码破解成功,该压缩包的密码为：{password}')
        success = True
        filenames = zf.namelist()
        print(f"[*]系统已为您自动提取出{len(filenames)}个文件：{filenames}")
        status["stop"] = True
        os._exit(0)
    except:
        with status["lock"]:
            status["tried_passwords"].append(password)
    return False


def get_crc(zip_file, fz):
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
    dic = its.product(string.printable, repeat=size)
    print(f"[+]系统开始进行CRC32碰撞破解······")
    for s in dic:
        s = ''.join(s).encode()
        if crc == (binascii.crc32(s)):
            print(f'[*]恭喜您，破解成功！\n[*]{filename} 文件的内容为：' + str(s.decode()))
            break


def display_progress(status, total_passwords, start_time):
    while not status["stop"]:
        time.sleep(0.0167)  # 每0.0167秒更新一次进度
        with status["lock"]:
            passwords_cracked = len(status["tried_passwords"])
            current_time = time.time()
            elapsed_time = current_time - start_time
            avg_cracked = int(passwords_cracked / elapsed_time) if elapsed_time > 0 else 0
            remaining_time = (total_passwords - passwords_cracked) / avg_cracked if avg_cracked > 0 else 0
            remaining_time_str = time.strftime('%H:%M:%S', time.gmtime(remaining_time))
            print("\r[-]当前破解进度：{:.2f}%，剩余时间：{}，当前时速：{}个/s，正在尝试密码:{:<20}".format(
                passwords_cracked / total_passwords * 100,
                remaining_time_str,
                avg_cracked,
                status["tried_passwords"][-1] if passwords_cracked > 0 else ""),
                end="", flush=True)


def adjust_thread_count():
    cpu_count = multiprocessing.cpu_count()
    return cpu_count * 2  # 使用逻辑CPU数量的两倍作为线程数


if __name__ == '__main__':
    try:
        print("""                          
     ______          ____                _   [*]Hx0战队      
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \  | |   | '__/ _` |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|   
           |_| |_____|                                 
    #Coded By Asaotomo               Update:2024.06.13
            """)
        if len(sys.argv) == 1:
            print(
                "[*]用法1(内置字典):Python3 Hx0_Zip_Cracker.py YourZipFile.zip \n[*]用法2(自定义字典):Python3 Hx0_Zip_Cracker.py  YourZipFile.zip  YourDict.txt")
            os._exit(0)
        zip_file = sys.argv[1]
        if is_zip_encrypted(zip_file):
            print(f'[!]系统检测到 {zip_file} 是一个加密的ZIP文件')
            zf = zipfile.ZipFile(zip_file)
            try:
                fix_zip_name = fix_zip_encrypted(zip_file)
                zf = zipfile.ZipFile(fix_zip_name)
                zf.testzip()
                zf.extractall()
                filenames = zf.namelist()
                print(
                    f"[*]压缩包 {zip_file} 为伪加密，系统已为您生成修复后的压缩包({fix_zip_name})，并自动提取出{len(filenames)}个文件：{filenames}")
                os._exit(0)
            except Exception as e:
                zf = zipfile.ZipFile(zip_file)
                print(f'[+]压缩包 {zip_file} 不是伪加密，准备尝试暴力破解')
                # crc32碰撞
                get_crc(zip_file, zf)
                # 破解加密的zip文件
                password_list = []
                if len(sys.argv) > 2:  # 检查是否指定了自定义字典文件
                    dict_file = sys.argv[2]
                    dict_type = "用户自定义字典"
                else:
                    dict_file = 'password_list.txt'
                    dict_type = "系统内置字典"
                try:
                    with open(dict_file, 'r') as f:
                        password_list += [line.strip() for line in f.readlines()]
                    print(f'[+]加载{dict_type}[{dict_file}]成功！')
                except Exception as e:
                    print(f'[!]加载{dict_type}失败！，原因：{e}')
                    exit(0)
                for length in range(1, 7):
                    password_list += [f'{i:0{length}d}' for i in range(10 ** length)]
                print(f'[+]加载0-6位纯数字字典成功！')
                password_list = list(OrderedDict.fromkeys(password_list))
                total_passwords = len(password_list)
                print(f"[+]当前爆破字典总数:{total_passwords}个")
                print(f"[+]系统开始进行暴力破解······")
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
                print(f"[+]动态调整线程数为：{max_threads}个")

                # 控制虚拟内存的占用
                threading.stack_size(65536)
                with ThreadPoolExecutor(max_workers=max_threads) as executor:  # 动态设置最大线程数
                    future_to_password = {executor.submit(crack_password, zip_file, password, status): password for
                                          password in password_list}
                    for future in as_completed(future_to_password):
                        if future.result():
                            success = True
                            break

                status["stop"] = True
                display_thread.join()

                if not success:
                    print('\n[-]非常抱歉，字典中的所有密码均已尝试，请尝试其他字典或使用更高级的破解方法！')
    except Exception as e:
        print(f'[!]发生错误：{e}')
