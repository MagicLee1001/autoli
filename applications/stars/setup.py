# -*- coding: utf-8 -*-
# @Author  : Li Kun
# @Time    : 2023/5/31 18:13
# @File    : setup.py

import os
import sys
import time
import winreg
import subprocess

if getattr(sys, 'frozen', False):
    current_dir = os.path.normpath(os.path.dirname(sys.executable))
else:
    current_dir = os.path.normpath(os.path.dirname(__file__))


def run_cmd(cmd, shell=True, capture_output=True):
    """
    run command by using subprocess,
    raise exception when error has happened
    return standard output and standard error
    Args:
        cmd:

    Returns:

    """
    cp = subprocess.run(cmd, shell=shell, capture_output=capture_output, encoding='utf-8')
    if cp.returncode != 0:
        error = f"something wrong has happened when running command [{cmd}]:{cp.stderr}"
        raise Exception(error)
    return cp.stdout, cp.stderr


def task_kill(exe_name):
    try:
        if "win" not in sys.platform:
            cmd = f"pkill {exe_name}"
        else:
            cmd = f"taskkill /f /t /im {exe_name}"
        run_cmd(cmd, shell=True, capture_output=False)
    except:
        pass


# 配置服务名和要自启动的应用程序路径
service_name = "AutoLiStars"
app_path = os.path.join(current_dir, 'start.bat')
instsrv_path = os.path.join(current_dir, 'bootstrap', 'instsrv.exe')
srvany_path = os.path.join(current_dir, 'bootstrap', 'srvany.exe')

# 安装服务
cmd = f'{instsrv_path} {service_name} {srvany_path}'
output = os.popen(cmd)
print(output.read())

# 定义要删除的注册表项路径
keypath = "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters" % service_name
print('注册表路径: ', keypath)
try:
    # 打开指定路径下的注册表项
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, keypath, 0, winreg.KEY_ALL_ACCESS)
    # 删除指定的注册表项
    winreg.DeleteKey(key, "")
    print("成功删除现有注册表项")
except FileNotFoundError:
    print("找不到指定的注册表项")
except PermissionError:
    print("没有权限删除注册表项")
except Exception as e:
    print("删除注册表项时出现错误:", str(e))
else:
    key.Close()

# 创建注册表项
key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, keypath)
winreg.SetValueEx(key, "Application", 0, winreg.REG_SZ, app_path)
winreg.SetValueEx(key, "AppDirectory", 0, winreg.REG_SZ, os.path.dirname(app_path))
key.Close()
print("配置成功！")

# 杀死现有的进程
task_kill('stars_client.exe')
task_kill('forward_ports.exe')
time.sleep(2)

# 后台启动星辰服务
output = os.popen(app_path)
print('星辰服务启动成功')

s = input('按任意键退出')
