# -*- coding: utf-8 -*-
# @Author  : Li Kun
# @Time    : 2024/5/14 15:17
# @File    : gen_secret.py

# EPService获取软件版本信息需要使用个人账号和密码
# 需要自己配置本机登陆账号密码生成密钥文件

import os
import sys
import json
from cryptography.fernet import Fernet

if getattr(sys, 'frozen', False):
    __current_dir = os.path.normpath(os.path.dirname(sys.executable))
else:
    __current_dir = os.path.normpath(os.path.dirname(__file__))

secret_keyfile = os.path.join(__current_dir, 'secret.key')
password_file = os.path.join(__current_dir, 'password.enc')


def gen_key(profile_json):
    """
    把用户名密码加密到本地
    Args:
        profile_json:
            username: str
            password: str
    Returns:

    """
    # 生成一个密钥
    key = Fernet.generate_key()

    # 将密钥保存到文件
    with open(secret_keyfile, 'wb') as key_file:
        key_file.write(key)

    # 加载先前保存的密钥
    with open(secret_keyfile, 'rb') as key_file:
        key = key_file.read()

    # 创建Fernet对象
    cipher_suite = Fernet(key)

    # 需要加密的密码
    password = profile_json

    # 将密码转换为二进制，然后加密
    cipher_text = cipher_suite.encrypt(password.encode())

    # 将加密后的密码保存到文件
    with open(password_file, 'wb') as encrypted_password_file:
        encrypted_password_file.write(cipher_text)


def get_profile():
    # 加载密钥
    with open(secret_keyfile, 'rb') as key_file:
        key = key_file.read()

    # 创建Fernet对象
    cipher_suite = Fernet(key)

    # 读取加密的密码
    with open(password_file, 'rb') as encrypted_password_file:
        cipher_text = encrypted_password_file.read()

    # 解密密码
    profile = cipher_suite.decrypt(cipher_text).decode()

    return profile


if __name__ == '__main__':
    gen_key(json.dumps({'username': 'admin', 'password': 'admin'}))
    print(get_profile())
