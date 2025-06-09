# -*- coding: utf-8 -*-
# @Author  : Li Kun
# @Time    : 2023/5/23 16:36
# @File    : stars_client.py

import os
import json
import time
import sys
import datetime
import traceback
import threading
import requests
import socket
import subprocess
import psutil
from loguru import logger
from urllib.parse import urljoin

CONN_TIMEOUT = 120  # socket超时

from vv_application_update_tool.update_sentinel import UpdateSentinel, UPDATE_AT_ANYTIME
u = UpdateSentinel("stars-client", [], update_trigger_at=UPDATE_AT_ANYTIME, skip=True)  #, server='http://localhost:13607')


def read_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        res = json.load(f)
        return res


def get_host_ip():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
        except OSError:
            # 电脑刚开机时可能向一个无法连接的网络尝试了一个套接字操作
            time.sleep(1)
        except Exception as e:
            logger.info(e)
            time.sleep(1)
        else:
            s.close()
            return ip_address


def update_remote_ipaddress(remote_host):
    while True:
        try:
            host_name = socket.gethostname()
        except Exception as e:
            time.sleep(1)
            logger.error(e)
        else:
            break
    ip_address = get_host_ip()
    if ip_address:
        # ip_address = "172.31.10.110"
        try:
            cnt = 1
            data = None
            while cnt <= 5:
                try:
                    url = urljoin(remote_host, f'/machine/getinfo?hostName={host_name}')
                    data = requests.request('Get', url).json()['data']
                except Exception as e:
                    # 有可能客户端启动时，电脑还没联网，无法更新数据
                    logger.error(e)
                    time.sleep(3)
                    cnt += 1
                else:
                    break
            if data:
                for i in data:
                    id = i['id']
                    update_url = urljoin(remote_host, f'/machine/updateinfo')
                    update_json = {'id': id, 'upper_address': ip_address}
                    resp_json = requests.request('Post', update_url, json=update_json).json()
                    if resp_json['code'] == 0:
                        logger.success(f'更新当前设备信息成功: id:{id}, hostName: {host_name}, ipAddress: {ip_address}')
            else:
                logger.warning(f'未查询到当前设备: hostName: {host_name}, ipAddress: {ip_address}')
        except Exception as e:
            logger.error(f'更新当前设备信息失败: {e}')
    else:
        logger.error('无法获取当前主机地址')
    return host_name, ip_address


class TCPClient(threading.Thread):
    def __init__(self, server_ip, server_port, cloud_host):
        super().__init__()
        self.server_ip = server_ip
        self.server_port = server_port
        self.cloud_host = cloud_host
        self.connect_server()

    def connect_server(self):
        # 开机状态主机IP可能会更新，这里可以及时更新IP地址
        self.hostname, self.host_ip = update_remote_ipaddress(self.cloud_host)
        while True:
            if u.done():
                break
            try:
                self.sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sk.settimeout(CONN_TIMEOUT)
                self.sk.connect((self.server_ip, self.server_port))
            except Exception as e:
                logger.error(f'Unable to connect to remote server {self.server_ip}:{self.server_port} <reason: {e}>')
                time.sleep(2)
            else:
                logger.success('connect success')
                break

    def run(self) -> None:
        while True:
            if u.done():
                logger.info("发现新包, 监控退出准备更新.")
                return
            try:
                # 接收服务端消息
                data = self.sk.recv(1024)
                if data == b'heartbeat':  # 常规心跳
                    self.sk.sendall(b'heartbeat ack')
                elif data == b'isAlive':  # 服务端检查连接是否已经有效
                    self.sk.sendall(b'isAlive ack')
                elif data == b'forbid':   # 重复连接，被服务端禁掉，客户端退出
                    logger.info('reconnect, server connect be prohibited')
                    self.sk.sendall(b'')
                    self.sk.close()
                    logger.info('connect close')
                    break
            # 这里是客户端断网或服务端重启、连接中断等场景
            except OSError as e:
                logger.error(f'与服务器连接异常 尝试重连... {e}')
                logger.error(traceback.format_exc())
                # 避免在一个已经连接的套接字上做了一个连接请求
                self.sk.close()
                # 给服务端处理连接丢失的时间
                time.sleep(5)
                # 只要服务器不挂就能连上
                self.connect_server()
            except:
                logger.error(traceback.format_exc())

        # 星辰掉线就告警
        try:
            url = "https://iot-openapi-ontest-b.chehejia.com/vvrobot/hook/messages?receive_id_type=chat_id"
            payload = json.dumps({
                "receive_id": "oc_5674bdae634b6797697d1d8792c80016",
                "msg_type": "text",
                "content": "{\"text\":\"星辰客户端<%s, %s>退出, 原因: 重复连接\"}" % (self.hostname, self.host_ip)
            })
            headers = {
                'Content-Type': 'application/json'
            }
            response = requests.request("POST", url, headers=headers, data=payload)
            logger.info(response.text)
        except:
            logger.error(traceback.format_exc())


if __name__ == '__main__':
    if getattr(sys, 'frozen', False):
        work_dir = os.path.normpath(os.path.dirname(sys.executable))
    else:
        work_dir = os.path.normpath(os.path.dirname(__file__))
    logger.add(os.path.join(work_dir, 'log', 'client_console_{time}.log'), rotation='24h')
    config_json = read_json_file(os.path.join(work_dir, 'stars_client.json'))
    server_ip, server_port, cloud_host = config_json['serverAddress'], config_json['serverPort'], config_json[
        'cloudHost']
    TCPClient(server_ip, server_port, cloud_host).start()

    # update_remote_ipaddress(config_json['cloudHost'])
