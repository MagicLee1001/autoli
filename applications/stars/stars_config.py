# -*- coding: utf-8 -*-
# @Author  : Li Kun
# @Time    : 2023/12/22 16:35
# @File    : config.py

import os
import socket
from utilities.windows.win_ops import get_host_ip


# 星辰TCP服务端口
stars_tcp_port = 9699
stars_udp_port = 9699

# 星辰黑名单
blacklist = ['10.240.232.133']

# ssh连接最大尝试次数
ssh_retry_times = int(60 * 60 * 8 / 10)  # 8个小时

# 服务端检查客户端心跳周期
heartbeat_interval = 60

# 接收客户端消息最大超时时间
max_client_socket_timeout = 5

# 测试管理平台云端host
# 线下环境: http://PC-M70JEQ1A:13607
# 线上环境: https://test-manager.ontest.k8s.chj.cloud
remote_host = 'https://test-manager.ontest.k8s.chj.cloud'

# 服务端与客户端在同一机器时的DNS IP映射 本机映射
local_client_ip = ('172.31.10.110', get_host_ip())

# 一台电脑接两个XCU时，格外对172.31.20.1进行监控
extra_monitor_target = [
    {'hostname': 'PC-PF3Q5MZ1', 'device_id': 21, 'port': 8886},
]

# 阈值告警屏蔽 专项测试台架阈值经常超限
threshold_alarm_mask = [
    'SIL_XCU_02_XPP',  # 性能压测台架01
    'SIL_XCU_01_XAP'   # 性能压测台架02
]

# CPU超限告警阈值
cpu_threshold = 0.9

# 可用内存不足告警阈值
mem_available_threshold = 0.15
mem_used_threshold = 0.8

# 星辰监控台架日志备份目录
backup_logdir = os.path.join(os.path.expanduser('~'), "XCULogs")
shared_logdir = backup_logdir.replace('C:\\', f'\\\\{socket.gethostname()}\\')

# 飞书通知管理员id
admin_fs_user_id = '4d88796e'
