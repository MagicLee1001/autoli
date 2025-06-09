# -*- coding: utf-8 -*-
# @Author  : Li Kun
# @Time    : 2023/5/23 16:35
# @File    : stars_server.py

import json
import os.path
import time
import traceback
import threading
import socket
from common.http_interface.api_coa import CustomCOAClient
from applications.stars.monitor import SSH_CONN_EXIT_SIGNAL, connections_obj, connections, connection_info, connection_sw_info
from applications.stars.monitor.performance import PerformanceMonitorThread, perf_online
from applications.stars.monitor.process import ProcessMonitorThread
from applications.stars.monitor.file import start_logs_check
from utilities.time_utils.time_ops import TimeOperation
from common.log import logger as logger
from applications.stars.stars_config import (
    stars_tcp_port, blacklist, ssh_retry_times, heartbeat_interval, max_client_socket_timeout,
    remote_host, local_client_ip, backup_logdir
)

# 以下路径是为了应付告警信息过长的情况，默认存储在用户主目录的 XCU_LOGS 文件夹下，需要开发和部署人员将该目录在局域网共享
logger.warning(f"在运行之前请务必保证已经将 {backup_logdir} 文件夹在局域网中共享")
try:
    if not os.path.isdir(backup_logdir):
        os.makedirs(backup_logdir)
except Exception as e:
    logger.error(f"创建 {backup_logdir} 失败: {e}")


# 线程锁
_lock = threading.Lock()

# 员工门户
try:
    coa = CustomCOAClient()
except:
    logger.error('COA instance create fail')
    coa = None


class MonitorThread(threading.Thread):
    """
    来一个客户端连接就起一个监控线程
    """

    def __init__(self, conn, addr):
        super().__init__()
        self.conn = conn
        self.conn.settimeout(max_client_socket_timeout)
        self.addr = addr
        self.device_id = ''
        self.rack_name = ''
        self.principal_name = ''
        self.device_desc = ''
        self.host_name = ''
        self.feishu_user_id = ''

    def run(self) -> None:
        """执行监控"""
        logger.info(f'开始监控 {self.addr} ...')
        ip_addr = self.addr[0]

        # 本地客户端ip可能被其他dns解析，这里转换下dns8.8.8.8解析后的ip
        ip_addr = local_client_ip[1] if ip_addr == local_client_ip[0] else ip_addr

        # 获取客户端所在上位机的设备信息
        device_info = coa.get_device_owner_info(remote_host, ip_addr=ip_addr)
        self.device_id, self.rack_name, self.principal_name, self.device_desc, \
            self.host_name, self.feishu_user_id = device_info
        conn_info_list = []
        conn_info_list.extend(device_info)
        # 添加客户端连接时间
        conn_info_list.append(TimeOperation.get_datetime_string())
        # 存储客户端连接信息
        connection_info[ip_addr] = conn_info_list
        # 设置该ip下所有ssh创建连接的flag
        SSH_CONN_EXIT_SIGNAL[self.conn] = 0

        # 所有监控线程的退出信号
        exit_event = threading.Event()
        # 开始进行进程/端口监控
        ProcessMonitorThread(
            ip_addr,
            port=8888,
            device_id=self.device_id,
            device_name=self.rack_name,
            owner_name=self.principal_name,
            device_desc=self.device_desc,
            fs_user_id=self.feishu_user_id,
            retry_times=ssh_retry_times,
            conn=self.conn,
            interval=30,
            exit_event=exit_event
        ).start()
        # 开始进行性能监控
        PerformanceMonitorThread(
            ip_addr,
            port=8888,
            device_id=self.device_id,
            device_name=self.rack_name,
            owner_name=self.principal_name,
            device_desc=self.device_desc,
            fs_user_id=self.feishu_user_id,
            retry_times=ssh_retry_times,
            conn=self.conn,
            monitor_exit=exit_event
        ).start()

        # 开始进行存储数据监控
        # 初始化时有些方法可能未完成 比如ssh连不上会一直连 DoIP服务初始化
        # storage_thd = StorageMonitorThread(
        #     ip_addr,
        #     ssh_port=8888,
        #     device_id=self.device_id,
        #     device_name=self.rack_name,
        #     owner_name=self.principal_name,
        #     device_desc=self.device_desc,
        #     fs_user_id=self.feishu_user_id,
        #     ssh_retry_times=ssh_retry_times
        # )
        # # 这里才是线程真正启动,与父线程是同级关系
        # storage_thd.start()

        # 通过一行函数调用启动所有日志监控线程
        start_logs_check(
            ip_addr, exit_event, 8888, self.device_id, self.rack_name, self.principal_name, self.device_desc,
            self.feishu_user_id, "root", "root", ssh_retry_times, self.conn
        )

        # 开始向客户端发送心跳包
        logger.info(f'开始对{self.addr}发送心跳, 心跳周期: {heartbeat_interval}s ...')
        try:
            while True:
                self.conn.send(b'heartbeat')
                data = self.conn.recv(1024)
                if data != b'heartbeat ack':  # 客户端心跳响应
                    logger.info(f'{self.addr} socket closed')
                    break
                time.sleep(heartbeat_interval)
        # 这里为客户端网络中断等场景
        except OSError as e:
            logger.error(f'{self.addr} 连接异常: {e}, 正在退出监控线程...')
        except:
            logger.error(f'{self.addr} 连接异常')
            logger.error(traceback.format_exc())

        # 主线程出异常, 连接关闭, 该IP池连接数量要复位
        # ssh监控退出 (所有监控job共享)
        SSH_CONN_EXIT_SIGNAL[self.conn] = 1
        # 通知所有监控job退出
        exit_event.set()
        # 此次socket连接销毁，释放资源
        self.conn.close()

        # 这时候看下最新的conn对象是否处于活跃状态，如果有，说明在心跳判断时间内，已经有新的连接进来了
        current_conn = connections_obj.get(ip_addr)
        is_active = True
        if current_conn:
            try:
                current_conn.send(b'isAlive')
                alive_resp = current_conn.recv(1024)
            except OSError as err:
                is_active = False
                logger.error(f'{self.addr} connection current_conn not alive: {err}')
            else:
                if alive_resp == b'':  # 客户端socket丢失可能会收到 b''
                    is_active = False
                    logger.error(f'{self.addr} connection current_conn client socket inactive')
            logger.info(is_active)
            if not is_active:
                with _lock:
                    connections[ip_addr] = 0
                    connections_obj[ip_addr] = 0

            logger.info(f'{self.addr} 上次监控线程退出成功，当前{ip_addr}的连接: {connections[ip_addr]}')


class HandleConnection(threading.Thread):
    def __init__(self, conn, addr):
        super().__init__()
        self.conn = conn
        self.addr = addr

    def run(self) -> None:
        ip = self.addr[0]
        ip = local_client_ip[1] if ip == local_client_ip[0] else ip
        # ip黑名单拒绝连接
        if ip in blacklist:
            self.conn.send(b'forbid')
            time.sleep(1)
            self.conn.close()
            return None
        with _lock:
            last_conn = connections_obj.get(ip)
        # 当前IP已经有连接
        if last_conn:
            logger.warning(f'{ip} has last connection: {last_conn}')
            # 检查上次连接是否有效
            # 无效则断开旧连接，释放新连接
            # 有效则向当前连接发送forbid从而阻止新连接
            try:
                last_conn.send(b'isAlive')
                alive_resp = last_conn.recv(1024)
            except OSError as e:
                logger.error(f'{ip} connection last_conn not alive: {str(e)}')
                SSH_CONN_EXIT_SIGNAL[last_conn] = 1
                last_conn.close()
                with _lock:
                    connections[ip] = 1
                    connections_obj[ip] = self.conn
            else:
                if alive_resp != b'isAlive ack':  # 可能会收到 b''
                    logger.error(f'{ip} alive_resp: {alive_resp}, connection client exit')
                    SSH_CONN_EXIT_SIGNAL[last_conn] = 1
                    last_conn.close()
                    with _lock:
                        connections[ip] = 1
                        connections_obj[ip] = self.conn
                else:
                    # 告诉现在的客户端不要再连了
                    self.conn.send(b'forbid')
                    # 这里因为客户端直接关闭socket,会接收到 b''
                    confirm = self.conn.recv(1024)
                    if confirm == b'':
                        logger.info(f'{ip} already close connection')
                        # 关闭,防止大量连接资源消耗
                        self.conn.close()
                        return
            time.sleep(1)
            # 启动监控线程
            MonitorThread(connections_obj[ip], self.addr).start()
        else:
            with _lock:
                connections[ip] = 1
                connections_obj[ip] = self.conn
                logger.info(f"Connected by: {self.addr}")
                # 启动监控线程
                MonitorThread(connections_obj[ip], self.addr).start()


class TCPServer(threading.Thread):
    """ 处理来自星辰客户端的请求 核心监控用"""

    def __init__(self, ip, port):
        super().__init__()
        self.sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sk.bind((ip, port))
        self.sk.listen(1000)
        logger.info(f"TCP socket create! bind {ip} {port}")

    def run(self) -> None:
        # 服务运行时，会记录所有连接信息放在 redis 中做存储；服务重启后，redis 相关的记录依然会保存，导致出现错误信息。
        # 这里需要在服务重启时，清理掉之前的连接信息，重新构建。
        # 目前整个服务端其实是单节点的，也没有做负载，服务会维护与客户端之间的长连接进行检测。
        # 因此这里在重启后直接删掉记录就可，如果后续要做分布式负载，这个方法需要改造。
        logger.info("clean connections and perf_online cache")
        connections.delete_name() # todo gzx 这里需要注意
        connection_info.delete_name()
        perf_online.delete_name()
        connection_sw_info.delete_name()
        # logger.info("clean connection_info cache")
        # connection_info.delete_name()
        logger.info("succ to clean")
        while True:
            conn, addr = self.sk.accept()  # 这里为阻塞等待连接
            HandleConnection(conn, addr).start()


class UDPServer(threading.Thread):
    def __init__(self, ip, port):
        super().__init__()
        self.sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sk.bind((ip, port))
        logger.info(f"UDP socket create! bind {ip} {port}")

    def run(self) -> None:
        while True:
            data, addr = self.sk.recvfrom(1024)
            logger.info(f'recv from {addr}: {data.decode()}')
            if data == b'connection_status':  # 接收到客户端在线信息请求
                try:
                    valid_connection = {}
                    for ip, cnt in connections.items():
                        if cnt:
                            valid_connection[ip] = connection_info[ip]
                    self.sk.sendto(json.dumps(valid_connection).encode('utf-8'), addr)
                except Exception as e:
                    self.sk.sendto(str(e).encode('utf-8'), addr)
            elif data == b'perf_connection_status':  # 接收到客户端性能在线信息请求
                try:
                    valid_perf_connection = {}
                    for ip, start_time in perf_online.items():
                        device_info = connection_info[ip]  # 这里变更元组为可变容器
                        device_info.append(start_time)
                        valid_perf_connection[ip] = device_info
                    self.sk.sendto(json.dumps(valid_perf_connection).encode('utf-8'), addr)
                except Exception as e:
                    self.sk.sendto(str(e).encode('utf-8'), addr)


if __name__ == '__main__':
    local_ip = '0.0.0.0'
    # 当前就一个主server 后面负载不够的时候再考虑多个server
    TCPServer(local_ip, stars_tcp_port).start()
    # UDPServer(local_ip, stars_udp_port).start()
    a = 1
