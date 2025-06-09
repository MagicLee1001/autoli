# -*- coding: utf-8 -*-
# @Author  : Li Kun
# @Time    : 2023/12/22 13:11
# @File    : storage.py

import datetime
import json
import requests
from typing import Union
from utilities.db.redis_api import RedisAPI
from common.http_interface.api_tmp import RedisStars
from common.log import logger as logger
from config.set_env import GlobalConstants


class Storage:
    """
    连接redis存储星辰连接信息
    """
    def __init__(self, namespace='stars', name='', redis_connection=None):
        self.namespace = namespace
        self.name = f'{self.namespace}:{name}'
        if redis_connection is None:
            self.redis = RedisAPI().master
        else:
            self.redis = redis_connection

    def __getitem__(self, key):
        value = self.redis.hget(self.name, key)
        if value is None:
            raise KeyError(key)
        try:
            return json.loads(value.decode('utf-8'))
        except json.JSONDecodeError:
            return value.decode('utf-8')

    def __setitem__(self, key, value):
        if isinstance(value, list | tuple | dict):
            value = json.dumps(value)
        self.redis.hset(self.name, key, value)

    def __delitem__(self, key):
        return self.redis.hdel(self.name, key)

    def get(self, key, default=None):
        value = self.redis.hget(self.name, key)
        if value is None:
            return default
        try:
            return json.loads(value.decode('utf-8'))
        except json.JSONDecodeError:
            return value.decode('utf-8')

    def items(self):
        items = self.redis.hgetall(self.name)
        dict_items = {}
        for key, value in items.items():
            decoded_key = key.decode('utf-8')
            try:
                # 尝试反序列化值
                decoded_value = json.loads(value.decode('utf-8'))
            except json.JSONDecodeError:
                # 如果不是JSON，就作为普通字符串处理
                decoded_value = value.decode('utf-8')
            dict_items[decoded_key] = decoded_value
        return dict_items.items()

    def delete_namespace(self):
        # This method will delete the namespace along with all its associated hashes
        keys_to_delete = self.redis.keys(f'{self.namespace}:*')
        if keys_to_delete:
            return self.redis.delete(*keys_to_delete)
        return False

    def delete_name(self):
        # This method will clear the specific hash assigned to this Storage instance
        return self.redis.delete(self.name)

    def get_namespace_items(self):
        keys_pattern = f"{self.namespace}:*"
        namespace_keys = self.redis.keys(keys_pattern)
        namespace_items = {}
        for key in namespace_keys:
            hash_items = self.redis.hgetall(key)
            items = {}
            for k, v in hash_items.items():
                try:
                    v = json.loads(v.decode('utf-8'))
                except json.JSONDecodeError:
                    v = v.decode('utf-8')
                items[k.decode('utf-8')] = v
            namespace_items[key.decode('utf-8')] = items
        return namespace_items

    def get_name_items(self):
        items = {}
        for k, v in self.redis.hgetall(self.name).items():
            try:
                v = json.loads(v.decode('utf-8'))
            except json.JSONDecodeError:
                v = v.decode('utf-8')
            items[k.decode('utf-8')] = v
        return items


class StorageV2:
    """
    通过测试管理平台接口，更新redis星辰信息
    """
    def __init__(self, namespace='stars', name=''):
        self.namespace = namespace
        self.name = f'{self.namespace}:{name}'
        self.redis_stars = RedisStars()

    def __getitem__(self, key):
        value = self.redis_stars.get_value(self.name, key).get('data', {}).get('data')
        if value is None:
            raise KeyError(key)
        return value
        # try:
        #     return json.loads(value.decode('utf-8'))
        # except json.JSONDecodeError:
        #     return value.decode('utf-8')

    def __setitem__(self, key, value):
        if isinstance(value, list | tuple | dict):
            value = json.dumps(value)
        self.redis_stars.set_value(self.name, key, value)

    def __delitem__(self, key):
        return self.redis_stars.delete_key(self.name, key)

    def get(self, key, default=None):
        value = self.redis_stars.get_value(self.name, key).get('data')
        if value is None:
            return default
        try:
            return json.loads(value.decode('utf-8'))
        except json.JSONDecodeError:
            return value.decode('utf-8')

    def items(self):
        data = self.redis_stars.get_namespace(self.name).get('data')
        return data.items()

    def delete_name(self):
        # This method will clear the specific hash assigned to this Storage instance
        return self.redis_stars.delete_namespace(self.name)


def report_to_tmp(
    device_id: Union[str, int],
    xcu_platform: str,
    xcu_platform_version: str,
    xcu_baseline: str,
    name: str,
    process_name: str,
    alert_time: datetime.datetime = None,
    log_path: str = "",
    content: dict = None,
) -> dict:
    """
    上报信息给 tmp
    :param device_id: 客户端 id;
    :param xcu_platform: 客户端对应 xcu 的信息, 如 XAP XPP 等;
    :param xcu_platform_version: 客户端对应 xcu 的版本信息;
    :param xcu_baseline: 客户端对应 xcu 的基线版本信息;
    :param name: 服务名字，必须传递，用来拼接 url; coredump 用 coredup, 进程重启监控用 process-restart
    :param process_name: 进程名字;
    :param log_path: 告警日志存储的位置;
    :param content: 具体告警信息;
    :param alert_time: 发生的时间;
    :return: 是否上报成功;
    """
    if alert_time is None:
        alert_time = datetime.datetime.now()
    alert_day = int(alert_time.strftime("%Y%m%d"))
    if content is None:
        content = {}
    url = f'{GlobalConstants.TMP_BASE_URL}/star-monitor-alert/{name}/report'
    logger.debug(f"name={name} 上报 process_name={process_name}")
    header = {
        "Authorization": 'Bearer ' + GlobalConstants.TMP_TOKEN
    }
    # if not device_id:
    #     device_id = -1  # 测试 device
    if xcu_platform_version.startswith("X"):  # 如果格式是 XAP1.2.3, 要提取出后面的版本
        xcu_platform_version = xcu_platform_version[3:]
    data = {
        "device_id": device_id,
        "process_name": process_name,
        "baseline": xcu_baseline,
        "platform": xcu_platform,
        "platform_version": xcu_platform_version,
        "log_path": log_path,
        "alert_day": alert_day,
        "alert_time": alert_time.strftime("%Y-%m-%d %H:%M:%S"),
        "content": content,
    }
    # logger.info(data)
    for i in range(3):
        try:
            resp = requests.post(url, json=data, headers=header)
            if resp.status_code != 200:
                logger.error(f"invalid http code: {resp.status_code}")
                return {}
            data = json.loads(resp.content)
            if data['code'] != 0:
                logger.error(f"fail to report: {data['message']}")
                return {}
            data = data['data']
            logger.info(f"响应是 {data}.")
            return data
        except Exception as e:
            logger.error(f"第 {i+1} 次上报失败: {e}")
    logger.error("用尽所有次数,依然无法上报成功.")
    return {}


if __name__ == '__main__':
    perf_online = StorageV2(namespace='stars', name='perf_online')  # ip:datetime_str
    del perf_online['10.121.84.70']
