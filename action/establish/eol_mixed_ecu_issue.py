# -*- coding: utf-8 -*-
# @Author  : Li Kun
# @Time    : 2022/8/4 17:53
# @File    : eol_mixed_ecu_issue.py

import os
import time
from config.set_env import GlobalConstants, EnvOperate
from utilities.files.file_utils import read_json_file
from common.http_interface.api_bsp import BSPSmartCheck2
from utilities.linux.xcu import xcu_client
from utilities.linux.xcu_cmd import has_specific_file
from utilities.time_utils.time_ops import TimeOperation


def mixed_ecu_issue_pressure_test(vin, mixed_ecu_info, times=1, report_path=''):

    if not report_path:
        report_path = EnvOperate.create_current_report_dir('mixed_ecu_issue_pressure_test')
    bsp = BSPSmartCheck2()
    for i in range(times):
        bsp.mixed_ecu(GlobalConstants.VIN)
        time.sleep(10)
        remote_vehicle_info_filepath = GlobalConstants.SMART_CHECK_APP_DATA_DIR + 'vehicle_info.json'
        local_vehicle_info_filepath = os.path.join(report_path, 'vehicle_info_%s_.json' % int(time.time()))
        xcu_client.sftp_get(remote_vehicle_info_filepath, local_vehicle_info_filepath)
        # check point 1 检查vehicle_info.json文件更新日期
        res = has_specific_file(xcu_client,
                                GlobalConstants.SMART_CHECK_APP_DATA_DIR,
                                remote_vehicle_info_filepath,
                                update_datetime=TimeOperation.get_datetime_string(),
                                deviation=20)
        if res:
            file_update = True
        else:
            file_update = False
        vehicle_info = read_json_file(local_vehicle_info_filepath)
        mixed_ecu_list = vehicle_info.get('mixedEcuList', [])
        # check point 2 检查混装件信息
        if mixed_ecu_list == mixed_ecu_info:
            good_mixed_ecu = True
        else:
            good_mixed_ecu = False
        print(file_update, good_mixed_ecu, local_vehicle_info_filepath)

