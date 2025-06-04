#!/usr/bin/env python 
# -*- coding: utf-8 -*-
# @Time    : 2022/5/26 13:26
# @Author  : Li Kun
# @File    : eol_station_test.py

import os
import time
import json
import threading
from common.log import logger
from common.http_interface.api_bsp import BSPSmartCheck2
from utilities.linux.xcu import xcu_client
from utilities.linux.xcu_cmd import get_pid_by_name
from utilities.time_utils.time_ops import TimeOperation
from config.set_env import EnvOperate, GlobalConstants
from utilities.browser.smart_check_operation import SmartCheckPage
from utilities.files.file_utils import append_file, read_json_file
from utilities.simulation.archive.eol_simulator import EOLAutoResponse
from action.state.eol_job_history import get_bspd_job_history, \
    get_bspd_job_station_log, get_bspd_job_station_json, analysis_station_upload_state
from utilities.feishu.robot import WebhookRobot
from action.establish import REPAIR_NOT_UPLOAD_LIST
import datetime

robot = WebhookRobot(GlobalConstants.EOL_AT_WEBHOOK_ADDRESS, secret=GlobalConstants.EOL_AT_WEBHOOK_SECRET)


class StationTest(SmartCheckPage):
    """
    Web浏览器页面，智能电检工位测试
    """

    def __init__(self, max_simulation_time=100, max_no_signal_time=50):
        super(StationTest, self).__init__()
        self.max_simulation_time = max_simulation_time  # 测试周期内的最大仿真应答时间
        self.max_no_signal_time = max_no_signal_time  # 未收到制定报文的最大超时时间
        self.report_path = ''

    def set_report_path(self, report_path):
        self.report_path = report_path

    def set_screenshot_path(self):
        common_path = EnvOperate.create_report_sub_dir(self.report_path, 'selenium_common_img')
        issue_path = EnvOperate.create_report_sub_dir(self.report_path, 'selenium_issue_img')
        self.set_common_screenshot_path(common_path)
        self.set_issue_screenshot_path(issue_path)

    def simulation(self, test_case_path):
        lua_tester = EOLAutoResponse(test_case_path)
        lua_tester.set_max_answer_time(self.max_simulation_time)
        lua_tester.set_timeout(self.max_no_signal_time)
        lua_tester.auto_response()

    def execution(self, station_name, max_end_time, is_repair_station=False, check_upload=True, select_btn=''):
        """
        登陆电检页面并点击执行电检工位，最终返回执行结果
        Args:
            station_name (str): 工位名称或工位号
            max_end_time (int): 工位最大执行时间，工位执行结束后会有确认按钮，即显性等待时间，超过这个时间则退出页面
            is_repair_station (bool): 是否为返修工位，True表示执行非返修工位
            check_upload: 是否检查云端日志与结果文件上传记录
            select_btn (str): 工位点击后可能会有二级按钮，这里表示二级按钮文本，非空则表示存在二级按钮

        Returns:
            tuple:

        """
        station_pass = False
        fail_point = None
        test_result = '通过'
        self.login()
        time.sleep(2)
        # self.monitor_mixed_ecu_dialog()
        logger.info(f'开始执行电检工位测试：{station_name}')
        start_time = TimeOperation.get_datetime_string()
        if not is_repair_station:  # 非返修
            try:
                self.station_execute(station_name, max_end_time=max_end_time)
            except Exception as e:
                test_result, fail_point = '不通过', f'执行工位失败：{e}'
            else:
                station_pass = True
        else:
            try:
                self.repair_station_execute(station_name, max_end_time=max_end_time, select_btn=select_btn)
            except Exception as e:
                test_result, fail_point = '不通过', f'执行工位失败：{e}'
            else:
                station_pass = True
        time.sleep(10)  # 跑完结束等待10秒以后上传日志和工位文件
        logger.info(f'{station_name} 工位执行结束')
        end_time = TimeOperation.get_datetime_string()
        if station_pass and check_upload:  # 工位执行完成后，查询日志上传结果
            log_num = 1
            json_num = 1
            if is_repair_station and station_name in REPAIR_NOT_UPLOAD_LIST:
                json_num = 0
            if 'DJ16' in station_name or '报交' in station_name:
                json_num = 2
            # 获取云端工位执行历史文件上传记录（包括日志文件和结果文件）
            job_history_data = get_bspd_job_history(GlobalConstants.VIN, GlobalConstants.SN)
            # 根据历史数据查询日志文件
            res_log = get_bspd_job_station_log(job_history_data)
            # 根据历史数据查询结果文件
            res_json = get_bspd_job_station_json(job_history_data)
            logger.info(f"查询日志和结果时间：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
            # 分析日志文件上传记录
            log_upload_res = analysis_station_upload_state(res_log, start_time, end_time, log_num)
            # 分析结果文件上传记录
            json_upload_res = analysis_station_upload_state(res_json, start_time, end_time, json_num)
            logger.info(f'{station_name} 日志上传: {log_upload_res}')
            logger.info(f'{station_name} 结果上传: {json_upload_res}')
            if not log_upload_res[-1] or not json_upload_res[-1]:
                # 日志或者结果有一项失败
                test_result, fail_point = '不通过', '日志或结果文件上传次数不符合预期'
                logger.warning(f'日志实际: {log_upload_res[0]}次, 预期: {log_upload_res[1]}次')
                logger.warning(f'结果实际: {json_upload_res[0]}次, 预期: {json_upload_res[1]}次')
        return start_time, end_time, test_result, fail_point

    def station_execute_on_can(self, test_case_path: str, station_name: str, max_execute_time=100) -> None:
        """
        工位执行时试用DoCAN仿真，仿真时根据用例进行响应
        2024年已弃用此方案，现主流方案被DoIP代替
        Args:
            test_case_path: 测试用例路径
            station_name: 工位名称
            max_execute_time: 最大执行时间

        Returns:

        """
        t1 = threading.Thread(target=self.simulation, args=(test_case_path,))
        t2 = threading.Thread(target=self.execution, args=(station_name, max_execute_time,))
        t1.start()
        time.sleep(1)
        t2.start()
        t1.join()
        t2.join()


def pressure_test(
        station_name,
        method='doip',
        max_simulation_time=800,
        max_execute_time=800,
        case_path='',
        is_repair_station=False,
        test_times=1
):
    """
    station_name (str): 压测工位名称
    method (str): 可选doip或docan
    max_simulation_time (int): 脚本仿真的最大超时时间，单位：秒
    max_execute_time (int): 在浏览器上执行工位时的最大执行时间，单位：秒
    case_path (str): 选docan时，需要给出仿真用例路径
    is_repair_station (bool): 是否为返修工位，默认False，表示非返修
    test_times (int): 压测次数
    """
    case_name = 'Test_SOP_SmartCheck_Station_Pressure'
    report_dir = EnvOperate.create_current_report_dir(case_name)
    result_file = os.path.join(report_dir, 'station_pressure_test_result.txt')
    for _i in range(test_times):
        tester = StationTest(max_simulation_time=max_simulation_time)
        tester.set_report_path(report_dir)
        tester.set_screenshot_path()
        if method == 'doip':  # DoIP
            tester.execution(station_name, max_execute_time, is_repair_station=is_repair_station)  # 执行压测
        else:  # DoCAN
            tester.station_execute_on_can(case_path, station_name, max_execute_time)
        time.sleep(1)
        tester.quit()
        c_date = TimeOperation.get_datetime_string()
        content = f'{_i + 1}  {c_date}  %s \n' % json.dumps(tester.station_res)
        append_file(content.encode('utf-8'), result_file)
    eol_log_download_dir = EnvOperate.create_report_sub_dir(report_dir, 'smart_check_app_log')
    xcu_client.sftp_download_files('/app_data/glog/smart_check/', eol_log_download_dir)


def station_execution_test(
        station_name='',
        report_dir='',
        max_execute_time=180,
        test_times=1,
        is_repair_station=False,
        check_upload=True,
        select_btn=''
):
    """
    电检工位测试主函数，通过打开浏览器登陆电检页面，选择非返修/返修工位的工位名称并点击执行进行测试
    Args:
        station_name (str): 工位名称或工位号
        report_dir (str): 报告路径，没有则自动创建
        max_execute_time (int): 工位最大执行时间，工位执行结束后会有确认按钮，即显性等待时间，超过这个时间则退出页面
        test_times (int): 工位测试次数
        is_repair_station (bool): 是否为返修工位，True表示执行非返修工位
        check_upload (bool): 是否检查云端日志与结果文件上传记录
        select_btn (str): 工位点击后可能会有二级按钮，这里表示二级按钮文本，非空则表示存在二级按钮

    Returns:
        tuple: 包含两个元素:
            - result_list (list): 每次测试结果的列表，元素为'test_result'，即'通过'或'不通过'的字符串
            - fail_script_info (str): 不通过时的失败信息描述，如果测试成功则为空字符串

    """
    fail_script_info = ''
    result_list = []
    case_name = 'TestSmartCheckStationExecute-%s' % station_name.upper()
    if not report_dir:
        report_dir = EnvOperate.create_current_report_dir(case_name)
    for _time in range(test_times):
        tester = StationTest()
        tester.set_report_path(report_dir)
        tester.set_screenshot_path()
        start_time, end_time, test_result, fail_point = tester.execution(
            station_name,
            max_end_time=max_execute_time,
            is_repair_station=is_repair_station,
            check_upload=check_upload,
            select_btn=select_btn
        )
        logger.info(f'{station_name} 执行结果: {test_result} 原因:{fail_point}')
        time.sleep(1)
        eol_log_download_dir = EnvOperate.create_report_sub_dir(report_dir, 'smart_check_app_log')
        station_results_download_dir = EnvOperate.create_report_sub_dir(report_dir, 'station_results')
        xcu_client.sftp_download_files('/app_data/glog/smart_check/', eol_log_download_dir)
        xcu_client.sftp_download_files('/app_data/smart_check_iot2/station_results/', station_results_download_dir)

        if not is_repair_station:  # lxl modify; lk modify 2022/12/08
            fail_script_info = '\n'
            temp_data = read_json_file(f'{station_results_download_dir}\\{GlobalConstants.VIN}_{station_name}.json')
            num_repair_station = len(temp_data['data']['sequenceResult'])
            for _i in range(0, num_repair_station):
                sequence = temp_data['data']['sequenceResult'][_i]
                script_result = sequence['finalResult']
                if '一键校验' in sequence['function']:
                    continue
                if not script_result:
                    for item in sequence['ecuResult']:
                        if not item['ecuResult']:
                            for result in item['itemResult']:
                                if not result['result']:
                                    fail_script_info += f"脚本：{sequence['function']}; 执行结果: {result['display']}; 失败原因:{result['failedReason']}\n"
                                    logger.info(fail_script_info)

        result_list.append(test_result)
        tester.quit()
    return result_list, fail_script_info


class UdsRespLog:
    log_content = ''


def catch_uds_response_log(xcu):
    res = xcu.execute_interact_cmd('tail -f /app_data/glog/smart_check/smart_check.INFO | grep uds_response', console=False, timeout=30)
    UdsRespLog.log_content = res


def station_execute_with_query_log(xcu, report_dir, station_number, max_execute_time=200, test_times=1):
    t1 = threading.Thread(target=catch_uds_response_log, args=(xcu,))
    t2 = threading.Thread(
        target=station_execution_test,
        args=(station_number,),
        kwargs={
            "report_dir": report_dir,
            "max_execute_time": max_execute_time,
            "test_times": test_times
        }
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def station_execute_via_cloud_job(station_info, issued_times=1, report_dir=''):
    """
    云端下发指令电检工位执行指令
        station_info = {
            "vin": GlobalConstants.VIN,
            "dataType": "stationInfo",
            "action": "cmd",
            "data": {
                "vin": GlobalConstants.VIN,
                "stationId": "DJ12",
                "stationName": "慢充检测工位",  # 1.钥匙匹配及防盗工位, 3.整车电检工位, 16.报交工位
                "label": ""
            }
        }
    """
    result = {
        'result': 'pass',
        'reason': ''
    }
    if not report_dir:
        report_dir = EnvOperate.create_current_report_dir('station_execute_via_cloud_job')
    vin = GlobalConstants.VIN
    browser = StationTest()
    browser.set_report_path(report_dir)  # 设置报告路径，必须
    browser.set_screenshot_path()  # 设置报告目录为截图路径，必须
    browser.login()
    time.sleep(5)
    bsp = BSPSmartCheck2()
    station_info = station_info
    station_name = station_info['data']['stationId']
    # 每隔time_interval秒下发一次指令，看电检程序是否重启，是否上传日志到云端
    pid_init = get_pid_by_name(xcu_client, 'smart_check')
    time_start = TimeOperation.get_datetime_string()
    logger.info(f'开始时间: {time_start}')
    for _i in range(issued_times):
        bsp.station_info_to_bsp_v1(station_info)
        station_name = station_info['data']['stationId']
        logger.info(f'云端下发的工位为：{station_name}')
        browser.confirm_execution_page(station_name, 1800)

    time_end = TimeOperation.get_datetime_string()
    pid_final = get_pid_by_name(xcu_client, 'smart_check')
    if pid_init != pid_final:
        result['result'] = 'fail'
        result['reason'] = 'pid not same'
    job_history_data = get_bspd_job_history(GlobalConstants.VIN, GlobalConstants.SN)
    station_log = get_bspd_job_station_log(job_history_data)
    station_json = get_bspd_job_station_json(job_history_data)
    json_uploaded = analysis_station_upload_state(station_json, time_start, time_end, issued_times)
    log_uploaded = analysis_station_upload_state(station_log, time_start, time_end, issued_times)
    if not json_uploaded[-1]:
        result['result'] = 'fail'
        result['reason'] = 'json uploaded fail'
    if not log_uploaded[-1]:
        result['result'] = 'fail'
        result['reason'] = 'log uploaded fail'
    browser.quit()
    time.sleep(1)
    station_results_download_dir = EnvOperate.create_report_sub_dir(report_dir, 'station_results')
    eol_log_download_dir = EnvOperate.create_report_sub_dir(report_dir, 'smart_check_app_log')
    xcu_client.sftp_download_files('/app_data/glog/smart_check/', eol_log_download_dir)
    xcu_client.sftp_download_files('/app_data/smart_check_iot2/station_results/', station_results_download_dir)
    temp_data = read_json_file(station_results_download_dir + '\\' + vin + "_" + station_name + '.json', )
    num_repair_station = len(temp_data['data']['sequenceResult'])
    for _i in range(0, num_repair_station):
        logger.info(f"{temp_data['data']['sequenceResult'][i]['function']}: {temp_data['data']['sequenceResult'][i]['finalResult']}")
    return result


if __name__ == '__main__':
    # pass

    # 压力测试  XP
    # env = GlobalConstants.ENV
    times = 50
    for i in range(times):
        pressure_test(
            station_name='DJ02',  # DJ11_1
            method='doip',  # doip or docan
            max_simulation_time=600,  # 最大仿真时间
            max_execute_time=1200,  # 最大Station测试时间
            test_times=1)

    station_execution_test(
        station_name='DJ20',
        is_repair_station=False,
        select_btn='FBCM',
        max_execute_time=30,
        test_times=1
    )  # 密钥注入工位d

