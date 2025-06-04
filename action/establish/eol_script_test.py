# -*- coding: utf-8 -*-
# @Author  : Li Kun
# @Time    : 2024/6/6 16:42
# @File    : eol_script_test.py

import os
import time
import json
import glob
from common.log import logger
from config.set_env import EnvOperate
from utilities.linux.xcu import xcu_client
from utilities.simulation.doipserver.doipserver_dyn import TcpMonitorThread, DynaInject
from utilities.browser.smart_check_operation import SmartCheckPage
from applications.ai.licloud_use.translator import Translator
from utilities.files.file_utils import read_json_file


class ReworkStation:
    def __init__(self, report_dir=''):
        self.report_dir = report_dir if report_dir else EnvOperate.create_current_report_dir('EOLScriptTest')
        self.fixed_station = '07_车机数据写入'
        self.simulator = TcpMonitorThread()
        # 先启动仿真
        self.start_simulator()

    def start_simulator(self):
        self.simulator.start()

    def stop_simulator(self):
        self.simulator.stop()

    def replace_lua_script(self, source, target):
        xcu_client.sftp_put(source, target)

    def compare_station_result(self, display):
        station_json = json.loads(xcu_client.execute_cmd('cat /app_data/smart_check_iot2/station_results/*_DJ20.json'))
        seq_ret = station_json['data']['sequenceResult']
        real_display = []
        for i in seq_ret:
            if i['function'] == '07_车机数据写入':
                final_result = i['finalResult']
                final_display = i['finalDisplay']
                assert not (final_result and '失败' in final_display)
                ecu_result = i['ecuResult']
                for ecu_ret in ecu_result:
                    ecu_result_bool = ecu_ret['ecuResult']
                    assert not final_result or ecu_result_bool
                    item_result = ecu_ret['itemResult']
                    for item_ret in item_result:
                        item_ret_bool = item_ret['result']
                        assert not ecu_result_bool or item_ret_bool
                        if item_ret.get('failedReason'):
                            real_display.append(item_ret['failedReason'])
                        else:
                            real_display.append(item_ret['display'])
                break
        logger.success(f'预期显示: {display}')
        logger.success(f'实际显示: {real_display}')
        for real_msg in real_display:
            if real_msg and '成功' not in real_msg:

                assert real_msg.replace(' ', '').upper() in display, f'实际显示结果与预期不一致; 预期: {display}, 实际: {real_display}'
        logger.success('测试通过')

    def run_testcase(self, testcase: dict, lua_script: str):
        """
        Args:
            lua_script: lua脚本路径
            testcase: 测试用例

        Returns:

        """
        # 创建报告文件夹
        # case_name = f'EOLScriptTest_{testcase["用例名称"]}'
        lua_name = '_'.join(lua_script.split('\\')[-1].split('_')[1:3])
        report_dir = EnvOperate.create_report_sub_dir(self.report_dir, lua_name)
        page = SmartCheckPage()
        page.set_common_screenshot_path(os.path.join(report_dir, 'common_img'))
        page.set_issue_screenshot_path(os.path.join(report_dir, 'issue_img'))
        try:
            # 注入用例
            _display, relation_data = Translator.make_resp_relation_via_testcases(testcase)
            display = [i for i in _display if '成功' not in i]
            logger.debug(f'///// 模拟测试用例: {testcase["用例名称"]}; \n用例数据: {relation_data}; \n显示: {display}')
            DynaInject(resp_relation=relation_data).start()
            # 替换lua脚本
            target_path = xcu_client.execute_cmd('ls /app_data/smart_check_iot2/lua_scripts/lua/*_07_*.lua').strip()
            xcu_client.execute_cmd(f'cp {target_path} {target_path}.bk')
            self.replace_lua_script(lua_script, target_path)
            xcu_client.execute_cmd(f'chmod 777 {target_path}')
            time.sleep(1)
            # 执行返修工位
            page.login()
            time.sleep(1)
            page.repair_station_execute(self.fixed_station, max_end_time=200, select_btn='ASU')
            time.sleep(1)
            # 解析结果
            self.compare_station_result(display)
            # 下载日志
            # station_results_download_dir = EnvOperate.create_report_sub_dir(report_dir, 'station_results')
            # xcu_client.sftp_download_files('/app_data/smart_check_iot2/station_results/', station_results_download_dir)
        # except AssertionError as e:
        #     logger.error(e)
        finally:
            page.quit()

    @classmethod
    def make_script_map(cls, scripts_dir):
        script_filepaths = glob.glob(os.path.join(scripts_dir, '*.lua'))
        script_map = {}
        for script_filepath in script_filepaths:
            script_map[script_filepath.split('\\')[-1].split('_')[1]] = script_filepath
        return script_map

    def run_all_testcase(self, case_dir, scripts_dir):
        testcase_filepaths = glob.glob(os.path.join(case_dir, '**', '*.json'))
        script_map = self.make_script_map(scripts_dir)
        for testcase_filepath in testcase_filepaths:
            data = read_json_file(testcase_filepath)
            testcases = data.get('testcases')
            requirement_name = data.get('requirement_name')
            logger.info(f'执行用例集: {testcase_filepath}, 用例数量: {len(testcases)}')
            # 获取对应脚本序号
            script_num = requirement_name.split('_')[1]
            script_path = script_map.get(script_num)
            if script_path:
                for testcase in testcases:
                    self.run_testcase(testcase, script_path)
                    a = 1


if __name__ == '__main__':
    tester = ReworkStation()

    # 测试单用例
    # testcase_path = r"D:\Project\autoli\applications\ai\licloud_use\output\电检\电检脚本需求_X01_19_车机密钥注入_01_20220425_draft\GPT_4_TURBO_testcases_2024-06-06_10-49-58.json"
    # lua_script = r"D:\likun3\Downloads\lua_scripts\lua\7ed596c27932557932d8cd23a9d70f30_19_HU_KEY_Injection_0x02_2023-06-21.lua"
    # formatted_test_cases = read_json_file(testcase_path)
    # for testcase in formatted_test_cases[0:3]:
    #     tester.run_testcase(lua_script, testcase)
    #     time.sleep(2)

    # 测试所有用例
    case_dir = r'D:\Project\autoli\applications\ai\licloud_use\output\电检'
    scripts_dir = r'D:\likun3\Downloads\lua_scripts\lua'
    tester.run_all_testcase(case_dir, scripts_dir)

    tester.stop_simulator()
