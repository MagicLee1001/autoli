# -*- coding: utf-8 -*-
# @Author  : Li Kun
# @Time    : 2023/1/10 17:16
# @File    : eol_config_manage.py

import os
import json
import time
import datetime
import requests
from urllib.parse import urljoin
from common.log import logger
from common.custom_lib import MyRequest
from config.set_env import GlobalConstants, EnvOperate
from utilities.linux.xcu import xcu_client
from utilities.windows.win_ops import open_exe, task_kill
from utilities.files.file_utils import read_json_file, write_json_file, change_dos_to_unix, \
    search_by_keyword, get_filepath_from_dir
from utilities.files.excel_handler import MyXlwings
from utilities.time_utils.time_ops import TimeOperation
from utilities.parser.parsing_string import is_json_type, rsc
from action.establish.eol_station_test import StationTest, station_execution_test


def remove_draft_baseline(host, baseline_id):
    logger.info('执行删除基线接口')
    url = urljoin(host, f'v1/smart-check/baseConfig/del?baseLineId={baseline_id}')
    response = requests.request("DELETE", url, headers={})
    try:
        response.raise_for_status()
    except Exception as e:
        logger.error(e)
    else:
        logger.debug(response.text)
        return response.json()


def start_simulator(module_name):
    simulator_path = os.path.normpath(
        os.path.join(GlobalConstants.v2c_dir, r"tool\start_simulator\start_simulator.exe"))
    logger.info(simulator_path)
    open_exe(simulator_path, params=f"-m {module_name}")


class TestVariables:
    host = 'https://bsp-diag-service.test-changzhou.k8s.chehejia.com'
    script_id = 0
    baseline_id = 0
    baseline_version = 0
    testcase_data = []  # 每个元素为一张用例表


class TestOperate(MyXlwings):
    def __init__(self, testcase_filepath, report_path=''):
        super(TestOperate, self).__init__(testcase_filepath)
        self.report_path = EnvOperate.create_current_report_dir('eol_config_manage') if not report_path else report_path
        self.max_timeout = 10
        self.testcase_filepath = testcase_filepath
        self.constants_sheet_name = 'GlobalConstants'
        self.testcase_sheet_prefix_name = 'TestCase'

    def quit(self):
        super(TestOperate, self).__del__()

    def api_request(self, url, method, params, body):
        """
        这里请求需要区分body的传参类型
        - body python类型，被eval(str)转换
            form-data: 表单数据 直接带入字典传入data; 表单中有文件类型的做特殊处理
            raw-json: json数据
        Returns:
            response.json()
        """
        if url:
            url = urljoin(TestVariables.host, url)
            logger.info(f'执行请求:{method} {url}')
            headers = {'Content-Type': 'application/json'}
            if '/v1/smart-check/baseConfig/publish' in url or '/v1/smart-check/cdd/baseline/import' in url:
                timeout = 50
            else:
                timeout = self.max_timeout
            if not MyRequest.is_filestream_in_body(body):  # raw-json
                response = requests.request(method, url, headers=headers, params=params, data=json.dumps(body),
                                            timeout=timeout)
            else:
                trans_body = {}
                for key, val in body.items():
                    if isinstance(val, int):
                        trans_body[key] = str(val)
                    else:
                        trans_body[key] = val
                payload = MyRequest.make_body2multipart_encoder(trans_body)  # form-data带文件流
                headers = {'Content-Type': payload.content_type}  # must
                response = requests.request(method, url, headers=headers, params=params, data=payload,
                                            timeout=timeout)
            try:
                response.raise_for_status()
            except Exception as e:
                logger.error(e)
            else:
                logger.debug(f'响应code: {response.json().get("code")}')
                return response.json()

    def read_constants_sheet(self):
        constants_sheet = self.wb.sheets[self.constants_sheet_name]  # 表名
        TestVariables.host = constants_sheet.range(f'A2').value
        TestVariables.script_id = int(constants_sheet.range(f'B2').value)
        TestVariables.baseline_id = int(constants_sheet.range(f'C2').value)
        TestVariables.baseline_version = constants_sheet.range(f'D2').value

    def parse_testcase_file(self, sheet_name):
        """
        解析一条测试表的所有测试用例
        Args:
            sheet_name: 工作表名称
        Returns:

        """
        vin = GlobalConstants.VIN
        self.read_constants_sheet()  # 全局变量引用
        testcase_sheet = self.wb.sheets[sheet_name]
        logger.info(f'正在解析用例表: {sheet_name}')
        if testcase_sheet.name.startswith(self.testcase_sheet_prefix_name):  # 有效用例
            test_sheet_data = []  # 一个测试表的数据
            # 拆分用例
            testcase_range = self.divide_row_range_in_sheet(testcase_sheet)
            if not testcase_range:
                return {}
            for ra in testcase_range:
                testcase_data = {}  # 一条测试用例数据
                testcase_data['classification'] = sheet_name
                case_id = testcase_sheet.range(f'A{ra[0]}').value
                case_name = testcase_sheet.range(f'B{ra[0]}').value
                enabled = True if testcase_sheet.range(f'C{ra[0]}').value == '是' else False
                if not enabled:
                    continue
                execute_times = int(testcase_sheet.range(f'D{ra[0]}').value)
                simulate = True if testcase_sheet.range(f'L{ra[0]}').value == '是' else False
                module_name = testcase_sheet.range(f'M{ra[0]}').value
                special_operation = testcase_sheet.range(f'N{ra[0]}').value
                file_upload = testcase_sheet.range(f'O{ra[0]}').value
                station_type = testcase_sheet.range(f'P{ra[0]}').value
                if station_type == '返修':
                    is_repair_station = True
                else:
                    is_repair_station = False
                station_name = testcase_sheet.range(f'Q{ra[0]}').value
                exec_timeout = testcase_sheet.range(f'R{ra[0]}').value
                exec_timeout = int(exec_timeout) if exec_timeout is not None else 20
                result_filepath = testcase_sheet.range(f'S{ra[0]}').value
                result_filepath = rsc(result_filepath) if type(result_filepath) is str else result_filepath
                if result_filepath is not None:
                    if '{vin}' in result_filepath:
                        result_filepath = result_filepath.format(vin=vin)
                expect_content = testcase_sheet.range(f'T{ra[0]}').value
                expect_content = rsc(expect_content) if type(expect_content) is str else expect_content
                glog_keyword = testcase_sheet.range(f'U{ra[0]}').value
                glog_keyword = rsc(glog_keyword) if type(glog_keyword) is str else glog_keyword
                check_upload = testcase_sheet.range(f'V{ra[0]}').value
                request_data = []
                for _r in range(ra[0], ra[1] + 1):  # 遍历每条用例信息 ra:(2,5)
                    once_time_req_info = {}  # 一次请求数据信息
                    url = testcase_sheet.range(f'E{_r}').value
                    once_time_req_info['url'] = rsc(url) if type(url) else url
                    once_time_req_info['method'] = testcase_sheet.range(f'F{_r}').value
                    params = testcase_sheet.range(f'G{_r}').value
                    once_time_req_info['params'] = rsc(params) if type(params) is str else params
                    body = testcase_sheet.range(f'H{_r}').value
                    once_time_req_info['body'] = rsc(body) if type(body) is str else body
                    expect_resp = testcase_sheet.range(f'I{_r}').value
                    once_time_req_info['expect_resp'] = rsc(expect_resp) if type(expect_resp) is str else expect_resp
                    resp_refer = testcase_sheet.range(f'J{_r}').value
                    once_time_req_info['resp_refer'] = rsc(resp_refer) if type(resp_refer) is str else resp_refer
                    resp_wait = testcase_sheet.range(f'K{_r}').value
                    once_time_req_info['resp_wait'] = int(resp_wait) if resp_wait is not None else None
                    request_data.append(once_time_req_info)
                testcase_data['case_id'] = case_id
                testcase_data['case_name'] = case_name
                testcase_data['execute_times'] = execute_times
                testcase_data['enabled'] = enabled
                testcase_data['simulate'] = simulate
                testcase_data['module_name'] = module_name
                testcase_data['station_type'] = station_type
                testcase_data['is_repair_station'] = is_repair_station
                testcase_data['station_name'] = station_name
                testcase_data['exec_timeout'] = exec_timeout
                testcase_data['result_filepath'] = result_filepath
                testcase_data['expect_content'] = expect_content
                testcase_data['request_data'] = request_data
                testcase_data['glog_keyword'] = glog_keyword
                testcase_data['check_upload'] = check_upload
                testcase_data['special_operation'] = special_operation
                testcase_data['file_upload'] = file_upload
                test_sheet_data.append(testcase_data)
            logger.info(test_sheet_data)
            return test_sheet_data

    def request_cloud(self, request_data):
        # TODO exec() 变量引用表达式没法取到响应 data,导致赋值不生效,目前采用hardcode eval()代替
        host = TestVariables.host
        baseline_id = TestVariables.baseline_id
        script_id = TestVariables.script_id
        # baseline_version 需要构造 x.xx.xxx 格式版本 一个用例声明周期的所以请求中共用
        datetime_now = datetime.datetime.now()
        major_version = str(datetime_now.month)
        minor_version = f'{datetime_now.day}{datetime_now.hour}'
        path_version = f'{datetime_now.minute}{datetime_now.second}'
        TestVariables.baseline_version = baseline_version = f'{major_version}.{minor_version}.{path_version}'
        self.__setattr__('baseline_id', baseline_id)
        self.__setattr__('script_id', script_id)
        self.__setattr__('baseline_version', baseline_version)
        if request_data and type(request_data) is list:
            for i in request_data:
                url = i.get('url')
                if url:
                    url = url.replace('{baseline_id}', str(self.__getattribute__("baseline_id"))) \
                        .replace('{script_id}', str(self.__getattribute__("script_id"))) \
                        .replace('{baseline_version}', str(self.__getattribute__("baseline_version")))
                method = i.get('method')
                params = i.get('params')
                if type(params) is str:
                    params = eval(params.replace('{baseline_id}', 'self.__getattribute__("baseline_id")')
                                  .replace('{script_id}', 'self.__getattribute__("script_id")')
                                  .replace('{baseline_version}', 'self.__getattribute__("baseline_version")')
                                  )
                else:
                    params = {}
                body = i.get('body')
                if type(body) is str:
                    body = eval(body.replace('{baseline_id}', 'self.__getattribute__("baseline_id")')
                                .replace('{script_id}', 'self.__getattribute__("script_id")')
                                .replace('{baseline_version}', 'self.__getattribute__("baseline_version")')
                                )
                else:
                    body = {}
                data = self.api_request(url, method, params, body)
                if url:
                    if '/v1/smart-check/baseConfig/getList' in url:  # 判断是否存在DRAFT 存在需要删除基线
                        if data['data']['records'][0]['baseStatus'] == 'DRAFT':
                            baseline_id = data['data']['records'][0]['id']
                            remove_draft_baseline(host, baseline_id)
                            time.sleep(3)
                            data = self.api_request(url, method, params, body)
                resp_refer = i.get('resp_refer')
                if resp_refer:  # 存在响应引用表达式
                    expression_list = resp_refer.split('&')
                    for expression in expression_list:
                        key, val = expression.split('=')[0], expression.split('=')[1]
                        self.__setattr__(key, eval(val))
                resp_wait = i.get('resp_wait')
                if resp_wait:
                    time.sleep(resp_wait)
                # 预期结果比较
                expect_resp = i.get('expect_resp')
                if expect_resp and is_json_type(expect_resp):
                    for k, v in json.loads(expect_resp).items():
                        assert v in data.get(k)  # 预期响应与返回结果对应

    def update_vehicle_config_files(self):
        """
        登陆电检页面，点击返修工位-电检文件更新
        Returns:

        """
        sm = StationTest()
        sm.set_report_path(self.report_path)
        sm.set_screenshot_path()
        sm.login()
        logger.info('打开电检主页面')
        time.sleep(10)
        logger.info('监控正在执行的整车数据文件更新弹窗')
        sm.monitor_mixed_ecu_dialog()
        logger.info('监控结束')
        sm.repair_station_execute('电检文件更新', max_end_time=30)
        sm.quit()

    def modify_cdd_file(self, server_ip_address='172.31.30.166'):
        """
        修改cdd配置文件
        Args:
            server_ip_address:
                172.31.30.166 代表本地仿真
                172.31.10.31  代表默认配置
        Returns:
        """
        try:
            logger.info('配置cdd文件 满足doip仿真环境')
            filepath = os.path.join(self.report_path, 'EOL_CddBaseline.json.bk')
            xcu_client.sftp_get('/app_data/cdd_file/EOL_CddBaseline.json', filepath)
            file_json = read_json_file(filepath)
            for i in range(len(file_json.get('ecuInfoList'))):
                file_json['ecuInfoList'][i]['ipServerAddress'] = server_ip_address
            target_filepath = os.path.join(self.report_path, 'EOL_CddBaseline.json')
            write_json_file(target_filepath, file_json)
            change_dos_to_unix(target_filepath)
            xcu_client.sftp_put(target_filepath, '/app_data/cdd_file/EOL_CddBaseline.json')
            xcu_client.execute_cmd('sync')
            # modify EOL_cloud_ecu_diag_addr.json file
            logger.info('配置EOL_cloud_ecu_diag_addr文件 满足doip仿真环境')
            filepath = os.path.join(self.report_path, 'EOL_cloud_ecu_diag_addr.json.bk')
            xcu_client.sftp_get('/app_data/smart_check_iot2/EOL_cloud_ecu_diag_addr.json', filepath)
            file_json = read_json_file(filepath)
            for i in range(len(file_json.get('ecuInfoList'))):
                file_json['ecuInfoList'][i]['ipServerAddress'] = server_ip_address
            target_filepath = os.path.join(self.report_path, 'EOL_cloud_ecu_diag_addr.json')
            write_json_file(target_filepath, file_json)
            change_dos_to_unix(target_filepath)
            xcu_client.sftp_put(target_filepath, '/app_data/smart_check_iot2/EOL_cloud_ecu_diag_addr.json')
            xcu_client.execute_cmd('sync')
            logger.info('doip仿真环境配置完成')
        except Exception as e:
            logger.error(e)

    def check_result_file(self, result_filepath, expect_content):
        if result_filepath and expect_content:
            filename = result_filepath.split('/')[-1]
            local_filepath = os.path.join(self.report_path, filename)
            if expect_content != '无此文件':
                xcu_client.sftp_get(result_filepath, local_filepath)
                logger.info(f'待检查文件: {result_filepath}, 已下载到本地: {local_filepath}')
            res = xcu_client.execute_cmd(f'cat {result_filepath}')
            if 'No such file or directory' in res and expect_content == '无此文件':
                return True
            elif 'No such file or directory' in res and expect_content != '无此文件':
                return False
            res = res.replace(' ', '')
            expect_content = expect_content.replace(' ', '')
            expect_content_list = expect_content.split('&')
            check_result = []
            for ep in expect_content_list:
                if ep.startswith('^'):  # 代表期望不在文件中
                    ep = ep[1:]
                    logger.info(f'期望 {ep} 不在{result_filepath}中')
                    if ep not in res:
                        check_result.append(True)
                        logger.info('符合预期')
                    else:
                        logger.error('不符合预期')
                        check_result.append(False)
                else:
                    logger.info(f'期望 {ep} 在{result_filepath}中')
                    if ep in res:
                        logger.info('符合预期')
                        check_result.append(True)
                    else:
                        logger.error('不符合预期')
                        check_result.append(False)
            if False in check_result:
                return False
            else:
                return True
        else:
            return True

    def check_glog_keyword_existing(self, keyword, start_time, end_time):
        logger.info('检查 glog日志关键字是否存在')
        logger.info(f'待检查的关键字: {keyword}')
        keyword = keyword.strip()
        local_glog_dir = EnvOperate.create_report_sub_dir(self.report_path, 'app_log')
        logger.info(f'下载日志文件到本地文件夹: {local_glog_dir}')
        xcu_client.sftp_download_files('/log/Application/', local_glog_dir)
        keyword_list = keyword.split('&')
        check_result = []
        for keyw in keyword_list:
            keyw = keyw.replace('^', '')
            logger.info(keyw)
            has_keyword = False
            for filepath in get_filepath_from_dir(local_glog_dir):
                logger.info(filepath)
                keyword_lines = search_by_keyword(filepath, keyw)
                if keyword_lines:
                    logger.info(f'find keyword filepath: {filepath}')
                    logger.info(f'find keyword lines: {keyword_lines}')
                    has_keyword = True
            if keyword.startswith('^'):  # 代表期望不在文件中
                logger.info(f'期望 {keyw} 不在日志中')
                if has_keyword:
                    logger.info('不符合预期')
                    check_result.append(False)
                else:
                    logger.info('符合预期')
                    check_result.append(True)
            else:
                if has_keyword:
                    logger.info('符合预期')
                    check_result.append(True)
                else:
                    logger.info('不符合预期')
                    check_result.append(False)
        if False in check_result:
            return False
        else:
            return True

    def get_station_file(self):
        res = xcu_client.execute_cmd('ls /app_data/smart_check_iot2/station_version_info/EOL*.json')
        station_filepath = res.replace('\n', '')
        local_station_filepath = os.path.join(self.report_path, 'station_info.json')
        xcu_client.sftp_get(station_filepath, local_station_filepath)
        return local_station_filepath

    def run_testcase(self, testcase_data):
        """
        执行测试用例
        Args:
            testcase_data: type dict, 一条测试用例数据
        Returns:
        """
        # 关闭仿真器进程
        try:
            task_kill('start_simulator.exe')
        except:
            pass
        time.sleep(2)
        case_id = testcase_data.get('case_id')
        case_name = testcase_data.get('case_name')
        logger.info(f'当前测试用例ID: {case_id}, 测试用例名称: {case_name}')
        logger.info(f'当前测试用例数据: {json.dumps(testcase_data)}')
        simulate = testcase_data.get('simulate')
        module_name = testcase_data.get('module_name') if testcase_data.get('module_name') else 'doipcfg'  # 仿真器加载的数据模块名
        if testcase_data.get('enabled'):
            run_time_start = TimeOperation.get_datetime_string()
            if simulate:
                start_simulator(module_name)
            time.sleep(2)
            execute_times = testcase_data.get('execute_times')
            for i in range(execute_times):
                logger.info(f'这条用例共执行{execute_times}次,这是第{i + 1}次')
                exec_result_list = []
                # 下发接口请求
                request_data = testcase_data.get('request_data')
                if request_data[0]['url']:
                    logger.info(f'{request_data}下发接口请求')
                    self.request_cloud(request_data)
                # 更新整车数据文件
                # logger.info('更新整车数据文件')
                # self.update_vehicle_config_files()
                special_operation = testcase_data.get('special_operation')
                if special_operation:
                    logger.info(f'执行XCU特殊操作: {special_operation}')
                    res = xcu_client.execute_interact_cmd(special_operation)
                    logger.info(f'特殊操作执行结果: {res}')
                file_upload = testcase_data.get('file_upload')
                if file_upload:
                    xcu_client.sftp_put(file_upload.split('&')[0], file_upload.split('&')[1])
                    logger.info(f'上传文件到XCU: {file_upload}')
                # 启动仿真
                if simulate:
                    logger.info('启动仿真前，修改IP地址')
                    self.modify_cdd_file()
                # 执行电检工位 最后再检查日志上传
                is_repair_station = testcase_data.get('is_repair_station')
                station_type = testcase_data.get('station_type')
                if testcase_data.get('check_upload') == '是':
                    check_upload_result = True
                else:
                    check_upload_result = False
                if station_type:
                    station_name = testcase_data.get('station_name')
                    logger.info(f'执行电检工位: {station_type}-{station_name}')
                    select_btn = None
                    exec_timeout = testcase_data.get('exec_timeout')
                    if '&' in station_name:
                        select_info = station_name.split('&')
                        station_name, select_btn = select_info[0], select_info[1]
                    self.get_station_file()
                    try:
                        exec_result_list = station_execution_test(
                            station_name=station_name,
                            report_dir=self.report_path,
                            max_execute_time=exec_timeout,
                            is_repair_station=is_repair_station,
                            check_upload=check_upload_result,
                            select_btn=select_btn
                        )
                    except Exception as e:
                        logger.error(e)
                time.sleep(5)
                # 检查结果文件
                result_filepath = testcase_data.get('result_filepath')
                if result_filepath:
                    logger.info('检查结果文件')
                    result_filepath = result_filepath.replace('{vin}', GlobalConstants.VIN)
                    logger.info(f'待结果文件路径 {result_filepath}')
                    multi_expect_content = testcase_data.get('expect_content')  # 多检查条件&拼接表示
                    if multi_expect_content:
                        for content in multi_expect_content.split('&'):
                            logger.info(f'需检查内容 {content}')
                            is_exist = self.check_result_file(result_filepath, content)
                            assert is_exist is True, '文件内容检查符合预期'

                # 检查日志文件
                glog_keyword = testcase_data.get('glog_keyword')
                if glog_keyword:
                    run_time_end = TimeOperation.get_datetime_string()
                    has_spec_keyword = self.check_glog_keyword_existing(glog_keyword, run_time_start, run_time_end)
                    assert has_spec_keyword is True, '日志关键字不存在'

                # 检查上传结果
                assert '不通过' not in exec_result_list, '工位执行检查失败'


if __name__ == '__main__':
    # print(TestVariables.host)
    # print(TestVariables.script_id)
    # print(TestVariables.baseline_id)
    # remove_draft_baseline(TestVariables.host, 253)

    t = TestOperate(r"D:\Project\autoli\src\case\eol\testcase_eol_conf_manage_demo.xlsx")
    sheet_names = t.get_testcase_sheet_names()
    print('测试用例表', sheet_names)
    all_testcase_data = t.parse_testcase_file('TestCase-ECU时间参数配置')
    print(all_testcase_data)
    for testcase_data in all_testcase_data:
        t.run_testcase(testcase_data)
        t.quit()
        # start_simulator('doipcfg')
