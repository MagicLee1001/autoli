# -*- coding: utf-8 -*-
# @Author  : Li Kun
# @Time    : 2022/11/1 15:23
# @File    : ota_ecu.py

import os
import time
from common.http_interface.api_ota import OTAService
from utilities.time_utils.time_ops import TimeOperation
from common.log import logger
from enum import Enum
from threading import Thread
from utilities.linux.xcu import xcu_client
from utilities.linux import xcu_cmd
from utilities.pcan.pcan_professor import PCAN
from utilities.pcan import PCANBasic as PB
from utilities.usb.relay import USBRelay
from utilities.files.excel_handler import ExcelRead
from utilities.files.file_utils import change_dos_to_unix, write_json_file, search_by_keyword, search_by_keyword_ota
from action.establish.ota_xcu import make_xcu_with_high_load


class OTACaseHandle:
    @staticmethod
    def translate_ota_testcase(source_path, target_path, sheet_name='Sheet1'):
        reader = ExcelRead(file_name=source_path)
        rows = reader.read_rows(sheet_name=sheet_name)
        final_rows = []
        for i in rows:
            i['upgradeDataList'] = eval(i['upgradeDataList'])
            i['enable'] = True if i['enable'] == 1 else False
            i['testTimes'] = int(i['testTimes'])
            i['actionKeywordTimes'] = int(i['actionKeywordTimes'])
            i['verifyKeyword'] = eval(i['verifyKeyword'])
            i['alternateUpgrade'] = True if i['alternateUpgrade'] == 1 else False
            final_rows.append(i)
        write_json_file(target_path, final_rows)

    @staticmethod
    def structure_upgrade_data_list(upgrade_data_list, common_upgrade_data_list):
        """

        Args:
            upgrade_data_list: 用例ECU升级信息
            common_upgrade_data_list: 公共ECU升级信息

        Returns:

        """
        for i in range(len(upgrade_data_list)):
            ecu_update_info = upgrade_data_list[i]
            ecu_name = ecu_update_info.get('ecuName')
            system_name = ecu_update_info.get('systemName')
            ecu_version = ecu_update_info.get('ecuVersion')
            system_version = ecu_update_info.get('systemVersion')
            if not ecu_version:
                for common_info in common_upgrade_data_list:
                    if common_info['ecuName'] == ecu_name and system_name == common_info['systemName']:
                        upgrade_data_list[i]['ecuVersion'] = common_info['ecuVersion']
            if not system_version:
                for common_info in common_upgrade_data_list:
                    if common_info['ecuName'] == ecu_name and system_name == common_info['systemName']:
                        upgrade_data_list[i]['systemVersion'] = common_info['systemVersion']
        return upgrade_data_list


class UpgradeActionKeyword(Enum):
    reboot = 1  # XCU重启； tag:times
    power_on_off = 2  # 上下电； tag:times
    bus_busy = 3  # 总线繁忙； tag:times
    high_load = 4  # CPU高负载与使用率； tag:times
    cancel_upgrade = 5  # 取消升级任务
    recreate_task = 6  # 再次创建下载任务
    space_overflow = 7  # OTA空间容量溢出
    restart_app = 8  # 重启 XCU fota app
    cwd_inject = 9  # 配置字注入
    cut_off_network = 10  # 断开网络
    xcu_offline = 11  # 用于XCU不在线，创建FOTA任务


class UpgradeVerifyKeyword(Enum):
    vehicle_mode = 1  # 校验升级前中后的车辆模式
    a_core_cw = 2  # A核config word校验
    a_core_version = 3  # xcu release baseline version
    m_core_version = 4  # ecu sub system version
    bus_banned = 5  # 检查28 xx 03禁言
    clear_dtc = 6  # 后处理 14 ff ff ff清故障码
    response_inhibition = 7  # 后处理 10 81 响应抑制
    complete_frame = 8  # 升级过程诊断报文不丢帧
    eth_log_package = 9  # 以太网报文打包
    precompile_message = 10  # uds预编译报文
    verify_version = 11  # ECU版本号校验，这里只校验FBCM,RBCM
    fingerprint_info = 12  # 升级完成后的指纹信息（诊断，如刷写日期），这里只校验FBCM,RBCM
    check_time = 13
    check_downgrade = 14  # 验证向低版本升级失败
    check_addinfo = 15  # 冰箱升级失败，检查addinfo
    check_B2_32 = 16  # 升级LIN节点无B2 32的诊断报文
    dtc_banned = 17  # 检查升级前禁dtc，用于ECU，不适用XCU
    security_seed_key = 18  # security seed and key，用于ECU，不适用XCU
    read_ecu_version = 19  # 读ecu版本号，用于ECU，不适用XCU
    check_integrity = 20  # 检查下载包完整性
    write_fingerprint = 21  # write fingerprint
    check_dependencies = 22  # check dependencies
    session_program = 23  # session program
    session_extended = 24  # session extended
    read_lin_version = 25  # read lin version
    erase_memory = 26  # erase memory
    lin_reset = 27  # lin reset
    check_crash = 28  # check_crash
    lin_8227 = 29  #
    log_notify_upload = 30  # 检查日志文件是否存在


class ActionKeywordMethod:
    @staticmethod
    def reboot():
        logger.info('控制XCU重启')
        xcu_client.execute_cmd('reboot')
        time.sleep(20)  # XCU启动后初始化时间

    @staticmethod
    def power_on_off(off_waiting=5):
        off_waiting = 30
        logger.info(f'控制台架上下电, 中间等待 {off_waiting} 秒')
        usb_relay = USBRelay()
        usb_relay.make_lifecycle(middle_waiting_time=off_waiting)
        usb_relay.close_handle()
        time.sleep(20)  # XCU启动后初始化时间

    @staticmethod
    def bus_busy():
        logger.info('控制总线繁忙')
        bdcan1 = PCAN(PB.PCAN_USBBUS1, PB.PCAN_BAUD_2M, CanFD=True)
        msg_data = ['0x00'] * 63
        msg_data.append('0x01')
        time_now = time.time()
        time.sleep(10)
        while time.time() - time_now < 30:
            bdcan1.send_message('0x096', msg_data, console=None)
            time.sleep(0.001)
        time.sleep(20)
        while time.time() - time_now < 30:
            bdcan1.send_message('0x096', msg_data, console=None)
            time.sleep(0.002)
        bdcan1.Uninitialize(PB.PCAN_USBBUS1)

    @staticmethod
    def high_load(*args, **kwargs):
        logger.info('控制XCU高负载, CPU使用率90%以上')
        t1 = Thread(target=make_xcu_with_high_load)
        t2 = Thread(target=get_last_upgrade_status, args=args, kwargs=kwargs)
        t1.start()
        time.sleep(10)
        t2.start()
        t1.join()
        t2.join()

    @staticmethod
    def space_overflow(ota, vin, veh_series, variable_veh_model, version, upgrade_data_list, stage,
                       source_type):
        logger.info('构造ota 空间容量溢出')
        res = xcu_client.execute_cmd('cd /ota/state && dd if=/dev/zero of=temp.doc  bs=1048576 count=5100')
        logger.info(res)
        xcu_client.execute_cmd('sync')
        assert_fail = False
        try:
            task_id, version = do_standard_ota_task_publish(ota, vin, veh_series, variable_veh_model, version,
                                                            upgrade_data_list, stage=stage,
                                                            source_type=source_type, keyword='space_overflow')
        except Exception as e:
            logger.error(e)
            assert_fail = True
        logger.info('移除临时大容量文件 temp.doc')
        xcu_client.execute_cmd('rm /ota/state/temp.doc')
        xcu_client.execute_cmd('sync')
        assert assert_fail == False
        logger.info('等待5分钟')
        time.sleep(500)
        # 推送任务
        task_id = create_task(ota, vin, veh_series, variable_veh_model, version)
        # 查询任务推送详情
        get_task_status(ota, task_id)
        # 查看下载详情
        status_ok, task_status = get_vehicle_current_download_status(ota, vin, task_id)
        assert status_ok == True, 'space_overflow 重新下载状态异常'

    @staticmethod
    def restart_app(end_waiting=15):
        """
        重启fota app
        Args:
            end_waiting: 重启后等待多少秒恢复
        Returns:

        """
        logger.info('重启fota app')
        pid = xcu_cmd.get_pid_by_name(xcu_client, 'fota')
        if pid:
            xcu_client.execute_cmd(f'kill -9 {pid}')
            logger.info(f'进程{pid}, 重启完成, 等待 {end_waiting}秒')
        time.sleep(end_waiting)

    @staticmethod
    def cwd_inject(filepath):
        try:
            config_word = UpgradeActionKeyword.cwd_inject.config_word
        except:
            config_word = "0740052100FFFF09D91F1FFF0203E3FFFF"
        try:
            download_pass = UpgradeActionKeyword.cwd_inject.download_pass
        except:
            download_pass = True
        logger.info(f'配置字注入: {config_word}')
        logger.info(f'预期下载结果: {download_pass}')
        remote_temp_dir = '/app_data/temp_vcs_test'
        shell_lines = [' #!/bin/bash\n',
                       'export LD_LIBRARY_PATH=:/apps/x01/lib:/framework/lib:/usr/lib:/lib\n',
                       'cd /apps/x01/bin/\n',
                       './uds_doip_cpp_test <<EOF\n',
                       '2\n',
                       f'{config_word}\n',
                       '0\n',
                       'EOF\n']
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(shell_lines)
        change_dos_to_unix(filepath)
        try:
            xcu_client.mkdir(remote_temp_dir)
        except:
            pass
        filename = filepath.split('\\')[-1]
        remote_shell_filepath = remote_temp_dir + '/' + filename
        xcu_client.sftp_put(filepath, remote_shell_filepath)
        cmd = f'cd {remote_temp_dir} && sh ./{filename}'
        xcu_client.execute_interact_cmd(cmd, console=False)
        time.sleep(5)
        ActionKeywordMethod.power_on_off()

    @staticmethod
    def hu_net(status):
        """
        控制网络开关
        on：打开网络
        off：关闭网络
        """
        if 'on' == status:
            logger.info('打开网络')
            os.system('adb shell svc data enable')
            time.sleep(2)
            os.system('adb shell svc data enable')
            time.sleep(5)
        if 'off' == status:
            logger.info('关闭网络')
            os.system('adb shell svc data disable')
            time.sleep(3)

    @staticmethod
    def xcu_net(status):
        """
        控制XCU断网重连
        on 打开网络
        off 关闭网络
        """
        logger.info('控制XCU断网重连:' + status)
        if status == 'off':
            xcu_client.execute_cmd('route del default')
            time.sleep(3)
        if status == 'on':
            xcu_client.execute_cmd('route add default gw 172.31.60.54')
            time.sleep(20)

    @staticmethod
    def power_on_off_stepped(waiting=1):
        logger.info(f'控制台架上下电, 中间等待 {waiting} 秒')
        usb_relay = USBRelay()
        usb_relay.make_lifecycle(middle_waiting_time=1)
        usb_relay.close_handle()
        time.sleep(waiting)  # XCU启动后初始化时间

    @staticmethod
    def log_notify_upload():
        logger.info('check log_notify_upload')
        res = xcu_client.execute_cmd('ls /log/log_notify_upload')
        if 'No such file or directory' in str(res):
            logger.info('log_notify_upload not found')
            res = xcu_client.execute_cmd('ls /log')
            logger.info(str(res))
            return False
        return True

    @staticmethod
    def check_crash():
        logger.info('check crash')
        res = xcu_client.execute_cmd('ls /log/Crash/Coredump/')
        if ('lianshan' in str(res)) | ('fota' in str(res)) | ('uchannel' in str(res)):
            dir = TimeOperation.get_datetime_string(fmt="%Y%m%d%H%M%S")
            path = 'D:\crash\\' + dir
            os.mkdir(path)
            xcu_client.sftp_download_files('/log/Crash/Coredump/', path)
            logger.info('found crash')
            return False

        # logger.info('check SWID')
        # bd = str(upgrade_data_list).split('-ID')[1].split('-')[0]
        # logger.info(f'bd: {bd}')
        # if bd.startswith('0'):
        #     bd = bd[1:]
        # SWID = xcu_client.execute_cmd('find /log/MCU/* -type f -mmin -5 -exec grep -H "" {} + | grep "SWID"')
        # if 'SWID[' + bd not in str(SWID):
        #     logger.info('SWID lost，下载MCU日志')
        #     logger.info(str(SWID))
        #     xcu_client.sftp_download_files('/log/MCU/', path)
        #     return False
        return True


class VerifyKeywordMethod:
    @staticmethod
    def vehicle_mode(filepath, ota_mode):
        """
            0x0: No Request
            0x1: Normal Mode 正常模式
            0x2: Factory Mode 工厂模式
            0x3: Logistic Mode 物流模式
            0x4: Exhibition Mode 展车模式
            0x5: OTA Mode 1 OTA模式1
            0x6: OTA Mode 2 OTA模式2
            0x7: Repair Mode 维修模式

            ota_mode True OTA模式1
            ota_mode False 正常模式
        Args:
            filepath: 生成的shell脚本本地路径
        Returns:

        """
        logger.info("verify 车辆模式")
        veh_mode_info = {
            'XCUVehMd_Inner': 0,
            'FBCMVehModSts': 0,
            'RBCMVehModSts': 0
        }
        #  sdc_toolbox 工具会影响模式切换
        # signal_nums = 3
        # signal_values = 'XCUVehMd_Inner\nFBCMVehModSts\nRBCMVehModSts\n'
        # remote_temp_dir = '/app_data/temp_vcs_test'
        # shell_lines = [' #!/bin/bash\n',
        #                'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../lib\n',
        #                'cd /apps/x01/bin/\n',
        #                './sdc_toolbox <<EOF\n',
        #                '1\n',
        #                f'{signal_nums}\n',
        #                signal_values,  # 'XCUPwrMd_Inner 2\n'
        #                '0\n',
        #                '0\n',
        #                'EOF\n']
        # with open(filepath, 'w', encoding='utf-8') as f:
        #     f.writelines(shell_lines)
        # change_dos_to_unix(filepath)
        # try:
        #     xcu_client.mkdir(remote_temp_dir)
        # except:
        #     pass
        # filename = filepath.split('\\')[-1]
        # remote_shell_filepath = remote_temp_dir + '/' + filename
        # xcu_client.sftp_put(filepath, remote_shell_filepath)
        # cmd = f'cd {remote_temp_dir} && sh ./call_sdc_toolbox.sh'
        bdcan1 = PCAN(PB.PCAN_USBBUS1, PB.PCAN_BAUD_2M, CanFD=True)
        time_now = time.time()
        while time.time() - time_now <= 60:
            if (veh_mode_info['XCUVehMd_Inner'] != 0) and (veh_mode_info['FBCMVehModSts'] != 0) and (
                    veh_mode_info['RBCMVehModSts'] != 0):
                break
            msg = bdcan1.read_message()
            if msg:
                if ota_mode:
                    if msg[2] == '0x397':
                        if msg[4][2][2] == '5':
                            veh_mode_info['XCUVehMd_Inner'] = msg[4][2][2]
                    if msg[2] == '0x509':  # FBCM整车模式
                        if msg[4][0][2] == 'a':
                            veh_mode_info['FBCMVehModSts'] = '5'
                    if msg[2] == '0x53c':  # RBCM整车模式
                        if msg[4][4][3] == '2':
                            veh_mode_info['RBCMVehModSts'] = '5'
                else:
                    if msg[2] == '0x397':
                        if msg[4][2][2] == '1':
                            veh_mode_info['XCUVehMd_Inner'] = msg[4][2][2]
                    if msg[2] == '0x509':  # FBCM整车模式
                        if msg[4][0][2] == '2':
                            veh_mode_info['FBCMVehModSts'] = '1'
                    if msg[2] == '0x53c':  # RBCM整车模式
                        if msg[4][4][3] == '0':
                            veh_mode_info['RBCMVehModSts'] = '1'
        #  sdc_toolbox 工具会影响模式切换
        # while time.time() - time_now <= 120:
        #     time.sleep(2)
        #     if ota_mode:
        #         if veh_mode_info['FBCMVehModSts'] == '5' and veh_mode_info['RBCMVehModSts'] == '5':
        #             break
        #     else:
        #         if veh_mode_info['FBCMVehModSts'] == '1' and veh_mode_info['RBCMVehModSts'] == '1':
        #             break
        # res = xcu_client.execute_interact_cmd(cmd, console=False)
        # for i in res.split('\r\n'):
        #     if 'XCUVehMd_Inner' in i and 'FBCMVehModSts' in i and 'RBCMVehModSts' in i:  # XCUVehMd_Inner: 1, FBCMVehModSts: 1, RBCMVehModSts: 1,
        #         signal_values = [j.split(' ')[-1] for j in i.split(',')]  # 提取信号值
        #         if ota_mode:
        #             if signal_values[1] == '5' and signal_values[2] == '5':
        #                 veh_mode_info['FBCMVehModSts'] = signal_values[1]
        #                 veh_mode_info['RBCMVehModSts'] = signal_values[2]
        #                 break
        #         else:
        #             if signal_values[1] == '1' and signal_values[2] == '1':
        #                 veh_mode_info['FBCMVehModSts'] = signal_values[1]
        #                 veh_mode_info['RBCMVehModSts'] = signal_values[2]
        #                 break
        bdcan1.Uninitialize(PB.PCAN_USBBUS1)
        logger.info(veh_mode_info)
        return veh_mode_info

    @staticmethod
    def xcu_work_mode5(local_filepath):
        """
        xcu_work_mode5
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify session program")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/ -type f -mmin -20 -exec grep -H "all_ecu_work_mode_feedback" {} + ')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '{"ECUName": "XCU", "Workmode": 5}')
        if content_q:
            logger.info('XCU Workmode 5')
            return '5'
        else:
            logger.info('XCU Workmode 5 not found')
            return '0'

    @staticmethod
    def a_core_cw():
        """
        获取存储在XCU A核中的配置字
        Returns:
            {'vehicleConfigWord': '0740052100FFFF0901030303020303FFFF'}
        """
        logger.info("verify XCU A核配置字")
        res = xcu_cmd.get_config_word_from_acore(xcu_client)
        logger.info(res)
        return res

    @staticmethod
    def xcu_version():
        logger.info("verify XCU版本信息")
        res = xcu_cmd.get_print_version(xcu_client)
        logger.info(res)
        return res

    @staticmethod
    def cloud_version(ota, vin):
        logger.info("查询云端版本信息")
        cloud_version = {
            'ecuVersion': '',
            'currentSoftwareVersion': '',
            'XCU_A': '',
            'XCU_M': ''
        }
        res = ota.get_cloud_version(vin)
        if res['data']:
            for ecuVersion in res['data']['ecuVersionList']:
                if 'XCU' in str(ecuVersion):
                    cloud_version['ecuVersion'] = ecuVersion['ecuVersion']
                    cloud_version['currentSoftwareVersion'] = ecuVersion['currentSoftwareVersion']
                    for subSystemVersion in ecuVersion['subSystemVersionList']:
                        if 'XCU_A' in str(subSystemVersion):
                            cloud_version['XCU_A'] = {
                                'subSystemVersion': subSystemVersion['subSystemVersion'],
                                'currentVersion': subSystemVersion['currentVersion']
                            }
                        if 'XCU_M' in str(subSystemVersion):
                            cloud_version['XCU_M'] = {
                                'subSystemVersion': subSystemVersion['subSystemVersion'],
                                'currentVersion': subSystemVersion['currentVersion']
                            }
                    break
        return cloud_version

    @staticmethod
    def bus_banned(local_filepath):
        """
        正则匹配升级过程中是否发送功能寻址 28 xx 03 总线禁言
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify 总线禁言")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '07 1e 0f 02 00 28 83 03')  # 禁言请求
        content_w05 = search_by_keyword(local_filepath, 'e4 ff 0f 02 00 28 83 03')  # 禁言请求
        content_r = search_by_keyword(local_filepath, '0f 02 7f 28')  # 禁言请求负响应
        content_3e = search_by_keyword(local_filepath, 'e4 ff 0f 02 00 3e 80')  # 诊断仪周期发送3E 80
        if (not content_q) and (not content_w05):
            logger.info('未找到 禁言请求')
            return False
        if not content_3e:
            logger.info('诊断仪周期发送3E 80 失败')
            return False
        if content_r:
            logger.info('找到 禁言请求负响应，不符合预期')
            return False
        return True

    @staticmethod
    def dtc_banned(local_filepath):
        """
        OTA升级前禁dtc
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify 禁止dtc")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, 'e4 ff 0f 02 00 85 82')  # 禁止dtc 请求
        # content_rs = search_by_keyword(local_filepath, '0f 02 c5 82')  # 禁止dtc 正响应  没有正响应，响应抑制
        content_rf = search_by_keyword_ota(local_filepath, '7f 85')  # 禁止dtc 负响应
        if not content_q:
            logger.info('未找到 禁止dtc 请求')
            return False
        # if not content_rs:
        #     logger.error('未找到 禁止dtc 正响应')
        #     return False
        if content_rf:
            logger.info(f'找到 禁止dtc 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 禁止dtc 请求 {content_q[-1]}')
        # logger.info(f'找到 禁止dtc 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def read_ecu_version(local_filepath):
        """
        读取ECU版本号
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify read ecu version")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '0f 02 00 22 f1 95')  # read ecu version 请求
        content_rs = search_by_keyword(local_filepath, '0f 02 62 f1 95')  # read ecu version 正响应
        content_rf = search_by_keyword_ota(local_filepath, '7f 22', '36 83 7f')  # read ecu version 负响应，去除36影响
        if not content_q:
            logger.info('未找到 read ecu version 请求')
            return False
        if not content_rs:
            logger.info('未找到 read ecu version 正响应')
            return False
        if content_rf:
            logger.info(f'找到 read ecu version 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 read ecu version 请求 {content_q[-1]}')
        # logger.info(f'找到 read ecu version 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def session_program(local_filepath):
        """
        session program
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify session program")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '0f 02 00 10 02')  # session program 请求
        content_rs = search_by_keyword(local_filepath, '0f 02 50 02')  # session program 正响应
        content_rf = search_by_keyword_ota(local_filepath, '7f 10')  # session program 负响应
        if not content_q:
            logger.info('未找到 session program 请求')
            return False
        if not content_rs:
            logger.info('未找到 session program 正响应')
            return False
        if content_rf:
            logger.info(f'找到 session program 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 session program 请求 {content_q[-1]}')
        # logger.info(f'找到 session program 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def security_seed_key(local_filepath):
        """
        Security Req Seed
        Security Send Key
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify Security Seed And Key")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q_seed = search_by_keyword(local_filepath, '0f 02 00 27 09')  # ECU Security Req Seed 请求
        content_r_seed = search_by_keyword(local_filepath, '0f 02 67 09')  # ECU Security Req Seed 正响应
        content_q_key = search_by_keyword(local_filepath, '0f 02 00 27 0a')  # ECU Security Send Key 请求
        content_r_key = search_by_keyword(local_filepath, '0f 02 67 0a')  # ECU Security Send Key 正响应
        content_rf = search_by_keyword_ota(local_filepath, '7f 27')  # Security Seed And Key 负响应
        content_rf_35 = search_by_keyword(local_filepath, '67 0a 35')  # invalidKey
        if not content_q_seed:
            logger.info('未找到 ECU Security Req Seed 请求')
            return False
        if not content_r_seed:
            logger.info('未找到 ECU Security Req Seed 正响应')
            return False
        if not content_q_key:
            logger.info('未找到 ECU Security Req Key 请求')
            return False
        if not content_r_key:
            logger.info('未找到 ECU Security Req Key 正响应')
            return False
        if content_rf:
            logger.info(f'找到 Security Seed And Key 负响应 {content_rf[-1]}')
            return False
        if content_rf_35:
            logger.info(f'找到 invalidKey {content_rf_35[-1]}')
            return False
        # logger.info(f'找到 ECU Security Req Seed 请求 {content_q_seed[-1]}')
        # logger.info(f'找到 ECU Security Req Seed 正响应 {content_r_seed[-1]}')
        # logger.info(f'找到 ECU Security Req Key 请求 {content_q_key[-1]}')
        # logger.info(f'找到 ECU Security Req Key 正响应 {content_r_key[-1]}')
        return True

    @staticmethod
    def check_integrity(local_filepath):
        """
        check integrity
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        return True
        logger.info("verify check integrity")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '31 01 f0 01')  # check integrity 请求
        content_rs = search_by_keyword(local_filepath, '0f 02 71 01 f0 01')  # check integrity 正响应
        content_rf = search_by_keyword_ota(local_filepath, '7f 31')  # check integrity 负响应
        content_rf_01 = search_by_keyword(local_filepath, '71 01 f0 01 01')  # incorrectResult_CRCFailure
        content_rf_02 = search_by_keyword(local_filepath, '71 01 f0 01 02')  # incorrectResult_SignatureFailure
        if not content_q:
            logger.info('未找到 check integrity 请求')
            return False
        if not content_rs:
            logger.info('未找到 check integrity 正响应')
            return False
        if content_rf:
            logger.info(f'找到 check integrity 负响应 {content_rf[-1]}')
            return False
        if content_rf_01:
            logger.info(f'找到 incorrectResult_CRCFailure {content_rf_01[-1]}')
            return False
        if content_rf_02:
            logger.info(f'找到 incorrectResult_SignatureFailure {content_rf_02[-1]}')
            return False
        # logger.info(f'找到 check integrity 请求 {content_q[-1]}')
        # logger.info(f'找到 check integrity 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def check_dependencies(local_filepath):
        """
        check dependencies
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify check dependencies")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '31 01 ff 01')  # check dependencies 请求
        content_rs = search_by_keyword(local_filepath, '0f 02 71 01 ff 01')  # check dependencies 正响应
        content_rf = search_by_keyword_ota(local_filepath, '7f 31')  # check dependencies 负响应
        content_3e = search_by_keyword(local_filepath, 'e4 ff 0f 02 00 3e 80')  # 诊断仪周期发送3E 80
        if not content_3e:
            logger.info('诊断仪周期发送3E 80 失败')
            return False
        if not content_q:
            logger.info('未找到 check dependencies 请求')
            return False
        if not content_rs:
            logger.info('未找到 check dependencies 正响应')
            return False
        if content_rf:
            logger.info(f'找到 check dependencies 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 check dependencies 请求 {content_q[-1]}')
        # logger.info(f'找到 check dependencies 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def write_fingerprint(local_filepath):
        """
        write fingerprint
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify write fingerprint")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '0f 02 00 2e f1 5a')  # write fingerprint 请求
        content_rs = search_by_keyword(local_filepath, '0f 02 6e f1 5a')  # write fingerprint 正响应
        content_rf = search_by_keyword_ota(local_filepath, '7f 2e')  # write fingerprint 负响应
        if not content_q:
            logger.info('未找到 write fingerprint 请求')
            return False
        if not content_rs:
            logger.info('未找到 write fingerprint 正响应')
            return False
        if content_rf:
            logger.info(f'找到 write fingerprint 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 write fingerprint 请求 {content_q[-1]}')
        # logger.info(f'找到 write fingerprint 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def session_extended(local_filepath):
        """
        session extended
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify session extended")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '0f 02 00 10 83')  # session extended 请求
        # content_rs = search_by_keyword(local_filepath, '0f 02 50 83')  # session extended 没有正响应 响应抑制
        content_rf = search_by_keyword_ota(local_filepath, '7f 10')  # session extended 负响应
        if not content_q:
            logger.info('未找到 session extended 请求')
            return False
        # if not content_rs:
        #     logger.info('未找到 session extended 正响应')
        #     return False
        if content_rf:
            logger.info(f'找到 session extended 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 session extended 请求 {content_q[-1]}')
        # logger.info(f'找到 session extended 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def read_lin_version(local_filepath):  # http://jira.it.chehejia.com/browse/MSCRUM-35264 已删除该功能,验证无此功能
        """
        read lin version
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify read lin version")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '0f 02 00 b2 32')  # read lin version 请求
        content_rs = search_by_keyword(local_filepath, '0f 02 f2 05 00')  # read lin version 没有正响应 响应抑制
        content_rf = search_by_keyword_ota(local_filepath, '7f b2')  # read lin version 负响应
        if not content_q:
            logger.info(f'未找到 read lin version 请求 {content_q[-1]}')
            return False
        if not content_rs:
            logger.info(f'未找到 read lin version 正响应 {content_rs[-1]}')
            return False
        if content_rf:
            logger.info(f'找到 read lin version 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 read lin version 请求 {content_q[-1]}')
        # logger.info(f'找到 read lin version 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def lin_8227(local_filepath):  # http://jira.it.chehejia.com/browse/MSCRUM-37624 Post脚本增加读取LIN版本号功能
        """
        read lin version
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify lin 8227 service")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q_01 = search_by_keyword(local_filepath, '0f 02 0c 01 31 01 82 27')  # 8227 请求
        content_rs_01 = search_by_keyword(local_filepath, '0c 01 0f 02 71 01 82 27')  # 8227 正相應
        content_q_03 = search_by_keyword(local_filepath, '0f 02 0c 01 31 03 82 27')  # 8227 请求
        content_rs_03 = search_by_keyword(local_filepath, '0c 01 0f 02 71 03 82 27')  # 8227 正相應
        content_rf = search_by_keyword_ota(local_filepath, '7f 31')  # 8227 负响应
        if not content_q_01:
            logger.info(f'未找到 8227 请求 {content_q_01[-1]}')
            return False
        if not content_rs_01:
            logger.info(f'未找到 8227 正响应 {content_rs_01[-1]}')
            return False
        if not content_q_03:
            logger.info(f'未找到 8227 请求 {content_q_03[-1]}')
            return False
        if not content_rs_03:
            logger.info(f'未找到 8227 正响应 {content_rs_03[-1]}')
            return False
        if content_rf:
            logger.info(f'找到 8227 负响应 {content_rf[-1]}')
            return False
        return True

    @staticmethod
    def erase_memory(local_filepath):
        """
        erase memory
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify erase memory")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '31 01 ff 00')  # erase memory 请求
        content_rs = search_by_keyword(local_filepath, '0f 02 71 01 ff 00')  # erase memory 正响应
        content_rf = search_by_keyword_ota(local_filepath, '7f 31')  # erase memory 负响应
        if not content_q:
            logger.info('未找到 erase memory 请求')
            return False
        if not content_rs:
            logger.info('未找到 erase memory 正响应')
            return False
        if content_rf:
            logger.info(f'找到 erase memory 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 erase memory 请求 {content_q[-1]}')
        # logger.info(f'找到 erase memory 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def lin_reset(local_filepath):
        """
        lin reset
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify lin reset")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '0f 02 00 11 01')  # lin reset 请求
        content_rs = search_by_keyword(local_filepath, '0f 02 51 01')  # lin reset 正响应
        content_rf = search_by_keyword_ota(local_filepath, '7f 11')  # lin reset 负响应
        if not content_q:
            logger.info('未找到 lin reset 请求')
            return False
        if not content_rs:
            logger.info('未找到 lin reset 正响应')
            return False
        if content_rf:
            logger.info(f'找到 lin reset 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 lin reset 请求 {content_q[-1]}')
        # logger.info(f'找到 lin reset 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def clear_dtc(local_filepath):
        """
        正则匹配升级过程中是否发送功能寻址清故障码 总线禁言
        Args:
            local_filepath: uds.tag 日志本地存储路径
        Returns:
            boolean
        """
        logger.info("verify 后处理，清DTC")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            # res = xcu_client.execute_cmd('find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            res = xcu_client.execute_cmd('find /log/ -type f -mmin -20 -exec grep -H "commandTag" {} + ')
            f.writelines(res)
        # content_q = search_by_keyword(local_filepath, 'e4 ff 0f 02 00 14 ff ff ff')  # 功能寻址清故障码 请求
        # content_rs = search_by_keyword(local_filepath, '0f 02 54')  # 清故障码 正响应
        # content_rf = search_by_keyword(local_filepath, '7f 14', '36 7f 14')  # 清故障码 负响应，排除36 7f 14影响用例判断
        content_19 = search_by_keyword(local_filepath, '"commandTag":19')  # finish
        content_37 = search_by_keyword(local_filepath, '"commandTag":37')  # post
        if not content_19:
            logger.info('未找到 功能寻址清故障码finish')
            return False
        if not content_37:
            logger.info('未找到 功能寻址清故障码post')
            return False
        # logger.info(f'找到 功能寻址清故障码finish {content_19[-1]}')
        # logger.info(f'找到 功能寻址清故障码post {content_37[-1]}')
        return True

    @staticmethod
    def response_inhibition(local_filepath):
        logger.info("verify 10 81 响应抑制请求")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '0f 02 e4 ff 10 81')  # 响应抑制 请求
        # content_rs = search_by_keyword(local_filepath, '0f 02 50')  # 响应抑制 没有正响应，响应抑制
        content_rf = search_by_keyword_ota(local_filepath, '7f 10')  # 响应抑制 负响应
        if not content_q:
            logger.info('未找到 响应抑制 请求')
            return False
        # if not content_rs:
        #     logger.info('未找到 响应抑制 正响应')
        #     return False
        if content_rf:
            logger.info(f'找到 响应抑制 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 响应抑制 请求 {content_q[-1]}')
        # logger.info(f'找到 响应抑制 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def complete_frame(local_filepath):
        logger.info("verify uds升级不丢帧")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd('find /log/ -type f -mmin -20 -exec grep -H "Application.tag" {} + ')
            f.writelines(res)
        frame_list = [
            '0f 02 0c 01 10 03',
            '0c 01 0f 02 50 03',
            '0f 02 0c 01 27 01',
            '0c 01 0f 02 67 01',
            '0f 02 0c 01 27 02',
            '0c 01 0f 02 67 02',
        ]
        for frame_keyword in frame_list:
            is_found = search_by_keyword(local_filepath, frame_keyword)
            if not is_found:
                logger.info(f'not found frame: {frame_keyword}')
                return False
        logger.info('found all frame')
        return True

    @staticmethod
    def eth_log_package():
        logger.info("verify xcu fota 以太网报文完整打包")
        res = xcu_client.execute_cmd('ls /log/Comm/Fota/*pcap*')  # test.pacp1.gz
        pcap_list = res.strip('\n').split('\n')
        no_packaged_num = 0
        for i in pcap_list:
            if not i.endswith('.gz'):
                no_packaged_num += 1
        if no_packaged_num == 1:
            logger.info('校验报文打包通过')
            return True
        else:
            logger.info(f'校验完整报文打包失败, no_packaged_num: {no_packaged_num}')
            logger.info(res)
            return False

    @staticmethod
    def precompile_message(local_filepath):
        logger.info("verify uds预编译报文")
        with open(local_filepath, 'w', encoding='utf-8') as f:
            res = xcu_client.execute_cmd(
                'find /log/Application/* -type f -mmin -20 -exec grep -H "uds.tag" {} + | grep "q_dcs_socket_tcp_"')
            f.writelines(res)
        content_q = search_by_keyword(local_filepath, '0f 02 00 31 01 ff')  # uds预编译报文 请求
        content_rs = search_by_keyword(local_filepath, '0f 02 71 01 ff')  # uds预编译报文 正响应
        content_rf = search_by_keyword_ota(local_filepath, '7f 31')  # uds预编译报文 负响应
        if not content_q:
            logger.info('未找到 uds预编译报文 请求')
            return False
        if not content_rs:
            logger.info('未找到 uds预编译报文 正响应')
            return False
        if content_rf:
            logger.info(f'uds预编译报文 负响应 {content_rf[-1]}')
            return False
        # logger.info(f'找到 uds预编译报文 请求 {content_q[-1]}')
        # logger.info(f'找到 清uds预编译报文 正响应 {content_rs[-1]}')
        return True

    @staticmethod
    def verify_version(upgrade_data_list):
        """
        校验版本号
        Args:
            upgrade_data_list: ECU升级信息
        Returns:
            boolean
        """
        logger.info('verify 升级完成后的ECU版本号')
        verify_result = []
        bdcan1 = PCAN(PB.PCAN_USBBUS1, PB.PCAN_BAUD_2M, CanFD=True)
        for i in upgrade_data_list:
            verified_ver = i['ecuVersion']
            ecu_name = i['ecuName']
            if ecu_name == 'FBCM':
                msg_id = '0x68a'
            elif ecu_name == 'RBCM':
                msg_id = '0x68c'
            else:
                msg_id = None
            if msg_id:
                verify_pass = False
                time_now = time.time()
                while time.time() - time_now <= 10:
                    msg = bdcan1.read_message()
                    if msg:
                        if msg[2].lower() == msg_id:
                            msg_data = msg[-1]
                            ver_byte_high = msg_data[4]
                            ver_byte_low = msg_data[5]
                            logger.info(f'BDCAN1 读取ecu_name: {ecu_name}; msg_id: {msg_id};')
                            logger.info(
                                f'msg_data第4,5字节: {ver_byte_high} {ver_byte_low}; 被比对版本: {verified_ver}')
                            if ver_byte_high[-2:].lower() == verified_ver[:2].lower() and ver_byte_low[
                                                                                          -2:].lower() == verified_ver[
                                                                                                          2:].lower():
                                verify_pass = True
                                break
                verify_result.append(verify_pass)
        bdcan1.Uninitialize(PB.PCAN_USBBUS1)
        logger.info(f'verify_result: {verify_result}')
        if verify_result and False not in verify_result:
            logger.info('版本号校验成功')
            return True
        else:
            logger.info('未找到指定的ECU或版本号校验失败，请核对测试用例')
            return False

    @staticmethod
    def fingerprint_info(upgrade_data_list, max_time=1200):
        logger.info('verify 刷写过程中指纹信息写入（刷写日期）')
        verify_pass = False
        from datetime import datetime
        datetime_now = datetime.now()
        now_year = datetime_now.year - 2000
        now_month = datetime_now.month
        now_day = datetime_now.day
        bdcan1 = PCAN(PB.PCAN_USBBUS1, PB.PCAN_BAUD_2M, CanFD=True)  # RBCM
        blecan = PCAN(PB.PCAN_USBBUS2, PB.PCAN_BAUD_2M, CanFD=True)  # FBCM
        upgrade_ecus = []
        for i in upgrade_data_list:
            ecu_name = i['ecuName']
            upgrade_ecus.append(ecu_name)
        time_now = time.time()
        if 'FBCM' not in upgrade_ecus and 'RBCM' in upgrade_ecus:
            verify_2ef15a = False
            verify_6ef15a = False
            while time.time() - time_now <= max_time:
                msg = bdcan1.read_message()
                if msg:
                    if msg[2].lower() == '0x793':
                        msg_data = msg[-1]
                        if msg_data[2:5] == ['0x2e', '0xf1', '0x5a']:
                            logger.info(f'bdcan1 读取can msg: 0x793 {msg_data}')
                            msg_data_year = eval(msg_data[6])
                            msg_data_month = eval(msg_data[7])
                            msg_data_day = eval(msg_data[8])
                            if now_year == msg_data_year and now_month == msg_data_month and now_day == msg_data_day:
                                verify_2ef15a = True
                    elif msg[2].lower() == '0x79b':
                        msg_data = msg[-1]
                        if msg_data[1:4] == ['0x6e', '0xf1', '0x5a']:
                            logger.info(f'bdcan1 读取can msg: 0x79b {msg_data}')
                            verify_6ef15a = True
                if verify_2ef15a and verify_6ef15a:  # 收到肯定响应
                    verify_pass = True
                    break
        elif 'FBCM' in upgrade_ecus and 'RBCM' not in upgrade_ecus:
            verify_2ef15a = False
            verify_6ef15a = False
            while time.time() - time_now <= max_time:
                msg = blecan.read_message()
                if msg:
                    if msg[2].lower() == '0x792':
                        msg_data = msg[-1]
                        if msg_data[2:5] == ['0x2e', '0xf1', '0x5a']:
                            logger.info(f'blecan 读取can msg: 0x792 {msg_data}')
                            msg_data_year = eval(msg_data[6])
                            msg_data_month = eval(msg_data[7])
                            msg_data_day = eval(msg_data[8])
                            if now_year == msg_data_year and now_month == msg_data_month and now_day == msg_data_day:
                                verify_2ef15a = True
                    elif msg[2].lower() == '0x79a':
                        msg_data = msg[-1]
                        if msg_data[1:4] == ['0x6e', '0xf1', '0x5a']:
                            logger.info(f'blecan 读取can msg: 0x79a {msg_data}')
                            verify_6ef15a = True
                if verify_2ef15a and verify_6ef15a:  # 收到肯定响应
                    verify_pass = True
                    break
        elif 'FBCM' in upgrade_ecus and 'RBCM' in upgrade_ecus:
            verify_f_2ef15a = False
            verify_f_6ef15a = False
            verify_r_2ef15a = False
            verify_r_6ef15a = False
            verify_f = False
            verify_r = False
            while time.time() - time_now <= max_time:
                if not verify_f:
                    msg = blecan.read_message()
                    if msg:
                        if msg[2].lower() == '0x792':
                            msg_data = msg[-1]
                            if msg_data[2:5] == ['0x2e', '0xf1', '0x5a']:
                                logger.info(f'blecan 读取can msg: 0x792 {msg_data}')
                                msg_data_year = eval(msg_data[6])
                                msg_data_month = eval(msg_data[7])
                                msg_data_day = eval(msg_data[8])
                                if now_year == msg_data_year and now_month == msg_data_month and now_day == msg_data_day:
                                    logger.info('verify_f_2ef15a: True')
                                    verify_f_2ef15a = True
                        elif msg[2].lower() == '0x79a':
                            msg_data = msg[-1]
                            if msg_data[1:4] == ['0x6e', '0xf1', '0x5a']:
                                logger.info(f'blecan 读取can msg: 0x79a {msg_data}')
                                logger.info('verify_f_6ef15a: True')
                                verify_f_6ef15a = True
                    if verify_f_2ef15a and verify_f_6ef15a:
                        verify_f = True
                if not verify_r:
                    msg = bdcan1.read_message()
                    if msg:
                        if msg[2].lower() == '0x793':
                            msg_data = msg[-1]
                            if msg_data[2:5] == ['0x2e', '0xf1', '0x5a']:
                                logger.info(f'bdcan1 读取can msg: 0x793 {msg_data}')
                                msg_data_year = eval(msg_data[6])
                                msg_data_month = eval(msg_data[7])
                                msg_data_day = eval(msg_data[8])
                                if now_year == msg_data_year and now_month == msg_data_month and now_day == msg_data_day:
                                    logger.info('verify_r_2ef15a: True')
                                    verify_r_2ef15a = True
                        elif msg[2].lower() == '0x79b':
                            msg_data = msg[-1]
                            if msg_data[1:4] == ['0x6e', '0xf1', '0x5a']:
                                logger.info(f'bdcan1 读取can msg: 0x79b {msg_data}')
                                logger.info('verify_r_6ef15a: True')
                                verify_r_6ef15a = True
                    if verify_r_2ef15a and verify_r_6ef15a:
                        verify_r = True
                if verify_f and verify_r:  # 收到肯定响应
                    verify_pass = True
                    break
        bdcan1.Uninitialize(PB.PCAN_USBBUS1)
        blecan.Uninitialize(PB.PCAN_USBBUS2)
        return verify_pass

    @staticmethod
    def check_time(offset=60):
        """
        校验刷写完成后的时间误差
        Args:
            offset: 时间误差，单位秒，默认10秒
        Returns:
        """
        res = xcu_cmd.check_xcu_system_time(xcu_client, offset=offset)
        return res

    @staticmethod
    def check_downgrade_status(ota, vin, version, max_time=1800):
        """
        验证向低版本升级失败
        """
        logger.info('开始向低版本升级')
        downgrade_status = True
        time_now = time.time()
        while time.time() - time_now < max_time:
            upgrade_status = ota.get_vehicle_last_upgrade_status(vin, version)
            time.sleep(5)
            if upgrade_status['data']:
                if upgrade_status['data']['errorType'] == 133 and upgrade_status['data']['upgradingEcuName'] == '' and \
                        upgrade_status['data']['eventType'] == 80:
                    downgrade_status = False
                    logger.info('向低版本升级失败，符合预期')
                    break
        return downgrade_status

    @staticmethod
    def check_addinfo_status(ota, vin, version, max_time=1800):
        """
        冰箱升级失败，检查addinfo
        """
        logger.info('冰箱升级失败，检查addinfo')
        addinfo_status = True
        format_time = ''
        type_95 = ''
        ecuNameLevel = ''
        time_now = time.time()
        while time.time() - time_now < max_time:
            if format_time == '':
                cmd1 = 'adb shell "logcat -vvv -d | grep com.lixiang.fota | grep addInfo | grep formatedTime"'
                res1 = os.popen(cmd1).read()
                if 'formatedTime' in str(res1):
                    format_time = 'formatedTime'
            if ecuNameLevel == '':
                cmd1 = 'adb shell "logcat -vvv -d | grep com.lixiang.fota | grep addInfo | grep ecuNameLevel"'
                res1 = os.popen(cmd1).read()
                if 'ecuNameLevel' in str(res1):
                    ecuNameLevel = 'ecuNameLevel'
            if type_95 == '':
                cmd2 = 'adb shell "logcat -vvv -d | grep com.lixiang.fota | grep \'type           : 95\'"'
                res2 = os.popen(cmd2).read()
                if 'type           : 95' in str(res2):
                    type_95 = 'type_95'
            upgrade_status = ota.get_vehicle_last_upgrade_status(vin, version)
            time.sleep(5)
            if upgrade_status['data']:
                if upgrade_status['data']['errorType'] == 133 and upgrade_status['data']['upgradingEcuName'] == '' and \
                        upgrade_status['data']['eventType'] == 80:
                    addinfo_status = False
                    if type_95 == '':
                        addinfo_status = True
                        logger.info('addinfo: type_95不符合预期')
                        break
                    if format_time == '':
                        addinfo_status = True
                        logger.info('addinfo: format_time不符合预期')
                        break
                    if ecuNameLevel == '':
                        addinfo_status = True
                        logger.info('addinfo: ecuNameLevel不符合预期')
                        break
                    logger.info('冰箱升级失败，addinfo符合预期')
                    break
        return addinfo_status

    @staticmethod
    def check_B2_32_status(ota, vin, version, max_time=1800):
        """
        升级LIN节点无B2 32的诊断报文
        """
        logger.info('开始升级LIN节点无B2 32的诊断报文')
        B2_32_status = True
        time_now = time.time()
        while time.time() - time_now < max_time:
            upgrade_status = ota.get_vehicle_last_upgrade_status(vin, version)
            time.sleep(5)
            if upgrade_status['data']:
                if upgrade_status['data']['upgradingEcuName'] == '' and upgrade_status['data']['errorType'] == 133 and \
                        upgrade_status['data'][
                            'eventType'] == 80:
                    logger.info('升级LIN节点失败')
                    B2_32_status = True
                if upgrade_status['data']['errorType'] == 0 and upgrade_status['data']['upgradingEcuName'] == '' and \
                        upgrade_status['data']['eventType'] == 75:
                    res = xcu_client.execute_cmd("cat /log/Application/* | grep -i \'B2 32\'")
                    if res is None:
                        logger.info('升级LIN节点无B2 32的诊断报文，符合预期')
                        B2_32_status = False
                    break
        return B2_32_status


def make_baseline(ota, version, veh_series, variable_veh_model, stage, source_type):
    logger.info(f'制作基线 {version}')
    variable_veh_models = []
    variable_veh_models.append(variable_veh_model)
    json_data = {
        "vehSeriesNo": veh_series,
        "variableVehModelNos": variable_veh_models,
        "version": version,
        "stage": stage,
        "sourceType": source_type
    }
    t = 0
    while t < 10:
        try:
            resp = ota.create_baseline(json_data)
            break
        except Exception as e:
            logger.info('create baseline error: ')
            logger.error(e.args)
            logger.info('traceback:')
            logger.error(e.with_traceback())
            time.sleep(15 + t)
            t = t + 1
    time.sleep(3)
    assert resp['code'] == 0
    baseline_id = resp['data']
    return baseline_id


def get_ecu_list_info(ota, veh_series, variable_veh_model, stage):
    logger.info('获取车型基线版本列表')
    params = {
        'vehSeries': veh_series,
        'vehVariableModel': variable_veh_model,
        'stage': stage,
        'isDeleted': False
    }
    baseline_version_list_info = ota.get_vehicle_baseline_version_list(params)
    ecu_list_info = ota.get_ecu_list(veh_series, variable_veh_model)
    assert baseline_version_list_info['code'] == 0, f'基线版本信息获取异常'
    assert ecu_list_info['code'] == 0, 'ECU列表获取异常'
    return ecu_list_info


def make_package(ota, vin, veh_series, variable_veh_model, version, source_type, upgrade_data_list):
    topology_info = ota.get_topology_by_vin(vin)
    time.sleep(1)
    logger.info('开始制包')
    variable_veh_models = []
    variable_veh_models.append(variable_veh_model)
    package_data = {  # 这里是user需要传的参数，要结合上面返回的数据
        'vehSeriesNo': veh_series,
        'variableVehModelNos': variable_veh_models,
        'version': version,
        'isMakeDelta': False,  # 是否制作增量包
        'makeDeltaVersions': [],
        'sourceType': source_type,
        'dataList': upgrade_data_list
    }
    post_data = OTAService.calculate_create_package_data_v2(topology_info, package_data)
    time.sleep(1)
    t = 0
    while t < 10:
        try:
            resp = ota.create_package(post_data)
            break
        except Exception as e:
            logger.info('create package error: ')
            logger.error(e.args)
            logger.info('traceback:')
            logger.error(e.with_traceback())
            time.sleep(15 + t)
            t = t + 1
    time.sleep(3)
    assert resp['code'] == 0, f'制包异常: {resp}'


def get_make_package_result(ota, veh_series, variable_veh_model, version):
    logger.info('查询制包结果')
    make_package_ok = False
    time_now = time.time()
    while time.time() - time_now <= 300:
        try:
            res = ota.get_last_create_record(veh_series, variable_veh_model, version)
        except Exception as e:
            logger.info('get_last_create_record error, try again')
            logger.info(e.args)
            time.sleep(5)
            res = ota.get_last_create_record(veh_series, variable_veh_model, version)
        time.sleep(5)
        if res['data']['status'] == 'SUCCESS':
            make_package_ok = True
            break
    assert make_package_ok == True, '查询制包结果异常'


def edit_baseline_desc_info(ota, baseline_id, veh_series, variable_veh_model, version):
    logger.info('获取基线描述信息')
    t = 0
    while t < 10:
        try:
            desc_info = ota.get_baseline_desc_info(baseline_id)
            break
        except Exception as e:
            logger.error(e.args)
            logger.info('with_traceback:')
            logger.error(e.with_traceback())
            time.sleep(15 + t)
            t = t + 1
    assert desc_info['code'] == 0, f'获取基线描述信息异常: {desc_info}'
    logger.info('编辑基线描述信息')
    t = 0
    while t < 10:
        try:
            resp = ota.modify_baseline_desc_info(desc_info['data'], veh_series, variable_veh_model, version)
            break
        except Exception as e:
            logger.error(e.args)
            logger.info('with_traceback:')
            logger.error(e.with_traceback())
            time.sleep(15 + t)
            t = t + 1
    assert resp['code'] == 0, f'编辑基线描述信息异常: {resp}'


def create_task(ota, vin, veh_series, variable_veh_model, version):
    logger.info('创建升级任务')
    vin_list = []
    vin_list.append(vin)
    post_data = {
        'executeType': 1,  # 立即执行
        'taskName': ota.desc_str,
        'taskRemark': ota.desc_str,
        'taskType': 5,  # 测试任务
        'upgradeType': 1,  # 普通升级
        'vehSeriesNo': veh_series,
        'vehVariableModelNo': variable_veh_model,
        'version': version,
        'vinList': vin_list
    }
    logger.info('create_task:')
    t = 0
    while t < 10:
        try:
            resp = ota.create_upgrade_task(post_data)
            break
        except Exception as e:
            logger.error(e.args)
            time.sleep(15 + t)
            t = t + 1
    assert resp['code'] == 0, f'创建升级任务异常: {resp}'
    task_id = resp['data']
    return task_id


def get_task_status(ota, task_id, max_time=300):
    logger.info('查询任务推送详情')
    task_publish_ok = False
    time_now = time.time()
    while time.time() - time_now < max_time:
        try:
            task_detail = ota.get_upgrade_task_details(task_id)
        except Exception as e:
            logger.info('get_upgrade_task_details error, try again')
            logger.info(e.args)
            time.sleep(5)
            task_detail = ota.get_upgrade_task_details(task_id)
        if task_detail['data']['isExecuted']:
            task_publish_ok = True
            break
        time.sleep(2)
    assert task_publish_ok == True, f'查询任务推送详情异常: {task_publish_ok}'


def get_vehicle_current_download_status(ota, vin, task_id, max_time=1200):
    """本质是推送任务以后，XCU下载升级包的完成状态"""
    logger.info('查询车辆当前升级状态（下载）')
    status_ok = False
    time_now = time.time()
    task_status = ota.get_upgrade_task_status(task_id, vin)
    time.sleep(5)
    while time.time() - time_now < max_time:
        task_status = ota.get_upgrade_task_status(task_id, vin)
        if task_status['data']:
            if task_status['data']['upgradeStatusTypeName'] == '提示状态' and task_status['data'][
                'upgradeStatusType'] == 35:
                status_ok = True
                break
        time.sleep(20)
    return status_ok, task_status


def get_vehicle_current_download_status_in_cancel_task(ota, vin, version, task_id, max_time=1200):
    """
    特殊要求: 查询下载状态时取消升级任务
    """
    logger.info('查询车辆当前升级状态（下载），并取消升级任务')
    try:
        cancel_timing = UpgradeActionKeyword.cancel_upgrade.cancel_timing
    except:
        cancel_timing = 1
    status_ok = False
    time_now = time.time()
    canceled = 0  # 已取消过，0代表没有
    if cancel_timing == 0 and not canceled:  # 查询开始前
        issue_cancel_upgrade_command(ota, vin, version)
        canceled = 1
    task_status = ota.get_upgrade_task_status(task_id, vin)
    while time.time() - time_now < max_time:
        task_status = ota.get_upgrade_task_status(task_id, vin)
        if task_status['data']:
            if task_status['data']['upgradeStatusTypeName'] == '无任务状态' \
                    and task_status['data']['upgradeStatusType'] == 0 \
                    and cancel_timing in (0, 1) \
                    and canceled == 1:  # 下载任务已经被取消，变为无任务状态
                break
            # 刚开始下载时
            elif task_status['data']['upgradeStatusTypeName'] == '开始下载' \
                    and task_status['data']['upgradeStatusType'] == 10 \
                    and cancel_timing == 1 \
                    and not canceled:
                issue_cancel_upgrade_command(ota, vin, version)  # 下发取消升级指令
                canceled = 1
            # 防止下载太快
            elif task_status['data']['upgradeStatusTypeName'] == '提示状态' \
                    and task_status['data']['upgradeStatusType'] == 35 \
                    and cancel_timing == 1 \
                    and not canceled:
                issue_cancel_upgrade_command(ota, vin, version)  # 下发取消升级指令
                canceled = 1
            elif task_status['data']['upgradeStatusTypeName'] == '提示状态' \
                    and task_status['data']['upgradeStatusType'] == 35:
                status_ok = True
                break
        time.sleep(5)
    if cancel_timing == 2 and not canceled:  # 查询结束后
        issue_cancel_upgrade_command(ota, vin, version)
    # assert status_ok == True  # 这块不能断言，会影响后续流程
    task_status = ota.get_upgrade_task_status(task_id, vin)
    return status_ok, task_status


def get_vehicle_current_download_status_in_recreate_task(ota, vin, veh_series, variable_veh_model, version, task_id,
                                                         upgrade_data_list,
                                                         max_time=300, stage='TEST', source_type='VCTD'):
    logger.info('查询车辆当前升级状态（下载），并重新创建升级下载任务')
    try:
        recreate_timing = UpgradeActionKeyword.recreate_task.recreate_timing
    except:
        recreate_timing = 1
    if (recreate_timing == 0) or (recreate_timing == 1):  # 车端有多个同版本升级任务抛弃后面任务的逻辑,用例去掉recreate_timing=0场景
        recreate_timing = 2
    status_ok = False
    time_now = time.time()
    recreated = 0  # 已创建过，0代表没有
    task_status = ota.get_upgrade_task_status(task_id, vin)
    task_id = task_id
    while time.time() - time_now < max_time:
        task_status = ota.get_upgrade_task_status(task_id, vin)
        if task_status['data']:
            # 刚开始下载时
            if task_status['data']['upgradeStatusTypeName'] == '开始下载' \
                    and task_status['data']['upgradeStatusType'] == 10 \
                    and recreate_timing in (0, 2) \
                    and not recreated:
                if recreate_timing == 0:
                    task_id = create_task(ota, vin, veh_series, variable_veh_model, version)  # 推送任务
                    recreated = 1
                elif recreate_timing == 2:
                    version = '0.0.1-' + TimeOperation.get_datetime_string(fmt="%Y%m%d%H%M%S")[2:]  # 当前升级的基线版本
                    baseline_id = make_baseline(ota, version, veh_series, variable_veh_model, stage, source_type)
                    # 开始制包
                    make_package(ota, vin, veh_series, variable_veh_model, version, source_type, upgrade_data_list)
                    # 查询制包结果
                    get_make_package_result(ota, veh_series, variable_veh_model, version)
                    # 获取和编辑基线描述信息
                    edit_baseline_desc_info(ota, baseline_id, veh_series, variable_veh_model, version)
                    # 推送任务
                    task_id = create_task(ota, vin, veh_series, variable_veh_model, version)
                    recreated = 1
                # 查询任务推送详情
                get_task_status(ota, task_id)  # 查询任务推送详情
            # 防止刚开始下太快
            elif task_status['data']['upgradeStatusTypeName'] == '提示状态' \
                    and task_status['data']['upgradeStatusType'] == 35 \
                    and recreate_timing in (0, 2) \
                    and not recreated:
                if recreate_timing == 0:
                    task_id = create_task(ota, vin, veh_series, variable_veh_model, version)  # 推送任务
                    recreated = 1
                elif recreate_timing == 2:  # 重新创建基线推送
                    version = '0.0.1-' + TimeOperation.get_datetime_string(fmt="%Y%m%d%H%M%S")[2:]  # 当前升级的基线版本
                    baseline_id = make_baseline(ota, version, veh_series, variable_veh_model, stage, source_type)
                    # 开始制包
                    make_package(ota, vin, veh_series, variable_veh_model, version, source_type, upgrade_data_list)
                    # 查询制包结果
                    get_make_package_result(ota, veh_series, variable_veh_model, version)
                    # 获取和编辑基线描述信息
                    edit_baseline_desc_info(ota, baseline_id, veh_series, variable_veh_model, version)
                    # 推送任务
                    task_id = create_task(ota, vin, veh_series, variable_veh_model, version)
                    recreated = 1
                # 查询任务推送详情
                get_task_status(ota, task_id)  # 查询任务推送详情
            # 真正下载完成
            elif task_status['data']['upgradeStatusTypeName'] == '提示状态' \
                    and task_status['data']['upgradeStatusType'] == 35:
                status_ok = True
                break
        time.sleep(5)
    if recreate_timing in (1, 3) and not recreated:  # 下载完成后
        if recreate_timing == 1:
            task_id = create_task(ota, vin, veh_series, variable_veh_model, version)  # 推送任务
        elif recreate_timing == 3:  # 重新创建基线推送
            version = '0.0.1-' + TimeOperation.get_datetime_string(fmt="%Y%m%d%H%M%S")[2:]  # 当前升级的基线版本
            baseline_id = make_baseline(ota, version, veh_series, variable_veh_model, stage, source_type)
            # 开始制包
            make_package(ota, vin, veh_series, variable_veh_model, version, source_type, upgrade_data_list)
            # 查询制包结果
            get_make_package_result(ota, veh_series, variable_veh_model, version)
            # 获取和编辑基线描述信息  这一步返回值报错 code:100001
            edit_baseline_desc_info(ota, baseline_id, veh_series, variable_veh_model, version)
            # 推送任务
            task_id = create_task(ota, vin, veh_series, variable_veh_model, version)
        get_task_status(ota, task_id)  # 查询任务推送详情
        status_ok, task_status = get_vehicle_current_download_status(ota, vin, task_id, max_time=max_time)
    return status_ok, task_status, task_id, version


def issue_upgrade_command(ota, vin, version):
    logger.info('功能安全确认')
    res = xcu_client.execute_cmd('cat /apps/x01/etc/sdc/dbc_lin_dbis_matrix.dbo')
    if 'VehModAvlOTAL2_Inner,uint8_t,uint8_t,1,0,0,255,' in res:
        xcu_client.execute_cmd('mount -o remount rw /apps')
        time.sleep(1)
        xcu_client.execute_cmd(
            f"""sed -i 's/VehModAvlOTAL2_Inner,uint8_t,uint8_t,1,0,0,255,/VehModAvlOTAL2_Inner,uint8_t,uint8_t,1,1,1,1,/g' /apps/x01/etc/sdc/dbc_lin_dbis_matrix.dbo""")
        xcu_client.execute_cmd('sync')
        logger.info('VehModAvlOTAL2_Inner 置为1')
    if 'XCUModAvlOTAL2_Inner,uint8_t,uint8_t,1,0,0,255,' in res:
        time.sleep(1)
        xcu_client.execute_cmd(
            f"""sed -i 's/XCUModAvlOTAL2_Inner,uint8_t,uint8_t,1,0,0,255,/XCUModAvlOTAL2_Inner,uint8_t,uint8_t,1,1,1,1,/g' /apps/x01/etc/sdc/dbc_lin_dbis_matrix.dbo""")
        xcu_client.execute_cmd('sync')
        logger.info('VehModAvlOTAL2_Inner 置为1')
        xcu_client.execute_cmd('reboot')
        time.sleep(5)
    logger.info(xcu_client.execute_cmd('ls /ota'))
    logger.info('下发升级命令')
    command_data = {
        'vin': vin,
        'targetVersion': version,
        'triggerType': 4,  # 自动化系统触发
        'upgradeType': 0,  # 立即升级
    }
    try:
        resp_data = ota.issue_upgrade_command(command_data)
    except Exception as e:
        logger.error(e.args)
        time.sleep(5)
        resp_data = ota.issue_upgrade_command(command_data)
    assert resp_data['code'] == 0, f'下发升级命令异常: {resp_data}'


def issue_cancel_upgrade_command(ota, vin, version):
    logger.info('下发取消升级命令')
    command_data = {
        'vin': vin,
        'targetVersion': version,
        'triggerType': 4,  # 自动化系统触发
        'upgradeType': 3,  # 取消升级
    }
    resp_data = ota.issue_upgrade_command(command_data)
    ActionKeywordMethod.reboot()
    assert resp_data['code'] == 0, f'下发取消升级命令异常: {resp_data}'


def get_last_upgrade_status(ota, vin, version, upgrade_data_list, max_time=1800, verify_time=False,
                            check_status=''):
    logger.info('查询升级状态')
    time.sleep(10)
    upgrade_ecu_set = set([i['systemName'] for i in upgrade_data_list])
    upgrade_success = False
    time_now = time.time()
    time_checked = False
    if check_status == 'check_downgrade':
        downgrade_status = VerifyKeywordMethod.check_downgrade_status(ota, vin, version, max_time=1800)
        assert downgrade_status == False, f'向低版本升级任务异常: {downgrade_status}'
    elif check_status == 'check_addinfo':
        addinfo_status = VerifyKeywordMethod.check_addinfo_status(ota, vin, version, max_time=1800)
        assert addinfo_status == False, f'冰箱升级失败，addinfo信息异常: {addinfo_status}'
    elif check_status == 'check_B2_32':
        B2_32_status = VerifyKeywordMethod.check_B2_32_status(ota, vin, version, max_time=1800)
        assert B2_32_status == False, f'升级LIN节点有B2 32的诊断报文，case fail: {B2_32_status}'
    else:
        while time.time() - time_now < max_time:
            upgrade_status = ota.get_vehicle_last_upgrade_status(vin, version)
            time.sleep(30)
            if upgrade_status['data']:
                if upgrade_status['data']['upgradingEcuName'] == '' and upgrade_status['data']['errorType'] == 133 and \
                        upgrade_status['data'][
                            'eventType'] == 80:
                    upgrade_success = False
                    break
                if set(upgrade_status['data']['upgradeCompleteEcuName'].split(',')) == upgrade_ecu_set and \
                        upgrade_status['data']['upgradingEcuName'] == '' and \
                        upgrade_status['data']['eventType'] == 75:
                    upgrade_success = True
                    break
                if verify_time and not time_checked:
                    if set(upgrade_status['data']['upgradeCompleteEcuName'].split(',')) == upgrade_ecu_set and \
                            upgrade_status['data']['upgradingEcuName'] == '' and \
                            upgrade_status['data']['eventType'] == 50:
                        time.sleep(30)
                        good_time = VerifyKeywordMethod.check_time()
                        if not good_time:
                            logger.info('XCU系统时间校验不通过')
                            upgrade_success = False
                        time_checked = True
        assert upgrade_success == True, f'查询升级状态异常: {upgrade_success}'


def do_standard_ota_task_publish(ota, vin, veh_series, variable_veh_model, version, upgrade_data_list, stage='TEST',
                                 source_type='VCTD', keyword=None):
    """
    task_type:
        Normal: 正常推送
        Cancel: 只取消
    """
    # 制作基线
    baseline_id = make_baseline(ota, version, veh_series, variable_veh_model, stage, source_type)
    # 开始制包
    make_package(ota, vin, veh_series, variable_veh_model, version, source_type, upgrade_data_list)
    # 查询制包结果
    get_make_package_result(ota, veh_series, variable_veh_model, version)
    # 获取和编辑基线描述信息
    edit_baseline_desc_info(ota, baseline_id, veh_series, variable_veh_model, version)
    # 推送任务
    task_id = create_task(ota, vin, veh_series, variable_veh_model, version)
    # 查询任务推送详情
    get_task_status(ota, task_id)
    # 用于XCU不在线
    if keyword == 'xcu_offline':
        # 下载过程中，XCU离线5分钟然后在线
        time.sleep(200)
        ActionKeywordMethod.xcu_net('on')
        time.sleep(60)
        ActionKeywordMethod.xcu_net('off')
        time.sleep(200)
        ActionKeywordMethod.xcu_net('on')
        time.sleep(60)
    # 查询车辆当前下载状态
    if keyword == 'cancel_upgrade':
        get_vehicle_current_download_status_in_cancel_task(ota, vin, version, task_id, max_time=660)
    elif keyword == 'recreate_task':
        status_ok, task_status, task_id, version = get_vehicle_current_download_status_in_recreate_task(
            ota, vin, veh_series, variable_veh_model, version, task_id, upgrade_data_list,
            max_time=660, stage='TEST', source_type='VCTD')
        assert status_ok == True, f'重新创建任务查询下载结果异常: {task_status}'
    elif keyword == 'space_overflow':
        status_ok, task_status = get_vehicle_current_download_status(ota, vin, task_id, max_time=180)
        assert status_ok == False, f'空间不足查询下载结果异常: {task_status}'
    elif keyword == 'cwd_inject':
        status_ok, task_status = get_vehicle_current_download_status(ota, vin, task_id, max_time=660)
        assert status_ok == True, f'配置字注入查询下载结果: {task_status}'
    elif keyword == 'cut_off_network':
        ActionKeywordMethod.hu_net('on')
        status_ok, task_status = get_vehicle_current_download_status(ota, vin, task_id, max_time=660)
        assert status_ok == True, f'断网重连查询下载结果: {task_status}'
    elif keyword == 'xcu_offline':
        status_ok, task_status = get_vehicle_current_download_status(ota, vin, task_id, max_time=660)
        assert status_ok == True, f'XCU不在线查询下载结果: {task_status}'
    else:
        status_ok, task_status = get_vehicle_current_download_status(ota, vin, task_id, max_time=7200)
        assert status_ok == True, f'查询下载结果异常: {task_status}'
    return task_id, version


def do_standard_ota_upgrade(vin, veh_series, variable_veh_model, upgrade_data_list, env='testtwo', stage='TEST',
                            source_type='VCTD'):
    """
    远程OTA升级
    Args:
        vin: 车辆识别号
        veh_series: 车系
        variable_veh_model: 变量车型
        upgrade_data_list: 制包数据信息列表
        env: testtwo环境; 其他环境暂不支持
        source_type: VCTD; 车云测试开发
        stage: TEST

    Returns:

    """
    ota = OTAService(env=env)
    version = '0.0.1-' + TimeOperation.get_datetime_string(fmt="%Y%m%d%H%M%S")[2:]  # 当前升级的基线版本
    # 创建基线到升级任务下发
    do_standard_ota_task_publish(ota, vin, veh_series, variable_veh_model, version, upgrade_data_list, stage=stage,
                                 source_type=source_type)
    # 下发升级命令
    issue_upgrade_command(ota, vin, version)
    # 查询升级状态
    get_last_upgrade_status(ota, vin, version, upgrade_data_list)


def do_keyword_ota_upgrade(vin, veh_series, variable_veh_model, upgrade_data_list,
                           env='testtwo', stage='TEST', source_type='VCTD', report_path=None, action_keyword=None,
                           verify_keyword=None):
    """
    数据驱动ECU升级主体逻辑
    Args:
        vin: type string; 车辆识别号
        veh_series: type string; 车系 默认X01
        variable_veh_model: type string; 变量车型
        upgrade_data_list: type list; 升级包信息列表
        env: type string; 默认
        stage: type string; 默认
        source_type: type string; 默认
        report_path: type string; 报告路径
        action_keyword: type Enum; 行为关键字，单条件
        verify_keyword: type list; 动作关键字，多条件

    Returns:

    """
    logger.info(f'行为关键字: {action_keyword}')
    logger.info(f'校验关键字: {verify_keyword}')

    if not report_path:
        report_path = os.getcwd()
    ota = OTAService(env=env)
    version = '0.0.1-' + TimeOperation.get_datetime_string(fmt="%Y%m%d%H%M%S")[2:]  # 当前升级的基线版本

    # *** 推送升级任务前的关键字校验 (多条件)
    if UpgradeVerifyKeyword.vehicle_mode.name in verify_keyword:
        shell_filepath = os.path.join(report_path, 'call_sdc_toolbox.sh')
        vehicle_mode_info = VerifyKeywordMethod.vehicle_mode(shell_filepath, False)
        assert vehicle_mode_info['XCUVehMd_Inner'] == vehicle_mode_info['FBCMVehModSts'] == \
               vehicle_mode_info['RBCMVehModSts'] == '1', f'升级前车辆模式异常: {vehicle_mode_info}'
    if UpgradeVerifyKeyword.a_core_cw.name in verify_keyword:  # 升级前配置字长度为17个字节且不为空
        cfg_wd_info_init = VerifyKeywordMethod.a_core_cw()
        assert cfg_wd_info_init['vehicleConfigWord'] is not None, f'升级前配置字值为空: {cfg_wd_info_init}'
        assert len(cfg_wd_info_init['vehicleConfigWord']) == 34, f'升级前配置字长度异常: {cfg_wd_info_init}'

    # *** 推送升级任务（XCU下载升级包） ***
    if action_keyword == UpgradeActionKeyword.cancel_upgrade:  # condition: cancel_upgrade&cancel_timing=middle&send_again=True
        keyword_condition = action_keyword.condition
        logger.info(f'关键字条件: {keyword_condition}')
        cancel_task_list = keyword_condition.split('&')
        cancel_timing_statement = cancel_task_list[1]  # 'cancel_timing=1'
        send_again_statement = cancel_task_list[2]  # 'send_again=True'
        # send_again = 0
        send_again = eval(send_again_statement.split('=')[-1])
        UpgradeActionKeyword.cancel_upgrade.cancel_timing = 0
        exec(f'UpgradeActionKeyword.cancel_upgrade.{cancel_timing_statement}')  # 枚举值注入
        # exec(send_again_statement)  # 变量赋值  TODO bug 现在看起来不管用
        # logger.info(f'send_again_statement: {send_again_statement}')
        # logger.info(f'send_again: {send_again}')
        task_id, version = do_standard_ota_task_publish(ota, vin, veh_series, variable_veh_model, version,
                                                        upgrade_data_list, stage=stage,
                                                        source_type=source_type, keyword='cancel_upgrade')
        if UpgradeActionKeyword.cancel_upgrade.cancel_timing < 3:
            time.sleep(20)
            status_ok, task_status = get_vehicle_current_download_status(ota, vin, task_id, max_time=60)
            assert status_ok == False, f'取消升级，查询结果异常，cancel_timing={UpgradeActionKeyword.cancel_upgrade.cancel_timing}'
            assert task_status['data']['upgradeStatusTypeName'] == '无任务状态', f'取消升级，查询结果异常，{task_status}'
        if send_again and UpgradeActionKeyword.cancel_upgrade.cancel_timing < 3:  # 升级过程中取消的话不能再次发送升级命令
            logger.info('再次发送升级命令')
            issue_upgrade_command(ota, vin, version)
            status_ok, task_status = get_vehicle_current_download_status(ota, vin, task_id, max_time=60)
            assert status_ok == False, f'取消升级，下发升级命令，查询下载结果异常，cancel_timing={UpgradeActionKeyword.cancel_upgrade.cancel_timing}'
            assert task_status['data'][
                       'upgradeStatusTypeName'] == '无任务状态', f'取消升级, 下发升级命令, 查询结果异常，{task_status}'
        if UpgradeActionKeyword.cancel_upgrade.cancel_timing != 3:
            return 1  # 升级任务取消无后续行为
    elif action_keyword == UpgradeActionKeyword.recreate_task:  # condition: recreate_task&recreate_timing=0
        keyword_condition = action_keyword.condition
        logger.info(f'关键字条件: {keyword_condition}')
        recreate_task_list = keyword_condition.split('&')
        recreate_timing_statement = recreate_task_list[1]  # 'recreate_timing=0'
        exec(f'UpgradeActionKeyword.recreate_task.{recreate_timing_statement}')  # 枚举值注入
        task_id, version = do_standard_ota_task_publish(ota, vin, veh_series, variable_veh_model, version,
                                                        upgrade_data_list, stage=stage,
                                                        source_type=source_type, keyword='recreate_task')
    elif action_keyword == UpgradeActionKeyword.space_overflow:  # 空间容量不足，下载失败，删除后重新推送
        ActionKeywordMethod.space_overflow(ota, vin, veh_series, variable_veh_model, version, upgrade_data_list, stage,
                                           source_type)
    elif action_keyword == UpgradeActionKeyword.cwd_inject:  # 配置字注入
        keyword_condition = action_keyword.condition
        logger.info(f'关键字条件: {keyword_condition}')
        cwd_inject_list = keyword_condition.split('&')
        cwd_inject_statement = cwd_inject_list[1]
        download_statement = cwd_inject_list[-1]
        exec(f'UpgradeActionKeyword.cwd_inject.{cwd_inject_statement}')  # 枚举值注入
        exec(f'UpgradeActionKeyword.cwd_inject.{download_statement}')  # 枚举值注入
        shell_filepath = os.path.join(report_path, 'call_uds_doip_test.sh')
        ActionKeywordMethod.cwd_inject(shell_filepath)
        download_pass = True
        try:
            do_standard_ota_task_publish(ota, vin, veh_series, variable_veh_model, version, upgrade_data_list,
                                         stage=stage,
                                         source_type=source_type,
                                         keyword='cwd_inject')
        except:
            download_pass = False
        assert download_pass == UpgradeActionKeyword.cwd_inject.download_pass
        return 1
    elif action_keyword == UpgradeActionKeyword.cut_off_network:  # 断网重连
        ActionKeywordMethod.hu_net('off')
        task_id, version = do_standard_ota_task_publish(ota, vin, veh_series, variable_veh_model, version,
                                                        upgrade_data_list, stage=stage,
                                                        source_type=source_type, keyword='cut_off_network')
    elif action_keyword == UpgradeActionKeyword.xcu_offline:
        ActionKeywordMethod.xcu_net('off')
        do_standard_ota_task_publish(ota, vin, veh_series, variable_veh_model, version,
                                     upgrade_data_list, stage=stage,
                                     source_type=source_type, keyword='xcu_offline')
    else:
        do_standard_ota_task_publish(ota, vin, veh_series, variable_veh_model, version, upgrade_data_list, stage=stage,
                                     source_type=source_type)
    # *** 下发升级命令 ***
    issue_upgrade_command(ota, vin, version)
    if action_keyword == UpgradeActionKeyword.cancel_upgrade and UpgradeActionKeyword.cancel_upgrade.cancel_timing == 3:  # 这里判断是否需要升级过程中发送取消升级命令
        time.sleep(10)
        issue_cancel_upgrade_command(ota, vin, version)

    # *** 升级过程中要根据关键字进行校验（断言放在最后）
    if UpgradeVerifyKeyword.vehicle_mode.name in verify_keyword:  # 需要校验升级过程中的整车模式,
        shell_filepath = os.path.join(report_path, 'call_sdc_toolbox.sh')
        init_vehicle_mode_info = VerifyKeywordMethod.vehicle_mode(shell_filepath, True)
    if UpgradeVerifyKeyword.fingerprint_info.name in verify_keyword:
        fingerprint_well = VerifyKeywordMethod.fingerprint_info(upgrade_data_list)
    if UpgradeVerifyKeyword.eth_log_package.name in verify_keyword:  # 需要校验升级过程中的日志打包情况
        time.sleep(20)
        packaged_well = VerifyKeywordMethod.eth_log_package()
    verify_time = False
    if UpgradeVerifyKeyword.check_time.name in verify_keyword:
        verify_time = True
    check_status = ''  # 用check_status的地方，一次只能使用一个条件
    if UpgradeVerifyKeyword.check_downgrade.name in verify_keyword:
        check_status = 'check_downgrade'
    if UpgradeVerifyKeyword.check_addinfo.name in verify_keyword:
        check_status = 'check_addinfo'
    if UpgradeVerifyKeyword.check_B2_32.name in verify_keyword:
        check_status = 'check_B2_32'

    # *** 升级过程中要根据关键字设计动作场景 (单条件) ***
    time.sleep(20)
    if action_keyword == UpgradeActionKeyword.reboot:  # 重启
        try:  # 无枚举值注入时默认赋值为 1
            keyword_times = UpgradeActionKeyword.reboot.times
        except:
            keyword_times = 1
        logger.info(f'XCU重启, 10秒后触发, 重启 {keyword_times}次, 周期间隔20秒')
        time.sleep(10)
        for i in range(keyword_times):
            ActionKeywordMethod.reboot()
        get_last_upgrade_status(ota, vin, version, upgrade_data_list, verify_time=verify_time)
    elif action_keyword == UpgradeActionKeyword.bus_busy:  # 总线繁忙
        try:
            ActionKeywordMethod.bus_busy()
        except Exception as e:
            logger.error(e.args)
        get_last_upgrade_status(ota, vin, version, upgrade_data_list, verify_time=verify_time)
    elif action_keyword == UpgradeActionKeyword.high_load:  # 高负载
        ActionKeywordMethod.high_load(ota, vin, version, upgrade_data_list, verify_time=verify_time)
    elif action_keyword == UpgradeActionKeyword.cut_off_network:  # 断网重连
        ActionKeywordMethod.hu_net('off')
        time.sleep(2)
        ActionKeywordMethod.hu_net('on')
        time.sleep(2)
        get_last_upgrade_status(ota, vin, version, upgrade_data_list, verify_time=verify_time)
    elif action_keyword == UpgradeActionKeyword.xcu_offline:
        # 下载过程中及升级过程中，XCU离线5分钟然后在线
        ActionKeywordMethod.xcu_net('off')
        time.sleep(200)
        ActionKeywordMethod.xcu_net('on')
        get_last_upgrade_status(ota, vin, version, upgrade_data_list, verify_time=verify_time)
    elif action_keyword == UpgradeActionKeyword.power_on_off:  # XCU上下电
        # 上下电操作默认枚举值注入
        try:
            keyword_times = UpgradeActionKeyword.power_on_off.times
        except:
            keyword_times = 1
        try:
            off_waiting = UpgradeActionKeyword.power_on_off.off_waiting
        except:
            off_waiting = 1
        logger.info(f'XCU上下电, 10秒后触发, 上下电 {keyword_times}次, 周期间隔20秒')
        time.sleep(10)
        for i in range(keyword_times):
            ActionKeywordMethod.power_on_off(off_waiting=off_waiting)
        get_last_upgrade_status(ota, vin, version, upgrade_data_list, verify_time=verify_time)
    elif action_keyword == UpgradeActionKeyword.restart_app:  # 重启XCU FOTA
        try:
            keyword_times = UpgradeActionKeyword.restart_app.times
        except:
            keyword_times = 1
        logger.info(f'FOTA重启, 40秒后触发, 重启 {keyword_times}次')
        time.sleep(40)
        for i in range(keyword_times):
            ActionKeywordMethod.restart_app()
        get_last_upgrade_status(ota, vin, version, upgrade_data_list, verify_time=verify_time)
    else:
        get_last_upgrade_status(ota, vin, version, upgrade_data_list, verify_time=verify_time,
                                check_status=check_status)

    # *** 升级任务完成后的关键字校验
    logger.info('解压日志')
    xcu_client.execute_cmd('ls /log/Application/*.zst |xargs -I{} /framework/bin/zstd_decompress {}')
    res = xcu_client.execute_cmd('ls /log/Application')
    logger.info(str(res))
    # for i in res.split('\n'):
    #     if '.zst' in i:
    #         xcu_client.execute_cmd('/framework/bin/zstd_decompress /log/Application/' + i)
    if UpgradeVerifyKeyword.vehicle_mode.name in verify_keyword:
        shell_filepath = os.path.join(report_path, 'call_sdc_toolbox.sh')
        vehicle_mode_info = VerifyKeywordMethod.vehicle_mode(shell_filepath, False)
        assert vehicle_mode_info['XCUVehMd_Inner'] == vehicle_mode_info['FBCMVehModSts'] \
               == vehicle_mode_info['RBCMVehModSts'] == '1', f'升级完成后车辆模式异常: {vehicle_mode_info}'
    if UpgradeVerifyKeyword.a_core_cw.name in verify_keyword:
        cfg_wd_info_final = VerifyKeywordMethod.a_core_cw()
        assert cfg_wd_info_init['vehicleConfigWord'] == cfg_wd_info_final[
            'vehicleConfigWord'], f'升级完成后,配置字校验异常,init:{cfg_wd_info_init}, final: {cfg_wd_info_final}'
    if UpgradeVerifyKeyword.check_downgrade.name in verify_keyword:
        version_info = VerifyKeywordMethod.xcu_version()
        xcu_baseline = version_info['xcu_baseline']
        for i in upgrade_data_list:
            if i['ecuName'] == 'XCU' and i['systemName'] == 'XCU_A':
                ecu_version = i['ecuVersion']
                if UpgradeVerifyKeyword.check_downgrade.name in verify_keyword:
                    logger.info(ecu_version)
                    logger.info(xcu_baseline)
                    logger.info(ecu_version.upper() not in xcu_baseline.upper())
                    assert ecu_version.upper() not in xcu_baseline.upper(), f'向低版本升级成功，case fail'
    if UpgradeVerifyKeyword.a_core_version.name in verify_keyword:
        version_info = VerifyKeywordMethod.xcu_version()
        xcu_baseline = version_info['xcu_baseline']
        for i in upgrade_data_list:
            if i['ecuName'] == 'XCU' and i['systemName'] == 'XCU_A':
                ecu_version = i['ecuVersion']
                assert ecu_version.upper() == xcu_baseline.upper(), f'升级完成后,xcu版本比对不通过: 目标版本: {ecu_version}, A核版本:{xcu_baseline}'
    if UpgradeVerifyKeyword.m_core_version.name in verify_keyword:
        version_info = VerifyKeywordMethod.xcu_version()
        ecu_sub_system = version_info['ecu_sub_system']
        for i in upgrade_data_list:
            if i['ecuName'] == 'XCU' and i['systemName'] == 'XCU_M':
                system_version = i['systemVersion']
                assert ecu_sub_system.upper() == system_version.upper(), f'升级完成后,系统版本比对不通过: 目标版本: {system_version}, M核版本:{ecu_sub_system}'
    if UpgradeVerifyKeyword.bus_banned.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'bus_banned_uds_%s.log' % TimeOperation.get_format_time_string(fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.bus_banned(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.dtc_banned.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'dtc_banned_uds_%s.log' % TimeOperation.get_format_time_string(fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.dtc_banned(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.check_integrity.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'check_integrity_uds_%s.log' % TimeOperation.get_format_time_string(fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.check_integrity(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.security_seed_key.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'security_seed_key_uds_%s.log' % TimeOperation.get_format_time_string(
                                    fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.security_seed_key(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.read_ecu_version.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'read_ecu_version_uds_%s.log' % TimeOperation.get_format_time_string(
                                    fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.read_ecu_version(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.check_dependencies.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'check_dependencies_uds_%s.log' % TimeOperation.get_format_time_string(
                                    fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.check_dependencies(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.write_fingerprint.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'write_fingerprint_uds_%s.log' % TimeOperation.get_format_time_string(
                                    fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.write_fingerprint(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.session_program.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'session_program_uds_%s.log' % TimeOperation.get_format_time_string(
                                    fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.session_program(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.session_extended.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'session_extended_uds_%s.log' % TimeOperation.get_format_time_string(
                                    fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.session_extended(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.read_lin_version.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'read_lin_version_uds_%s.log' % TimeOperation.get_format_time_string(
                                    fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.read_lin_version(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.lin_8227.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'lin_8227_uds_%s.log' % TimeOperation.get_format_time_string(
                                    fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.lin_8227(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.erase_memory.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'erase_memory_uds_%s.log' % TimeOperation.get_format_time_string(
                                    fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.erase_memory(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.lin_reset.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'lin_reset_uds_%s.log' % TimeOperation.get_format_time_string(
                                    fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.lin_reset(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.clear_dtc.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'clear_dtc_uds_%s.log' % TimeOperation.get_format_time_string(fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.clear_dtc(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.response_inhibition.name in verify_keyword:
        filepath = os.path.join(report_path, 'response_inhibition_uds_%s.log' % TimeOperation.get_format_time_string(
            fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.response_inhibition(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.complete_frame.name in verify_keyword:
        filepath = os.path.join(report_path,
                                'complete_frame_uds_%s.log' % TimeOperation.get_format_time_string(fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.complete_frame(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.precompile_message.name in verify_keyword:
        filepath = os.path.join(report_path, 'precompile_message_uds_%s.log' % TimeOperation.get_format_time_string(
            fmt='%Y%m%d%H%M%S'))
        verify_pass = VerifyKeywordMethod.precompile_message(filepath)
        assert verify_pass == True
    if UpgradeVerifyKeyword.verify_version.name in verify_keyword:
        verify_pass = VerifyKeywordMethod.verify_version(upgrade_data_list)
        assert verify_pass == True

    # 最后处理升级过程中的断言，否则直接断言会中断逻辑，造成升级未结束
    if UpgradeVerifyKeyword.vehicle_mode.name in verify_keyword:
        assert init_vehicle_mode_info['XCUVehMd_Inner'] == init_vehicle_mode_info['FBCMVehModSts'] == \
               init_vehicle_mode_info['RBCMVehModSts'] == '5', f'升级过程中车辆模式异常: {init_vehicle_mode_info}'
    if UpgradeVerifyKeyword.eth_log_package.name in verify_keyword:
        assert packaged_well == True, f'升级过程中日志打包异常'
    if UpgradeVerifyKeyword.fingerprint_info.name in verify_keyword:
        assert fingerprint_well == True, f'升级过程中指纹信息异常'
    if UpgradeVerifyKeyword.check_crash.name in verify_keyword:
        check_crash = ActionKeywordMethod.check_crash()
        assert check_crash == True, f'升級過程中，發現crash'
    if UpgradeVerifyKeyword.log_notify_upload.name in verify_keyword:
        check_log_notify_upload = ActionKeywordMethod.log_notify_upload()
        assert check_log_notify_upload == True, f'升級后，log_notify_upload不存在'

    logger.info(f'upgrade_data_list:: {upgrade_data_list}')
    if ('XCU' in str(upgrade_data_list)) and (check_status != 'check_downgrade'):
        cloud_version = VerifyKeywordMethod.cloud_version(ota, vin)
        logger.info(f'cloud_version:: {cloud_version}')
        for i in upgrade_data_list:
            if i['ecuName'] == 'XCU' and i['systemName'] == 'XCU_A':
                baseVersion = i['ecuVersion']
                A_systemVersion = i['systemVersion']
            if i['ecuName'] == 'XCU' and i['systemName'] == 'XCU_M':
                M_systemVersion = i['systemVersion']
        assert baseVersion.upper() == cloud_version[
            'ecuVersion'].upper(), f'升级完成后,云端基线版本比对不通过: 目标版本: {baseVersion.upper()}, 云端版本:{cloud_version["ecuVersion"].upper()}'
        assert baseVersion.upper() == cloud_version[
            'currentSoftwareVersion'].upper(), f'升级完成后,云端基线版本比对不通过: 目标版本: {baseVersion.upper()}, 云端版本:{cloud_version["currentSoftwareVersion"].upper()}'
        assert A_systemVersion.upper() == cloud_version['XCU_A'][
            'subSystemVersion'].upper(), f'升级完成后,云端A核版本比对不通过: 目标版本: {A_systemVersion.upper()}, 云端版本:{cloud_version["XCU_A"]["subSystemVersion"].upper()}'
        assert A_systemVersion.upper() == cloud_version['XCU_A'][
            'currentVersion'].upper(), f'升级完成后,云端A核版本比对不通过: 目标版本: {A_systemVersion.upper()}, 云端版本:{cloud_version["XCU_A"]["currentVersion"].upper()}'
        assert M_systemVersion.upper() == cloud_version['XCU_M'][
            'subSystemVersion'].upper(), f'升级完成后,云端M核版本比对不通过: 目标版本: {M_systemVersion.upper()}, 云端版本:{cloud_version["XCU_M"]["subSystemVersion"].upper()}'
        assert M_systemVersion.upper() == cloud_version['XCU_M'][
            'currentVersion'].upper(), f'升级完成后,云端M核版本比对不通过: 目标版本: {M_systemVersion.upper()}, 云端版本:{cloud_version["XCU_M"]["currentVersion"].upper()}'

    if UpgradeVerifyKeyword.check_crash.name in verify_keyword:
        check_crash = ActionKeywordMethod.check_crash()
        assert check_crash == True, f'升級過程中，發現crash'
    #  升级后分区检测
    res = xcu_client.execute_cmd('df -h')
    logger.info(str(res))
    if (('/dev' in str(res)) and ('/dev/shm' in str(res)) and ('/run' in str(res)) and (
            '/sys/fs/cgroup' in str(res)) and ('/etc/machine-id' in str(res)) and ('/tmp' in str(res)) and (
                '/var' in str(res)) and ('/apps' in str(res)) and ('/framework' in str(res)) and (
                '/log' in str(res)) and ('/app_data' in str(res)) and ('/ota' in str(res)) and (
                '/sota_app' in str(res)) and ('/ecu_back' in str(res))) or (
            ('/dev' in str(res)) and ('/dev/shm' in str(res)) and ('/run' in str(res)) and (
            '/sys/fs/cgroup' in str(res)) and ('/etc/machine-id' in str(res)) and ('/tmp' in str(res)) and (
                    '/var' in str(res)) and ('/apps' in str(res)) and ('/ecu_back' in str(res)) and (
                    '/app_data' in str(res)) and ('/ota' in str(res)) and ('/log' in str(res)) and (
                    '/sota_app' in str(res))) or (
            ('/dev' in str(res)) and ('/dev/shm' in str(res)) and ('/run' in str(res)) and (
            '/sys/fs/cgroup' in str(res)) and ('/etc/machine-id' in str(res)) and ('/tmp' in str(res)) and (
                    '/var' in str(res)) and ('/apps' in str(res)) and ('/factory' in str(res)) and (
                    '/app_data' in str(res)) and ('/ota' in str(res)) and ('/log' in str(res)) and (
                    '/sota_app' in str(res))):
        pass
    else:
        assert False, f'分区异常常'


if __name__ == '__main__':
    # logger.info('PCAN 模拟ESP发送96 车速报文')
    # id = '0x96'
    # messages_96 = [
    #     [0x34, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0x4B, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0xC3, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0xDF, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0xB0, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0x9D, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0xDC, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0x0B, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0xE7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0xE3, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0x38, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0x3C, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0xA3, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0x14, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0x7B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    #     [0x0F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    # ]

    logger.info('PCAN 模拟ESP发送 车速报文')
    id = '0x100'
    messages_100 = [
        [0x7c, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x7b, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xc1, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x85, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xe0, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x50, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xb0, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x84, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x22, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x19, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x2e, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xd7, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x0d, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xe6, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xdc, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x3d, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x7c, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x7b, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xc1, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x85, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xe0, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x50, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xb0, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x84, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x22, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x19, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x2e, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xd7, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x0d, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xe6, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xdc, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x3d, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x7c, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x7b, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xc1, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x85, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xe0, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x50, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xb0, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x84, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x22, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x19, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x2e, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xd7, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x0d, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xe6, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xdc, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x3d, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ]
    # messages_100 = [   #可废弃
    #     [0x75, 0x45, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x75, 0x45, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x3c, 0x49, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x95, 0x46, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x95, 0x46, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x0b, 0x4a, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xa1, 0x47, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xa1, 0x47, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xf2, 0x4b, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x07, 0x48, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x07, 0x48, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x28, 0x4c, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x3c, 0x49, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x3c, 0x49, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xc3, 0x4d, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x0b, 0x4a, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x0b, 0x4a, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xf9, 0x4e, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xf2, 0x4b, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xf2, 0x4b, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x18, 0x4f, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x28, 0x4c, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x28, 0x4c, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x59, 0x40, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xc3, 0x4d, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xc3, 0x4d, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0x5e, 0x41, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xf9, 0x4e, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    #     [0xf9, 0x4e, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00],
    # ]
    #
    id = '0x76'
    messages_100 = [
        [0x08, 0x01, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0xd2, 0x02, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0x8f, 0x03, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0x9c, 0x04, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0x02, 0x05, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0xf4, 0x06, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0xcf, 0x07, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0x5e, 0x08, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0xf1, 0x09, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0xc7, 0x0a, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0xd4, 0x0b, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0x7f, 0x0c, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0xb6, 0x0d, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0x4e, 0x0e, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0x1e, 0x0f, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
        [0xe9, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00],
    ]
    messages = messages_100
    bdcan1 = PCAN(PB.PCAN_USBBUS1, PB.PCAN_BAUD_2M, CanFD=True)
    # msg_data = [0xDF,0x05,0x00,0x00,0x00,0x00,0x00,0x00]  # Change the string data to byte list
    time_now = time.time()
    while True:
        for msg_data in messages:
            bdcan1.send_message(id, msg_data, console=None)
            time.sleep(0.01)  # 插入暂停以控制发送的速度
    # //*** 升级变量维护
    # vin = 'LW433B120N1000062'
    # veh_series = 'X01'
    # variable_veh_model = 'X151CN1A1LK3'
    # upgrade_data_list = [  # 这里是用户自定义，需要几个ECU升几个，前提是ECU在该车系网络拓扑中，且保证已同步升级包
    #     {
    #         "ecuName": "XCU",
    #         "systemName": "XCU_A",
    #         "ecuVersion": "8113",
    #         "systemVersion": "XCU_A_X03-release-APP6.1.16-BSP1.9.6-rc2.20221025-564"
    #     }
    # ]
    # ***//

    # # 开始升级
    # do_standard_ota_upgrade(vin, veh_series, variable_veh_model, upgrade_data_list)

    # # 校验
    # res = VerifyKeywordMethod.vehicle_mode('call_sdc_toolbox.sh')
    # print(res)
    # res = VerifyKeywordMethod.a_core_cw()
    # print(res)
    # res = VerifyKeywordMethod.xcu_version()
    # print(res)
    # res = VerifyKeywordMethod.bus_banned('1.log')
    # print(res)
    # res = VerifyKeywordMethod.clear_dtc('2.log')
    # print(res)
    # res = VerifyKeywordMethod.response_inhibition('3,log')
    # print(res)
    # res = VerifyKeywordMethod.complete_frame('4,log')
    # print(res)

    # print(UpgradeActionKeyword.cancel_upgrade)
    # print(UpgradeActionKeyword.cancel_upgrade.name)
    # print(UpgradeActionKeyword.cancel_upgrade.value)
    # exec('UpgradeActionKeyword.cancel_upgrade.condition = "1&2=3"')
    # print(UpgradeActionKeyword.cancel_upgrade.condition)
