import sys
import os
from headless_ida import HeadlessIda

# 将../../ 目录添加到 sys.path 中，便于后续导入patcher模块
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(os.path.dirname(current_dir))
sys.path.append(root_dir)

TARGET_PROC_PATH = os.path.abspath("./httpd_81")
# 可以通过patchelf，添加依赖库
TEMP_PROC_PATH = TARGET_PROC_PATH + "_temp"
ADDED_LIBRARY_PATH = "/tmp/libmonitor.so"
os.system(f"cp {TARGET_PROC_PATH} {TEMP_PROC_PATH}")
os.system(f"patchelf --add-needed {ADDED_LIBRARY_PATH} {TEMP_PROC_PATH}")


# 也可以通过lief，修改elf文件，添加依赖库
# import lief
# binary = lief.parse(TARGET_PROC_PATH)
# binary.add_library(ADDED_LIBRARY_PATH)
# binary.write(TEMP_PROC_PATH)

# 可以通过patchelf，添加依赖库
# os.system(f"cp {TARGET_PROC_PATH} {TEMP_PROC_PATH}")
# os.system(f"patchelf --add-needed {ADDED_LIBRARY_PATH} {TEMP_PROC_PATH}")

# 也可直接通过LD_PRELOAD环境变量，在运行时添加依赖库

# 通过HeadlessIda，实现调用idapython
headlessida = HeadlessIda(
    "/Applications/IDA Professional 9.0.app/Contents/MacOS/idat", TEMP_PROC_PATH
)
# 使用绝对导入
from patcher.patcher import SignalMonitorPatcher




control_flow_monitared_function_list = [
    "aspTendaGetLongString",
    "aspTendaGetStatus",
    "updateUrlLog",
    "fromSysStatusHandle",
    "formGetWanStatus",
    "formGetSysInfo",
    "formGetWanStatistic",
    "formGetAllWanInfo",
    "formGetWanNum",
    "aspGetWanNum",
    "formGetPortStatus",
    "formsetNotUpgrade",
    "aspGetCharset",
    "fromWizardHandle",
    "form_fast_setting_get",
    "form_fast_setting_pppoe_get",
    "form_fast_setting_wifi_set",
    "form_fast_setting_pppoe_set",
    "formGetWanConnectStatus",
    "GetProduct",
    "form_fast_setting_internet_set",
    "form_usb_get",
    "SysToolpassword",
    "formNotNowUpgrade",
    "formGetHomeLink",
    "fromAdvGetMacMtuWan",
    "fromAdvSetMacMtuWan",
    "formAdvGetLanIp",
    "SetWebIpAccess",
    "fromWanPolicy",
    "formSetSafeWanWebMan",
    "formGetSafeWanWebMan",
    "formWanParameterSetting",
    "formGetWanParameter",
    "getAdvanceStatus",
    "setDnsCheck",
    "getDnsCheck",
    "add_white_node",
    "getSmartPowerManagement",
    "setSmartPowerManagement",
    "getSchedWifi",
    "setSchedWifi",
    "formGetSchedLed",
    "formSetSchedLed",
    "GetParentControlInfo",
    "saveParentControlInfo",
    "formGetDhcpServer",
    "aspTendaGetDhcpClients",
    "fromDhcpListClient",
    "formTendaGetDhcpClients",
    "aspTendaGetDhcpClients",
    "formGetAdvanceStatus",
    "formSetVirtualSer",
    "formGetVirtualSer",
    "mDMZSetCfg",
    "mDMZGetCfg",
    "formGetUpnpLists",
    "formSetUpnp",
    "fromNatStaticSetting",
    "formSetSysToolDDNS",
    "formGetSysToolDDNS",
    "aspmGetRouteTable",
    "formGetRouteStatic",
    "fromSetRouteStatic",
    "fromAddressNat",
    "mNatGetStatic",
    "asp_error_message",
    "asp_error_redirect_url",
    "aspmGetIPRate",
    "fromAdvSetPortVlan",
    "formBulletinSet",
    "formNatSet",
    "aspNatSet",
    "formGetMacFilterCfg",
    "formSetParentControlEnable",
    "formSetQosBand",
    "formGetQosBand",
    "formGetDeviceDetail",
    "formSetClientState",
    "formSetDeviceName",
    "formGetSystemSet",
    "formSetSpeedWan",
    "formGetMacfilterRuleList",
    "formGetIptv",
    "formGetDdosDefenceList",
    "formGetAutoQosInfo",
    "formSetAutoQosInfo",
    "formGetBandWidthSpeed",
    "formGetSysLog",
    "fromSysToolSysLog",
    "fromLogsSetting",
    "fromSysToolTime",
    "fromSysToolChangePwd",
    "fromSysToolBaseUser",
    "fromSysToolGetUpgrade",
    "fromSysToolSetUpgrade",
    "fromGetIpMacBind",
    "fromSetIpMacBind",
    "formWifiMultiSsid",
    "formWifiBasicGet",
    "formWifiBasicSet",
    "formWifiApScan",
    "formWifiBeamformingGet",
    "formWifiBeamformingSet",
    "formWifiClientList",
    "formWifiClientListAll",
    "formWifiMacFilterGet",
    "formWifiMacFilterSet",
    "initWifiMacFilter",
    "addWifiMacFilter",
    "delWifiMacFilter",
    "formWifiRadioGet",
    "formWifiRadioSet",
    "formWifiPowerGet",
    "formWifiPowerSet",
    "formWifiStatistic",
    "formWifiStatisticClear",
    "formWifiStatus",
    "formAliScheduleStatus",
    "formWifiWpsStart",
    "formWifiWpsOOB",
    "formWifiConfigGet",
    "formGetWifiWps",
    "formStartWifiWps",
    "formGetUSBStatus",
    "formSetUsbPrint",
    "formGetUsbPrint",
    "formSetSambaConf",
    "formGetSambaConf",
    "formsetUsbUnload",
    "formGetUsbCfg",
    "TendaAte",
    "formWriteFacMac",
    "formMfgTest",
    "formTendaModelStatus",
    "aspGetPortShow",
    "aspGetCfm",
    "aspGetfilterMaxNum",
    "aspGetModeShow",
    "aspGetMaxNatNum",
    "formQuickIndex",
    "aspGetifnlist",
    "fromGetSysTime",
    "fromgetApModeCfg",
    "fromGetWirelessRepeat",
    "fromSetWifiGusetBasic",
    "fromGetWifiGusetBasic",
    "fromGetWrlStatus",
    "formSetPPTPServer",
    "formGetPPTPServer",
    "formgetPptpOnlineClient",
    "formSetPPTPClient",
    "formGetPPTPClient",
]

[
    "formSetFirewallCfg",
    "formGetSystemStatus",
    "formGetRouterStatus",
    "fromAdvSetLanip",
    "formGetOnlineList",
    "formGetParentCtrlList",
    "formSetCfm",
    "fromsetApModeCfg",
    "fromSetWirelessRepeat",
    "formSetPPTPUserList",
    "goform/WifiWpsSet",
    "goform/SetIPTVCfg",
]

called_monitared_function_list = ["doSystemCmd", "sprintf", "sscanf"]
call_nop_function_list = ["CommitCfm"]
conn_ip = "192.168.0.153"
conn_port = 8888

patcher = SignalMonitorPatcher(
    control_flow_monitared_function_list=control_flow_monitared_function_list,
    called_monitared_function_list=called_monitared_function_list,
    call_nop_function_list=call_nop_function_list,
    target_dir_path=os.path.abspath("./"),
    target_proc_name="httpd_81_temp",
    output_proc_name="httpd_81_patch",
    conn_ip=conn_ip,
    conn_port=conn_port,
)
patcher.init_monitor_probe_setup()
patcher.get_constant_string_in_strcmp()
patcher.call_nop_patch()
patcher.call_probe_patch()
patcher.control_flow_probe_patch()
patcher.apply_patches()
patcher.gen_monitor_config()
patcher.gen_fuzzer_config()


# TARGET_PROC_PATH = os.path.abspath("../tenda_ac9/httpd_81")
# TEMP_PROC_PATH = TARGET_PROC_PATH + "_TMP"
# OUTPUT_PROC_PATH = TARGET_PROC_PATH + "_patch"
# ADDED_LIBRARY_PATH = "/tmp/libmonitor.so"
# CONFIG_OUTPUT_PATH = "../tenda_ac9/"

# # TARGET_PROC_PATH = os.path.abspath("../arm/2_uclibc")
# # TEMP_PROC_PATH = TARGET_PROC_PATH + "_TMP"
# # OUTPUT_PROC_PATH = TARGET_PROC_PATH + "_patch"
# # ADDED_LIBRARY_PATH = "/tmp/libmonitor.so"
# # CONFIG_OUTPUT_PATH = "../arm/"


# # binary = lief.parse(TARGET_PROC_PATH)
# # binary.add_library(ADDED_LIBRARY_PATH)
# # binary.write(TEMP_PROC_PATH)

# os.system(f"cp {TARGET_PROC_PATH} {TEMP_PROC_PATH}")
# os.system(f"orb patchelf --add-needed {ADDED_LIBRARY_PATH} {TEMP_PROC_PATH}")
# headlessida = HeadlessIda(
#     "/Applications/IDA Professional 9.0.app/Contents/MacOS/idat", TEMP_PROC_PATH
# )


# control_flow_monitared_function_list = ["formSetSambaConf"]
# called_monitared_function_list = ["doSystemCmd"]
# conn_ip = "192.168.0.153"
# conn_port = 8888

# patcher = SignalMonitorPatcher(
#     control_flow_monitared_function_list,
#     called_monitared_function_list,
#     conn_ip,
#     conn_port,
# )
# patcher.init_monitor_probe_setup()
# patcher.get_constant_string_in_strcmp()
# patcher.control_flow_probe_patch()
# patcher.call_probe_patch()
# # patcher.inject_control_flow_probe_to_function()
# # patcher.insert_probe_into_function_to_monitor_specific_call()
# patcher.apply_patches()
# # patcher.gen_monitor_config()
# patcher.gen_fuzzer_config()
