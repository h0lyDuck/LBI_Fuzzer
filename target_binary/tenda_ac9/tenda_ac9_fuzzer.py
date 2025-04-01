import sys
import os
from headless_ida import HeadlessIda

# 将../../ 目录添加到 sys.path 中，便于后续导入patcher模块
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(os.path.dirname(current_dir))
sys.path.append(root_dir)

from fuzzer.fuzzer import Fuzzer
from string import Template


tenda_ac9_fuzz_template = Template(
    """\
POST $PATH?img/main-logo.png HTTP/1.1
Host: 192.168.0.1:81
Content-Length: $CONTENT_LENGTH
X-Requested-With: XMLHttpRequest
Accept-Language: zh-CN,zh;q=0.9
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36
Origin: http://192.168.0.1:81
Referer: http://192.168.0.1:81/wifi_wps.html?random=0.7163678692016655&
Accept-Encoding: gzip, deflate, br
Cookie: password=5f4dcc3b5aa765d61d8327deb882cf99kgemji
Connection: keep-alive

$PAYLOAD
"""
)

fuzzer = Fuzzer(
    target_ip="192.168.0.1",
    target_port=81,
    fuzzer_config_path="./fuzzer_config.json",
    fuzz_output_path="./fuzz_output",
    sample_constraint_model_path="./ac9.json",
    fuzz_http_message_template=tenda_ac9_fuzz_template,
)
# fuzzer.fuzz()
fuzzer.only_receive_udp_data()