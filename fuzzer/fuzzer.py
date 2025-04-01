import socket
import requests
import threading
import queue
import json
import networkx as nx
import math
import matplotlib.pyplot as plt
import networkx.algorithms.dag as dag
import time
import os
import tqdm
from string import Template
from pprint import pprint
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.console import Group
from rich.columns import Columns
from rich import box

from .utils import *


class Fuzzer:
    def __init__(
        self,
        target_ip: str,
        target_port: int,
        fuzzer_config_path: str,
        fuzz_output_path: str,
        sample_constraint_model_path: str,
        fuzz_http_message_template: Template,
        feedback_udp_port: int = 8888,
        timeout: int = 1000,
    ):
        # 目标靶机的IP地址和端口
        self.target_ip = target_ip
        self.target_port = target_port

        # 目标靶机反馈信息的UDP端口
        self.feedback_udp_port = feedback_udp_port
        # 创建UDP套接字，用于接受来自测试程序反馈的控制流执行信息以及函数调用信息,
        self.feedback_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.feedback_udp_socket.bind(("", self.feedback_udp_port))
        # self.feedback_udp_socket.settimeout(feedback_timeout)
        self.feedback_udp_socket.setblocking(False)
        self.feedback_info_queue = queue.Queue()

        self.feedback_path_count = {}

        self.dashboard_stop_signal = threading.Event()

        self.fuzz_output_path = fuzz_output_path
        if not os.path.exists(self.fuzz_output_path):
            os.makedirs(self.fuzz_output_path)

        self.timeout = timeout

        # 约束模型读入初始化
        self.sample_constraint_model_path = sample_constraint_model_path
        self.sample_constraint_model_list = []
        with open(self.sample_constraint_model_path, "r") as f:
            temp = json.loads(f.read())

            self.sample_constraint_model_list = [
                item
                for item in temp
                if not ("method" in item and item["method"].lower() == "get")
            ]
        random.shuffle(self.sample_constraint_model_list)
        # HTTP报文模板
        self.fuzz_http_message_template = fuzz_http_message_template

        self.cf_monitored_func_cfg = {}
        self.call_monitored_func_list = {}
        # self.results = []
        self.stub_point_to_basic_block_map = {}
        self.cfg_edge_weight_dict = {}

        self.init_config(fuzzer_config_path)

        self.fuzz_count = 0
        self.bug_finding = 0
        self.current_fuzz_interface = ""
        self.seed_queue_len = 0
        self.score = 0
        self.start_time = 0
        self.interface_index = 0

    def init_config(self, fuzzer_config_path):
        global str_fuzz_library
        with open(fuzzer_config_path, "r") as f:
            self.fuzzer_config = json.loads(f.read())

        self.call_monitored_func_list = self.fuzzer_config["call_monitored_func"]
        for monitored_func in tqdm.tqdm(self.fuzzer_config["cf_monitored_func"]):
            # if monitored_func in [
            #     "formGetSystemStatus",
            #     "formGetRouterStatus",
            #     "fromAdvSetLanip",
            #     "formGetOnlineList",
            #     "formGetParentCtrlList",
            #     "formSetCfm",
            #     "fromsetApModeCfg",
            #     "fromSetWirelessRepeat",
            #     "formSetPPTPUserList",
            # ]:
            #     continue
            nx_func_cfg_json = self.fuzzer_config["cf_monitored_func"][monitored_func][
                "nx_func_cfg_json"
            ]
            nx_func_cfg = nx.node_link_graph(nx_func_cfg_json)
            self.cf_monitored_func_cfg[monitored_func] = nx_func_cfg
            longest_path = get_longest_path(nx_func_cfg)
            longest_path_len = len(longest_path)
            # nx_func_cfg.graph["longest_path_len"] = longest_path_len
            # nx_func_cfg.graph["longest_path"] = longest_path
            for block_id in nx_func_cfg.nodes:
                # 映射桩点与基本块的映射关系
                self.stub_point_to_basic_block_map[
                    hex(nx_func_cfg.nodes[block_id]["patch_inst_addr"])[2:]
                ] = block_id
                # 若当前基本块中存在对被监控函数的调用，则计算该监控函数对完整控制流图的影响
                if nx_func_cfg.nodes[block_id]["call_monitored_functions"] != []:
                    path_list = get_all_paths_from_start_to_target(
                        nx_func_cfg, block_id
                    )
                    path_contribution_weight = {}
                    for path in path_list:
                        for index in range(len(path) - 1):
                            edge = (path[index], path[index + 1])
                            new_path_contribution_weight = (
                                longest_path_len + index + 1 - (len(path) - 1)
                            )
                            if (
                                path_contribution_weight.get(edge, 0)
                                < new_path_contribution_weight
                            ):
                                path_contribution_weight[edge] = (
                                    new_path_contribution_weight
                                )
                    for edge in path_contribution_weight:
                        nx_func_cfg.edges[edge]["weight"] += path_contribution_weight[
                            edge
                        ]
            for edge in nx_func_cfg.edges:
                self.cfg_edge_weight_dict[edge] = (
                    nx_func_cfg.edges[edge]["weight"],
                    longest_path_len,
                )

        str_fuzz_library += self.fuzzer_config["const_str_list_in_strcmp"]
        # pprint(self.fuzzer_config["cf_monitored_func"])
        # print(self.stub_point_to_basic_block_map)

    # def mutate_seed(self, seed: Seed, score):
    #     new_seed = seed.copy()
    #     new_seed.priority = 0 - score
    #     for i in seed.payload:

    #     return new_seed

    def is_seed_vulnerable(
        self, seed, call_feedback_info_list, control_flow_edge_list, payload
    ):
        for call_feedback_info in call_feedback_info_list:
            for i in range(4):
                if call_feedback_info[f"a{i}"]["type"] == "pointer":
                    similarity = max_string_similarity(
                        call_feedback_info[f"a{i}"]["value"],
                        seed.get_payload_value_list(),
                    )
                    if similarity > 0.50:
                        for call_monitored_func in self.call_monitored_func_list:
                            if (
                                int(call_feedback_info["call_addr"], 16)
                                == self.call_monitored_func_list[call_monitored_func][
                                    "addr"
                                ]
                            ):
                                call_feedback_info["vuln_func"] = call_monitored_func
                                break
                        output = {
                            "similarity": similarity,
                            "payload": payload,
                            "call_feedback_info": call_feedback_info,
                            "control_flow_edge_list": control_flow_edge_list,
                        }
                        with open(
                            os.path.join(
                                self.fuzz_output_path,
                                f"fuzzing_results_{time.time()}.json",
                            ),
                            "w",
                        ) as f:
                            f.write(json.dumps(output, indent=4))
                        return True
        return False

    def fuzz(self):
        # print("开始fuzzing")
        self.start_time = time.time()
        self.show_fuzz_dashboard()
        for index, sample_constraint_model in enumerate(
            self.sample_constraint_model_list
        ):

            pq = queue.PriorityQueue()
            self.interface_index = index
            self.current_fuzz_interface = sample_constraint_model["url"]
            init_seeds = generate_init_fuzz_seeds(sample_constraint_model["parameters"])
            for seed in init_seeds:
                pq.put(seed)
            self.seed_queue_len = pq.qsize()
            start_time = time.time()
            while not pq.empty() and time.time() - start_time < self.timeout:
                seed = pq.get()
                self.seed_queue_len = pq.qsize()
                payload = {
                    "PAYLOAD": seed.get_payload(),
                    "PATH": (
                        sample_constraint_model["url"]
                        if sample_constraint_model["url"].startswith("/")
                        else "/" + sample_constraint_model["url"]
                    ),
                    "CONTENT_LENGTH": len(seed.get_payload()),
                }
                payload = self.fuzz_http_message_template.substitute(payload)
                # print(payload)
                is_success, score, call_feedback_info_list, control_flow_edge_list = (
                    self.send_request(payload)
                )
                self.fuzz_count += 1
                if not is_success:
                    time.sleep(1)
                    pq.put(seed)
                    # output = {
                    #     "payload": payload,
                    # }
                    # with open(
                    #     os.path.join(
                    #         self.fuzz_output_path,
                    #         f"fuzzing_results_{time.time()}.json",
                    #     ),
                    #     "w",
                    # ) as f:
                    #     f.write(json.dumps(output))
                    # input("send_request失败")
                    print("send request失败")
                    continue
                if call_feedback_info_list == []:
                    break
                if self.is_seed_vulnerable(
                    seed, call_feedback_info_list, control_flow_edge_list, payload
                ):
                    self.bug_finding += 1
                    break
                if score <= 0:
                    continue
                self.score = score
                seed.mutate(score)
                pq.put(seed)
                # 变异payload
        self.dashboard_stop_signal.set()

    def generate_fuzzing_sample_score(self, control_flow_feedback_info_list):
        try:
            edge_list = []
            score = 0
            longest_path_len = 0
            for index in range(len(control_flow_feedback_info_list) - 1):
                edge = (
                    self.stub_point_to_basic_block_map[
                        control_flow_feedback_info_list[index]["pc"]
                    ],
                    self.stub_point_to_basic_block_map[
                        control_flow_feedback_info_list[index + 1]["pc"]
                    ],
                )
                if edge not in edge_list:
                    edge_list.append(edge)

            for edge in edge_list:
                score += self.cfg_edge_weight_dict[edge][0]
                longest_path_len = self.cfg_edge_weight_dict[edge][1]

            self.feedback_path_count[tuple(edge_list)] = (
                self.feedback_path_count.get(tuple(edge_list), -1) + 1
            )

            score = (
                score
                - (longest_path_len * self.feedback_path_count[tuple(edge_list)]) / 40
            )
            return score, edge_list
        except Exception as e:
            # print("generate_fuzzing_sample_score出现异常")
            # print(e)
            return -1, []

    def send_request(self, payload: str):
        def receive_udp_data(
            sock: socket.socket, data_queue: queue.Queue, event: threading.Event
        ):
            while not event.is_set():
                try:
                    data, addr = sock.recvfrom(1024)
                    data_queue.put((data, addr))
                except BlockingIOError:
                    continue
            # print("receive_udp_data退出接收循环")

        # 创建一个事件对象，用于控制UDP接收线程的停止
        stop_event = threading.Event()
        # 启动线程来接收UDP数据
        udp_thread = threading.Thread(
            target=receive_udp_data,
            args=(self.feedback_udp_socket, self.feedback_info_queue, stop_event),
        )
        udp_thread.start()

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 连接服务器
            server_address = (
                self.target_ip,
                self.target_port,
            )  # 假设HTTP服务默认使用80端口，根据实际情况调整
            client_socket.connect(server_address)
            # 发送请求报文
            client_socket.send(payload.encode("latin1"))

            # 接收服务器响应
            response_data = b""
            while True:
                part = client_socket.recv(1024)
                if not part:
                    break
                response_data += part
            # 可以对响应数据进行后续处理，比如打印查看等
            # print(response_data.decode("utf-8", errors="ignore"))
            client_socket.close()
        except:
            # print(f"HTTP请求出现异常: {e}")
            time.sleep(4)
            client_socket.close()
            stop_event.set()
            return False, 0, [], []
        received_data_list = []
        call_feedback_info_list = []
        control_flow_feedback_info_list = []
        time.sleep(2)
        stop_event.set()
        while not self.feedback_info_queue.empty():
            received_data, addr = self.feedback_info_queue.get()
            received_data_list.append(json.loads(received_data.decode("latin1")))

        for info in received_data_list:
            if info["type"] == "call_probe":
                call_feedback_info_list.append(info)
            elif info["type"] == "cf_probe":
                control_flow_feedback_info_list.append(info)

        # 计算分数
        score, edge_list = self.generate_fuzzing_sample_score(
            control_flow_feedback_info_list
        )
        return True, score, call_feedback_info_list, edge_list

    def only_receive_udp_data(self):
        def receive_udp_data(
            sock: socket.socket, data_queue: queue.Queue, event: threading.Event
        ):
            while not event.is_set():
                try:
                    data, addr = sock.recvfrom(1024)
                    data_queue.put((data, addr))
                except BlockingIOError:
                    continue
            # print("receive_udp_data退出接收循环")

        stop_event = threading.Event()
        udp_thread = threading.Thread(
            target=receive_udp_data,
            args=(self.feedback_udp_socket, self.feedback_info_queue, stop_event),
        )
        udp_thread.start()
        input("探针反馈数据：")
        received_data_list = []
        call_feedback_info_list = []
        control_flow_feedback_info_list = []
        while not self.feedback_info_queue.empty():
            received_data, _ = self.feedback_info_queue.get()
            received_data_list.append(json.loads(received_data.decode("latin1")))
            print(json.loads(received_data.decode("latin1")))
        # for info in received_data_list:
        #     if info["type"] == "call_probe":
        #         call_feedback_info_list.append(info)
        #     elif info["type"] == "cf_probe":
        #         control_flow_feedback_info_list.append(info)
        # self.generate_fuzzing_sample_score(control_flow_feedback_info_list)
        # stop_event.set()

    def show_fuzz_dashboard(self):
        def print_current_dashboard():

            # 标题面板（固定部分）
            title_panel = Panel(
                Text(
                    "Linux Base IoT Fuzzer (LBI_FUZZER)",
                    justify="center",
                    style="bold blue on black",
                ),
                box=box.DOUBLE,
                width=90,
            )

            with Live(refresh_per_second=10) as live:
                while True:
                    time.sleep(0.1)

                    stats_text = Text(justify="left")
                    crashes_text = Text(justify="left")
                    stats_text.append("Fuzz count       : ")
                    stats_text.append(f"{self.fuzz_count}\n")
                    stats_text.append("Fuzzed time      : ")
                    stats_text.append(f"{round(time.time()-self.start_time,0)}s\n")
                    stats_text.append("Seed Queue Len   : ")
                    stats_text.append(f"{self.seed_queue_len}\n")
                    stats_text.append("Total Interface  : ")
                    stats_text.append(
                        f"{self.interface_index}/{len(self.sample_constraint_model_list)}\n"
                    )
                    stats_text.append("Curr Fuzz InterF : ")
                    stats_text.append(f"{self.current_fuzz_interface}\n")
                    stats_text.append("Score            : ")
                    stats_text.append(f"{self.score}\n")
                    stats_text.append("\n")
                    stats_text.append("Bug Finding      : ")
                    stats_text.append(f"{self.bug_finding}\n")

                    # coverage_text._text = []
                    # coverage_text.append("Branch coverage : ", style="green")
                    # coverage_text.append(f"{random.randint(30, 80)}%\n")
                    # coverage_text.append("Edge coverage   : ", style="cyan")
                    # coverage_text.append(f"{random.randint(20, 70)}%\n")
                    # coverage_text.append("New paths       : ")
                    # coverage_text.append(
                    #     f"{random.randint(0, 5)}/cycle\n", style="yellow"
                    # )

                    # crashes_text.append("Bug Finding      : ")
                    # crashes_text.append(f"{self.bug_finding}\n")
                    # crashes_text.append("Timeouts       : ")
                    # crashes_text.append(f"{random.randint(0, 3)}\n")
                    # crashes_text.append("Exceptions     : ")
                    # crashes_text.append(f"{random.randint(0, 5)}\n", style="magenta")

                    # ==== 每次循环重建动态布局 ====

                    content_panels = Group(
                        Panel(
                            stats_text, title="[bold red]Fuzzing Stats", padding=(1, 2)
                        ),
                        # Panel(
                        #     crashes_text, title="[bold yellow]Findings", padding=(1, 2)
                        # ),
                    )

                    main_layout = Columns(
                        [
                            Panel(content_panels, width=90),
                        ]
                    )

                    full_layout = Columns(
                        [Panel(Columns([title_panel, main_layout]), box=box.SIMPLE)]
                    )

                    live.update(full_layout)

        pass
        # 启动线程来接收UDP数据
        udp_thread = threading.Thread(
            target=print_current_dashboard,
        )
        udp_thread.start()
