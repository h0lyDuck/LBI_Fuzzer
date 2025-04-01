import math
import Levenshtein
import subprocess
import itertools
import random
import json
import urllib.parse
from collections import Counter

str_fuzz_library = []

class Seed(object):
    def __init__(self, priority, payload):
        self.priority = priority
        self.payload = payload

    def __str__(self):
        return "Seed(priority={p}, name={n})".format(p=self.priority, n=self.payload)

    def __lt__(self, other):
        """定义<比较操作符。"""
        return self.priority < other.priority

    def get_payload(self, payload_type="URL_TYPE"):
        if payload_type == "URL_TYPE":
            return urllib.parse.urlencode(self.payload)
        elif payload_type == "JSON":
            return json.dumps(self.payload)

    def get_payload_value_list(self):
        return list(self.payload.values())

    def mutate(self, score):
        """
        变异函数
        :return:
        """
        self.score = 0 - score
        for key in self.payload:
            rand_num = random.random()
            if rand_num < 0.1:
                self.payload[key] = random.choice(str_fuzz_library)
            elif rand_num < 0.4:
                self.payload[key] = radamsa_mutate(
                    self.payload[key]
                    if isinstance(self.payload[key], str)
                    else str(self.payload[key])
                )



RADAMSA_PATH = "/Users/h0lyduck/Tools/radamsa"
# Function which takes bytes and returns mutated bytes


def get_longest_path(G) -> list:
    """
    寻找有向图中遍历所有边且每条边仅遍历一次的最长路径
    :param G: 输入的有向图
    :return: 最长的遍历路径
    """
    start_nodes = [n for n in G.nodes if G.in_degree(n) == 0]
    assert len(start_nodes) == 1, "图应该只有一个头节点"
    start = start_nodes[0]
    all_paths = []
    edge_counts = {}  # 用于记录每条边出现的次数
    visited_edges = set()

    # def dfs(node, path):
    #     """
    #     深度优先搜索辅助函数
    #     :param node: 当前节点
    #     :param path: 当前已经走过的路径
    #     """
    #     nonlocal edge_counts
    #     nonlocal visited_edges
    #     nonlocal all_paths
    #     for successor in G.successors(node):
    #         edge = (node, successor)
    #         if edge not in visited_edges:
    #             visited_edges.add(edge)
    #             new_path = path + [successor]
    #             if G.out_degree(successor) == 0:
    #                 all_paths.append(new_path)
    #             else:
    #                 dfs(successor, new_path)
    #             visited_edges.remove(edge)
    def dfs(node, path):
        """
        深度优先搜索辅助函数
        :param node: 当前节点
        :param path: 当前已经走过的路径
        """
        nonlocal edge_counts
        nonlocal all_paths
        for successor in G.successors(node):
            edge = (node, successor)
            if edge_counts.get(edge, 0) < 2:
                edge_counts[edge] = edge_counts.get(edge, 0) + 1
                new_path = path + [successor]
                if G.out_degree(successor) == 0:
                    all_paths.append(new_path)
                else:
                    dfs(successor, new_path)
                edge_counts[edge] -= 1

    dfs(start, [start])
    longest = max(all_paths, key=len, default=[])
    return longest


def get_all_paths_from_start_to_target(G, target_node):
    """
    获取有向图G中从头节点到指定节点的所有路径，要求一条边至多出现两次
    :param G: 有向图
    :param target_node: 指定节点
    :return: 从头节点到指定节点的所有路径组成的列表，每条路径是节点的列表形式
    """
    start_nodes = [n for n in G.nodes if G.in_degree(n) == 0]
    assert len(start_nodes) == 1, "图应该只有一个头节点"
    start = start_nodes[0]
    all_paths_list = []
    edge_counts = {}  # 用于记录每条边出现的次数

    def dfs(node, path):
        """
        深度优先搜索的辅助函数
        :param node: 当前节点
        :param path: 当前已经走过的路径
        """
        nonlocal all_paths_list
        nonlocal edge_counts
        if node == target_node:
            all_paths_list.append(path.copy())
            return
        for neighbor in G.neighbors(node):
            edge = (node, neighbor)
            if edge_counts.get(edge, 0) < 2:
                edge_counts[edge] = edge_counts.get(edge, 0) + 1
                new_path = path + [neighbor]
                dfs(neighbor, new_path)
                edge_counts[edge] -= 1

    dfs(start, [start])
    return all_paths_list


def get_forward_edges(G, target_node):
    """
    获取有向图G中指定节点的所有前向边
    :param G: 有向图
    :param target_node: 目标节点
    :return: 目标节点的所有前向边组成的列表
    """
    forward_nodes = []
    for edge in G.edges():
        if edge[1] == target_node:
            forward_nodes.append(edge)
    return forward_nodes


def string_to_vector(s):
    """
    将字符串转换为字符频次向量
    :param s: 字符串
    :return: 字符频次向量（以字典形式表示）
    """
    return Counter(s)


def cosine_similarity(vec1, vec2):
    """
    计算两个向量的余弦相似度
    :param vec1: 第一个向量（字典形式）
    :param vec2: 第二个向量（字典形式）
    :return: 余弦相似度（取值范围在0到1之间，越接近1越相似）
    """
    intersection = set(vec1.keys()) & set(vec2.keys())
    numerator = sum([vec1[x] * vec2[x] for x in intersection])
    sum1 = sum([vec1[x] ** 2 for x in vec1.keys()])
    sum2 = sum([vec2[x] ** 2 for x in vec2.keys()])
    denominator = math.sqrt(sum1) * math.sqrt(sum2)
    if denominator == 0:
        return 0
    return numerator / denominator


def string_similarity_cosine(str1, str2):
    """
    使用余弦相似度计算两个字符串的相似度
    :param str1: 第一个字符串
    :param str2: 第二个字符串
    :return: 相似度（取值范围在0到1之间，越接近1越相似）
    """
    vec1 = string_to_vector(str1)
    vec2 = string_to_vector(str2)
    similarity = cosine_similarity(vec1, vec2)
    return similarity


def string_similarity_levenshtein(str1, str2):
    """
    使用Levenshtein距离计算两个字符串的相似度
    :param str1: 第一个字符串
    :param str2: 第二个字符串
    :return: 相似度（取值范围在0到1之间，越接近1越相似）
    """
    distance = Levenshtein.distance(str1, str2)
    max_length = max(len(str1), len(str2))
    if max_length == 0:
        return 0
    similarity = 1 - distance / max_length
    return similarity


def lcs(str1, str2):
    """
    计算两个字符串的最长公共子序列长度
    :param str1: 第一个字符串
    :param str2: 第二个字符串
    :return: 最长公共子序列长度
    """
    m, n = len(str1), len(str2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if str1[i - 1] == str2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    return dp[m][n]


def string_similarity_lcs(str1, str2):
    """
    使用最长公共子序列计算两个字符串的相似度
    :param str1: 第一个字符串
    :param str2: 第二个字符串
    :return: 相似度（取值范围在0到1之间，越接近1越相似）
    """
    lcs_length = lcs(str1, str2)
    max_len = max(len(str1), len(str2))
    if max_len == 0:
        return 0
    similarity = lcs_length / max_len
    return similarity


def max_string_similarity(input_str, str_list):
    if len(input_str) == 0:
        return 0
    max_sim = 0
    for s in str_list:
        # 使用 difflib 中的 SequenceMatcher 计算相似度
        s = str(s)
        sim = max(
            string_similarity_levenshtein(input_str, s),
            string_similarity_cosine(input_str, s),
            string_similarity_lcs(input_str, s),
        )
        if sim > max_sim:
            max_sim = sim
    return max_sim


def radamsa_mutate(input: str):
    # call radamsa with arguments
    process = subprocess.Popen(
        [RADAMSA_PATH], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    process.stdin.write(input.encode("latin1"))
    process.stdin.close()
    return process.stdout.read()


def generate_init_fuzz_seeds(param_names):
    """
    生成初始模糊测试种子

    :param param_names: 参数名称列表
    :return: 模糊测试种子列表
    """
    # 定义数据类型列表，包含整数和字符串
    data_types = [int, str]
    # 使用itertools.product生成所有可能的数据类型组合
    type_combinations = itertools.product(data_types, repeat=len(param_names))
    # 初始化模糊测试种子列表
    fuzz_seeds = []
    # 遍历所有类型组合
    for type_combination in type_combinations:
        # 为每个类型组合生成3个种子
        for _ in range(3):
            # 初始化种子字典
            seed = {}
            # 遍历参数名称和数据类型
            for param_name, data_type in zip(param_names, type_combination):
                # 如果数据类型是整数
                if data_type == int:
                    # 生成一个随机整数并添加到种子字典
                    seed[param_name] = random.randint(0, 0xFFFFFF)
                # 如果数据类型是字符串
                elif data_type == str:
                    # 从字符串模糊库中随机选择一个字符串并添加到种子字典
                    seed[param_name] = random.choice(str_fuzz_library)
            # 将种子添加到模糊测试种子列表
            fuzz_seeds.append(Seed(-0xFFFFFFFF, seed))
    # 返回模糊测试种子列表
    return fuzz_seeds
