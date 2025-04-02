# -*- coding: utf-8 -*-
# @Time    : 2025/1/23
# @Author  : h0lyduck

import idautils
import idc
import idaapi
import ida_ua
import ida_idaapi
import ida_name
import ida_bytes
import ida_ida
import ida_funcs
import ida_gdl
import struct
import shutil
import networkx as nx
import json
import os
from enum import Enum, auto


class PROBE_INST(Enum):
    NOP = auto()
    MOVR = auto()
    MOVI = auto()
    ADDR = auto()
    ADDI = auto()
    SUBR = auto()
    SUBI = auto()
    CMPR = auto()
    CMPI = auto()
    B = auto()
    LDRI = auto()
    LDRR = auto()
    LDRO = auto()
    LDRPC = auto()


def get_arm_reg_content(ea, reg_id=0, depth=0xFF):
    try:
        if depth == 0:
            return None
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, ea)
        if insn.Op1.type == idc.o_reg and insn.Op1.reg == reg_id:
            if insn.itype == idaapi.ARM_mov:
                return get_arm_reg_content(idc.prev_head(ea), insn.Op2.reg, depth - 1)
            elif insn.itype == idaapi.ARM_add:
                if insn.Op2.type == idc.o_reg and insn.Op2.reg == 15:
                    ry = ea + 8  # arm采用2级流水线，因此是当前正在执行指令的地址ƒ+8
                    # print(f"ry: {ry:x}")
                else:
                    # print("insn.Op2.reg: ", insn.Op2.reg)
                    ry = get_arm_reg_content(idc.prev_head(ea), insn.Op2.reg, depth - 1)
                if insn.Op3.type == idc.o_reg:
                    rz = get_arm_reg_content(idc.prev_head(ea), insn.Op3.reg, depth - 1)
                    if rz is None or ry is None:
                        return None
                    # print(f"ry+rz: {(ry + rz) & 0xFFFFFFFF:x}")
                    return (ry + rz) & 0xFFFFFFFF
            elif insn.itype == idaapi.ARM_ldr:
                if insn.Op2.type == idc.o_mem:
                    mem = ida_bytes.get_wide_dword(insn.Op2.addr)
                    # print(f"insn.Op2.mem: {mem:x}")
                    return mem
            return None
        else:
            return get_arm_reg_content(idc.prev_head(ea), reg_id, depth - 1)
    except RecursionError:
        return None


class SignalMonitorPatcher:
    def __init__(
        self,
        control_flow_monitared_function_list: list = [],
        called_monitared_function_list: list = [],
        call_nop_function_list: list = [],
        target_dir_path: str = "",
        target_proc_name: str = "",
        output_proc_name: str = "",
        monitor_config_name: str = "monitor.conf",
        fuzzer_config_name: str = "fuzzer_config.json",
        conn_ip: str = "",
        conn_port: int = 0,
    ):
        self.target_dir_path = target_dir_path
        self.target_proc_name = target_proc_name
        # self.target_proc_path = target_proc_path
        self.monitor_config_name = monitor_config_name
        self.output_proc_name = output_proc_name
        self.fuzzer_config_name = fuzzer_config_name
        self.is_be = ida_ida.inf_is_be()
        self.cpuname = ida_ida.inf_get_procname().lower()
        self.conn_ip = conn_ip
        self.conn_port = conn_port
        self.str_cmp_dict = {
            "strcmp": {},
            "strncmp": {},
            "strcasecmp": {},
            "strncasecmp": {},
        }
        self.call_nop_function_list = call_nop_function_list
        self.const_str_list_in_strcmp = []
        if self.cpuname.startswith("arm"):
            self.call_probe_patch_inst = 0xFFE00000
            self.cf_probe_patch_inst = 0xFFD00000
        # todo：mips架构的 illgeal 指令
        elif self.cpuname.startswith("mips"):
            self.call_probe_patch_inst = 0xFFFFFFFF
            self.cf_probe_patch_inst = 0x12121212
        else:
            print("Unsupported Architecture")
            exit(1)
        self.control_flow_monitared_function_list = control_flow_monitared_function_list
        self.control_flow_monitared_function_dict = {}

        self.called_monitared_function_list = called_monitared_function_list
        self.called_monitared_function_dict = {}

    def inst_to_list(self, num: int) -> list:
        """
        将整数转换为字节列表。

        参数:
        - num: 要转换的整数。

        返回:
        - 包含整数字节表示的列表。
        """
        # 判断是否为大端字节序
        if self.is_be:
            # 如果是大端字节序，使用大端字节序打包整数
            byte_data = struct.pack(">I", num)
        else:
            # 如果是小端字节序，使用小端字节序打包整数
            byte_data = struct.pack("<I", num)
        # 将字节数据转换为列表
        result_list = list(byte_data)
        return result_list

    def init_monitor_probe_setup(self) -> None:
        """
        初始化监控探针的设置。

        1. 遍历`control_flow_monitared_function_list`中的函数，生成它们的控制流图，并将这些信息存储在`control_flow_monitared_function_dict`中。
        2. 遍历`called_monitared_function_list`中的函数，将它们的地址、引用和调用探针指令存储在`called_monitared_function_dict`中。
        3. 遍历`called_monitared_function_dict`中的函数，将它们的引用信息添加到`control_flow_monitared_function_dict`中。
        """

        print("[*] init_monitor_probe_setup")
        # 遍历control_flow_monitared_function_list中的函数
        for control_flow_monitared_func in self.control_flow_monitared_function_list:
            # 生成函数的控制流图
            ida_func_cfg = self.gen_func_cfg_by_funcname(control_flow_monitared_func)
            nx_func_cfg = nx.DiGraph()
            nx_func_cfg.graph["has_dangerous_function"] = False
            # 遍历控制流图中的块
            for block in ida_func_cfg:
                block_start_ea = block.start_ea
                block_end_ea = block.end_ea
                block_id = self.get_block_id(block)
                # 将块添加到nx_func_cfg中
                nx_func_cfg.add_node(
                    block_id,
                    start_ea=block_start_ea,
                    end_ea=block_end_ea,
                    is_patch=False,
                    call_monitored_functions=[],
                )
            # 遍历控制流图中的块
            for block in ida_func_cfg:
                block_id = f"{control_flow_monitared_func}_{block.start_ea:x}"
                # 遍历块的后继块
                for succ_block in block.succs():
                    succ_block_id = self.get_block_id(succ_block)
                    # 在nx_func_cfg中添加边
                    nx_func_cfg.add_edge(block_id, succ_block_id, weight=0)
            # 获取函数的地址
            func_addr = ida_name.get_name_ea(
                ida_idaapi.BADADDR, control_flow_monitared_func
            )
            func = ida_funcs.get_func(func_addr)
            func_start_ea = func.start_ea
            func_end_ea = func.end_ea
            # 将函数的信息存储在control_flow_monitared_function_dict中
            self.control_flow_monitared_function_dict[control_flow_monitared_func] = {
                "start_ea": func_start_ea,
                "end_ea": func_end_ea,
                "ida_func_cfg": ida_func_cfg,
                "nx_func_cfg": nx_func_cfg,
                # "call_monitor_function": {},
            }
            # # 遍历called_monitared_function_list中的函数
            # for called_monitared_function in self.called_monitared_function_list:
            #     # 将函数的信息存储在control_flow_monitared_function_dict中
            #     self.control_flow_monitared_function_dict[control_flow_monitared_func][
            #         "call_monitor_function"
            #     ][called_monitared_function] = []

        # 遍历所有函数
        for func in idautils.Functions():
            func_name = ida_name.get_ea_name(func)
            # 如果函数在called_monitared_function_list中
            if ida_name.get_ea_name(func) in self.called_monitared_function_list:
                # 将函数的信息存储在called_monitared_function_dict中, 确定函数的调用探针指令
                self.called_monitared_function_dict[func_name] = {
                    "addr": func,
                    "xrefto": [],
                    "call_probe_patch_inst": self.call_probe_patch_inst,
                }
                # 调用监控探针指令自加
                self.call_probe_patch_inst += 1

        # 遍历called_monitared_function_dict中的函数
        for func_name in self.called_monitared_function_dict:
            # 遍历函数的引用
            for xref in idautils.XrefsTo(
                self.called_monitared_function_dict[func_name]["addr"]
            ):
                # 如果引用类型为17（调用）
                if xref.type == 17:
                    # 获取引用所属的函数
                    inst_belonging_func = ida_funcs.get_func(xref.frm)
                    inst_belonging_func_name = ida_name.get_ea_name(
                        inst_belonging_func.start_ea
                    )
                    # 如果引用所属的函数在control_flow_monitared_function_dict中
                    if inst_belonging_func_name in [
                        x for x in self.control_flow_monitared_function_dict
                    ]:

                        nx_func_cfg = self.control_flow_monitared_function_dict[
                            inst_belonging_func_name
                        ]["nx_func_cfg"]
                        nx_func_cfg.graph["has_dangerous_function"] = True
                        for block_id in nx_func_cfg.nodes:
                            if (
                                nx_func_cfg.nodes[block_id]["start_ea"]
                                <= xref.frm
                                < nx_func_cfg.nodes[block_id]["end_ea"]
                            ):
                                # 将引用信息添加到called_monitared_function_dict中
                                self.called_monitared_function_dict[func_name][
                                    "xrefto"
                                ].append(
                                    {
                                        "type": xref.type,
                                        "type_name": idautils.XrefTypeName(xref.type),
                                        "from": xref.frm,
                                        "to": xref.to,
                                        "block_id": block_id,
                                    }
                                )
                                nx_func_cfg.nodes[block_id][
                                    "call_monitored_functions"
                                ].append(
                                    {
                                        "func_name": func_name,
                                        "call_addr": xref.frm,
                                    }
                                )

        control_flow_monitared_function_dele_list = []
        # 遍历control_flow_monitared_function_dict中的函数
        for control_flow_monitared_func in self.control_flow_monitared_function_dict:
            nx_func_cfg = self.control_flow_monitared_function_dict[
                control_flow_monitared_func
            ]["nx_func_cfg"]
            if nx_func_cfg.graph["has_dangerous_function"] == False:
                control_flow_monitared_function_dele_list.append(
                    control_flow_monitared_func
                )
                # del self.control_flow_monitared_function_dict[
                #     control_flow_monitared_func
                # ]
        for control_flow_monitared_func in control_flow_monitared_function_dele_list:
            del self.control_flow_monitared_function_dict[control_flow_monitared_func]
        print("[*] init_monitor_probe_setup done")

    def get_constant_string_in_strcmp(self):
        print("[*] get_constant_string_in_strcmp")
        for func in idautils.Functions():
            func_name = ida_name.get_ea_name(func)
            # 如果函数在called_monitared_function_list中
            if ida_name.get_ea_name(func) in self.str_cmp_dict:
                # 将函数的信息存储在control_flow_monitared_function_dict中
                func_name = ida_name.get_ea_name(func)
                self.str_cmp_dict[func_name]["addr"] = func
        for func_name in self.str_cmp_dict:
            # print(f"  [+] get_constant_string_in_strcmp func: {func_name}")
            # 遍历函数的引用
            for xref in idautils.XrefsTo(self.str_cmp_dict[func_name]["addr"]):
                # 如果引用类型为17（调用）
                if xref.type == 17:
                    # 获取引用所属的函数
                    inst_belonging_func = ida_funcs.get_func(xref.frm)
                    inst_belonging_func_name = ida_name.get_ea_name(
                        inst_belonging_func.start_ea
                    )
                    # 如果引用所属的函数在control_flow_monitared_function_dict中
                    if inst_belonging_func_name in [
                        x for x in self.control_flow_monitared_function_dict
                    ]:
                        # print(
                        #     f"    str_cmp func: {func_name}, xref: {xref.frm:x}, inst_belonging_func_name: {inst_belonging_func_name}"
                        # )
                        arg_addr_list = idaapi.get_arg_addrs(xref.frm)
                        # print(f"arg_addr_list: {[hex(x) for x in arg_addr_list]}")
                        if self.cpuname.startswith("arm"):
                            if (
                                func_name in ["strcmp", "strcasecmp"]
                                and len(arg_addr_list) == 2
                            ):
                                for reg_id, addr in enumerate(arg_addr_list):
                                    str_addr = get_arm_reg_content(addr, reg_id)
                                    # print(str_addr)
                                    if str_addr is not None:
                                        # print(hex(str_addr))
                                        const_bytes = idc.get_strlit_contents(str_addr)
                                        if const_bytes is not None:
                                            const_str = const_bytes.decode("latin1")
                                            self.const_str_list_in_strcmp.append(
                                                const_str
                                            )
                            elif (
                                func_name in ["strncmp", "strncasecmp"]
                                and len(arg_addr_list) == 3
                            ):
                                for reg_id, addr in enumerate(arg_addr_list):
                                    str_addr = get_arm_reg_content(addr, reg_id)
                                    if str_addr is not None:
                                        const_bytes = idc.get_strlit_contents(str_addr)
                                        if const_bytes is not None:
                                            const_str = const_bytes.decode("latin1")
                                            self.const_str_list_in_strcmp.append(
                                                const_str
                                            )
                        elif self.cpuname.startswith("mips"):
                            # todo
                            pass
        print("[*] get_constant_string_in_strcmp done")

    def call_probe_patch(self) -> None:
        print("[*] call_probe_patch")
        for vuln_func in self.called_monitared_function_dict:
            for xrefto in self.called_monitared_function_dict[vuln_func]["xrefto"]:
                patch_inst = self.inst_to_list(
                    self.called_monitared_function_dict[vuln_func][
                        "call_probe_patch_inst"
                    ]
                )
                for i in range(len(patch_inst)):
                    ida_bytes.patch_byte(xrefto["from"] + i, patch_inst[i])
        print("[*] call_probe_patch done")

    def call_nop_patch(self):
        print("[*] call_nop_patch")
        for func in self.call_nop_function_list:
            func_addr = ida_name.get_name_ea(ida_idaapi.BADADDR, func)
            for xref in idautils.XrefsTo(func_addr):
                if xref.type == 17:
                    if self.cpuname.startswith("arm"):
                        patch_inst = self.inst_to_list(0xe3a00001)
                        for i in range(len(patch_inst)):
                            ida_bytes.patch_byte(xref.frm + i, patch_inst[i])
        print("[*] call_nop_patch Done")

    def get_block_id(self, block) -> str:
        return f"{idc.get_func_name(block.start_ea)}_{block.start_ea:x}"

    def control_flow_probe_patch(self):
        print("[*] control_flow_probe_patch")
        for func in self.control_flow_monitared_function_dict:
            ida_func_cfg = self.control_flow_monitared_function_dict[func][
                "ida_func_cfg"
            ]
            nx_func_cfg = self.control_flow_monitared_function_dict[func]["nx_func_cfg"]
            for block in ida_func_cfg:
                block_start_ea = block.start_ea
                block_end_ea = block.end_ea
                is_patchable_in_current_block = False
                block_id = self.get_block_id(block)
                probe_inst = ""
                patch_inst_addr = 0
                # print(f"[*] current analysis block 0x{block_start_ea:x}")
                for insn_ea in idautils.Heads(block_start_ea, block_end_ea):
                    if self.cpuname.startswith("arm"):
                        res, probe_inst = self.arm_inst_analysis(insn_ea)
                    elif self.cpuname.startswith("mips"):
                        # todo: mips 架构的 illegal 指令
                        pass
                    else:
                        print("Unsuppoted Architecture")
                        exit()
                    if res:
                        is_patchable_in_current_block = True
                        patch_inst_addr = insn_ea
                        break
                if is_patchable_in_current_block:
                    nx_func_cfg.nodes[block_id]["patch_inst_addr"] = patch_inst_addr
                    nx_func_cfg.nodes[block_id][
                        "cf_probe_patch_inst"
                    ] = self.cf_probe_patch_inst
                    self.cf_probe_patch_inst += 1
                    patch_inst = self.inst_to_list(
                        nx_func_cfg.nodes[block_id]["cf_probe_patch_inst"]
                    )
                    for i in range(len(patch_inst)):
                        ida_bytes.patch_byte(patch_inst_addr + i, patch_inst[i])
                    nx_func_cfg.nodes[block_id]["is_patch"] = True
                    nx_func_cfg.nodes[block_id]["probe_inst"] = probe_inst
                else:
                    print(
                        f"[!] No patchable instructions can be found in the current block {block_start_ea:x}"
                    )
                    break

        print("[*] control_flow_probe_patch done")

    def arm_inst_analysis(self, insn_ea):
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, insn_ea)
        # print(insn.itype)
        # print(idaapi.ARM_ldr)

        # Nop eg : NOP
        if insn.itype == idaapi.ARM_nop:  #
            return True, f"{PROBE_INST.NOP.value:x},0,0,0"
        elif insn.itype == idaapi.ARM_mov:
            # Register, inst eg: MOV     R3, R2
            if insn.Op1.type == idc.o_reg and insn.Op2.type == idc.o_reg:
                return (
                    True,
                    f"{PROBE_INST.MOVR.value:x},{insn.Op1.reg:x},{insn.Op2.reg:x},0",
                )
            # Immediate Value, inst eg: MOV     R3, #0
            elif insn.Op1.type == idc.o_reg and insn.Op2.type == idc.o_imm:
                return (
                    True,
                    f"{PROBE_INST.MOVI.value:x},{insn.Op1.reg:x},{insn.Op2.value:x},0",
                )
        elif insn.itype == idaapi.ARM_add:
            # Register, inst eg: ADD     R3, PC, R3
            if (
                insn.Op1.type == idc.o_reg
                and insn.Op2.type == idc.o_reg
                and insn.Op3.type == idc.o_reg
            ):
                return (
                    True,
                    f"{PROBE_INST.ADDR.value:x},{insn.Op1.reg:x},{insn.Op2.reg:x},{insn.Op3.reg:x}",
                )
            # Imm, inst eg: ADD     R3, R3, #1
            elif (
                insn.Op1.type == idc.o_reg
                and insn.Op2.type == idc.o_reg
                and insn.Op3.type == idc.o_imm
            ):
                return (
                    True,
                    f"{PROBE_INST.ADDI.value:x},{insn.Op1.reg:x},{insn.Op2.reg:x},{insn.Op3.value:x}",
                )
        elif insn.itype == idaapi.ARM_sub:
            # Register, inst eg: SUB     R3, R3, R0
            if (
                insn.Op1.type == idc.o_reg
                and insn.Op2.type == idc.o_reg
                and insn.Op3.type == idc.o_reg
            ):
                return (
                    True,
                    f"{PROBE_INST.SUBR.value:x},{insn.Op1.reg:x},{insn.Op2.reg:x},{insn.Op3.reg:x}",
                )
            # Imm, inst eg: SUB     SP, SP, #8
            elif (
                insn.Op1.type == idc.o_reg
                and insn.Op2.type == idc.o_reg
                and insn.Op3.type == idc.o_imm
            ):
                return (
                    True,
                    f"{PROBE_INST.SUBI.value:x},{insn.Op1.reg:x},{insn.Op2.reg:x},{insn.Op3.value:x}",
                )
        elif insn.itype == idaapi.ARM_b:
            if insn.Op1.type == ida_ua.o_near:
                return (True, f"{PROBE_INST.B.value:x},{insn.Op1.addr:x},0,0")
        elif insn.itype == idaapi.ARM_ldr:
            # Inst eg: LDR     R3, =0x87C
            if insn.Op1.type == idc.o_reg and insn.Op2.type == idc.o_mem:
                return (
                    True,
                    f"{PROBE_INST.LDRI.value:x},{insn.Op1.reg:x},{insn.Op2.addr:x},0",
                )
            # Inst eg: LDR     R2, [R3,R2]
            elif insn.Op1.type == idc.o_reg and insn.Op2.type == idc.o_phrase:
                return (
                    True,
                    f"{PROBE_INST.LDRR.value:x},{insn.Op1.reg:x},{insn.Op2.reg:x},{insn.Op2.specflag1:x}",
                )
            # Inst eg: LDR     R0, [R11,#-0x58]
            # Inst eg: LDR     R3, [R3]
            elif insn.Op1.type == idc.o_reg and insn.Op2.type == idc.o_displ:
                return (
                    True,
                    f"{PROBE_INST.LDRO.value:x},{insn.Op1.reg:x},{insn.Op2.reg:x},{insn.Op2.addr:x}",
                )
        # Inst eg: LDR     PC, [R2,R3,LSL#2]
        # elif insn.itype == idaapi.ARM_ldrpc:
        # print(
        #     insn.Op2.type,
        #     idc.o_phrase,
        #     idc.o_displ,
        #     idc.GetDisasm(insn_ea),
        # )
        # if insn.Op1.type == idc.o_reg and insn.Op2.type == idc.o_phrase:
        #     print(insn.Op1.reg)
        #     print(insn.Op2.reg)
        #     print(insn.Op2.value)
        #     print(insn.Op2.specflag1)

        #     return (
        #         True,
        #         f"{PROBE_INST.LDRPC.value:x},{insn.Op2.reg:x},{insn.Op2.specflag1:x},{insn.Op2.value}",
        #     )
        # todo: 添加其他指令作为被插桩指令
        # print("Unsupported instrustion111")
        return False, None

    def mips_inst_analysis(self, insn_ea):
        # todo
        pass

    def apply_patches(self):
        """
        将临时文件中的patch应用到输出文件。

        1. 复制临时文件到输出文件。
        2. 打开输出文件。
        3. 定义一个访问器函数 用于处理每个patch。
        4. 遍历所有patch并应用。
        5. 关闭文件。
        """
        # 复制临时文件到输出文件
        print("[*] apply_patches")
        shutil.copyfile(
            os.path.join(self.target_dir_path, self.target_proc_name),
            os.path.join(self.target_dir_path, self.output_proc_name),
        )
        # 打开输出文件
        with open(
            os.path.join(self.target_dir_path, self.output_proc_name), "r+b"
        ) as f:

            def visitor(ea, file_offset, original_value, patched_value):
                """
                访问器函数，用于处理每个patch。

                参数:
                - ea: 指令地址。
                - file_offset: 文件偏移量。
                - original_value: 原始值。
                - patched_value: patch值。
                """
                # 如果文件偏移量无效
                if file_offset == ida_idaapi.BADADDR:
                    # 打印错误信息
                    print(
                        "%08X: has no file mapping (original: %02X patched: %02X)...skipping...\n"
                        % (ea, original_value, patched_value)
                    )
                    # 返回失败
                    return
                # 定位到文件偏移量
                f.seek(file_offset)
                # 获取指令的位数
                bits = ida_bytes.nbits(ea)
                # 计算字节数
                num_bytes = (bits + 7) // 8
                # 判断字节序
                if ida_ida.inf_is_wide_high_byte_first():
                    byte_order = "big"
                else:
                    byte_order = "little"
                # 将patch值转换为字节数组
                patched_value = patched_value.to_bytes(num_bytes, byte_order)
                # 写入patch值
                f.write(patched_value)
                # 返回成功
                return

            # 遍历所有patch并应用
            ida_bytes.visit_patched_bytes(0, ida_idaapi.BADADDR, visitor)
        print("[*] apply_patches done")

    def gen_func_cfg_by_funcname(self, func_name):
        """
        根据函数名生成函数的控制流图。

        参数:
        - func_name: 函数的名称。

        返回:
        - 函数的控制流图。
        """
        # 根据函数名获取函数地址
        func_addr = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
        # 如果函数地址无效
        if func_addr == ida_idaapi.BADADDR:
            # 打印错误信息
            print(f"[!] Function {func_name} not found.")
            # 抛出异常
            raise ValueError
        # 根据函数地址生成控制流图
        return self.gen_func_cfg_by_funcaddr(func_addr)

    def gen_func_cfg_by_funcaddr(self, func_addr):
        """
        根据函数地址生成函数的控制流图。

        参数:
        - func_addr: 函数的地址。

        返回:
        - 函数的控制流图。
        """
        # 根据函数地址获取函数对象
        func = ida_funcs.get_func(func_addr)
        # 如果函数对象不存在
        if func is None:
            # 打印错误信息
            print(f"[!] Function at address 0x{func_addr:X} not found.")
            # 抛出异常
            raise ValueError
        # 根据函数对象生成控制流图
        graph = ida_gdl.FlowChart(func)
        # 返回控制流图
        return graph

    def gen_monitor_config(self):
        """
        生成监控配置文件。

        1. 打开配置文件。
        2. 导入pwn模块并关闭其输出。
        3. 读取临时文件并判断是否启用PIE。
        4. 写入PIE启用状态。
        5. 写入连接地址。
        6. 遍历调用监控函数的字典并写入调用监控函数的信息。
        7. 遍历控制流监控函数的字典并写入控制流监控函数的信息。
        """
        print("[*] gen_monitor_config")
        # 打开配置文件
        with open(
            os.path.join(self.target_dir_path, self.monitor_config_name), mode="w"
        ) as f:
            # 获取目标程序是否开启地址随机化保护
            import pwn

            with pwn.context.quiet:
                temp_elf = pwn.ELF(
                    os.path.join(self.target_dir_path, self.target_proc_name)
                )
                if temp_elf.pie:
                    f.write(f"pie:{1}\n")
                else:
                    f.write(f"pie:{0}\n")

            # 写入连接地址
            if self.conn_ip != "":
                f.write(f"conn_addr:{self.conn_ip}:{self.conn_port}\n")

            # 遍历调用监控函数的字典
            for func_name in self.called_monitared_function_dict:
                # 获取调用监控函数的指令
                call_probe_patch_inst = self.called_monitared_function_dict[func_name][
                    "call_probe_patch_inst"
                ]
                # 获取调用监控函数的地址
                call_addr = self.called_monitared_function_dict[func_name]["addr"]
                # 写入调用监控函数的信息
                f.write(f"call:{call_probe_patch_inst:x}:{call_addr:x}:{func_name}\n")

            # 遍历控制流监控函数的字典
            for func_name in self.control_flow_monitared_function_dict:
                # 获取控制流监控函数的基本块
                blocks = self.control_flow_monitared_function_dict[func_name][
                    "nx_func_cfg"
                ].nodes
                # 遍历控制流监控函数的节点
                for func_block in blocks:
                    # 获取节点
                    block = blocks[func_block]
                    # 判断是否patch
                    if block["is_patch"]:
                        # 写入控制流监控函数的信息
                        f.write(
                            f"cf:{block['cf_probe_patch_inst']:x}:{block['probe_inst']}:{func_name}\n"
                        )
        print("[*] gen_monitor_config done")

    def gen_fuzzer_config(self):
        """
        生成fuzzer配置文件。
        1. 打开配置文件。
        2. 写入fuzzer的配置信息。
        """
        print("[*] gen_fuzzer_config")
        # 打开配置文件
        fuzzer_config = {
            "cf_monitored_func": {},
            "call_monitored_func": self.called_monitared_function_dict,
            "const_str_list_in_strcmp": self.const_str_list_in_strcmp,
        }
        # print(self.called_monitared_function_dict)
        # for call_monitored_func in self.called_monitared_function_dict:
        #     # print(self.called_monitared_function_dict[monitored_func])
        #     fuzzer_config["call_monitored_func"][call_monitored_func] = {
        #         "addr": self.called_monitared_function_dict[call_monitored_func]["addr"],
        #     }
        for cf_monitored_func in self.control_flow_monitared_function_dict:
            fuzzer_config["cf_monitored_func"][cf_monitored_func] = {
                "nx_func_cfg_json": nx.node_link_data(
                    self.control_flow_monitared_function_dict[cf_monitored_func][
                        "nx_func_cfg"
                    ]
                ),
                "start_ea": self.control_flow_monitared_function_dict[
                    cf_monitored_func
                ]["start_ea"],
                "end_ea": self.control_flow_monitared_function_dict[cf_monitored_func][
                    "end_ea"
                ],
            }

            # print(monitored_func)
            # print(
            #     self.control_flow_monitared_function_dict[monitored_func]["nx_func_cfg"]
            # )

            # pprint(nx.node_link_data(
            #     self.control_flow_monitared_function_dict[monitored_func]["nx_func_cfg"]
            # ))

            # print(
            #     json_graph.dumps(
            #         self.control_flow_monitared_function_dict[monitored_func][
            #             "nx_func_cfg"
            #         ]
            #     )
            # )

        with open(
            os.path.join(self.target_dir_path, self.fuzzer_config_name), mode="w"
        ) as f:
            json.dump(fuzzer_config, f)
        print("[*] gen_fuzzer_config done")


if __name__ == "__main__":
    control_flow_monitared_function_list = ["formSetSambaConf"]
    called_monitared_function_list = ["doSystemCmd"]
    conn_ip = "192.168.0.153"
    conn_port = 8888

    patcher = SignalMonitorPatcher(
        control_flow_monitared_function_list,
        called_monitared_function_list,
        conn_ip,
        conn_port,
    )
    patcher.init_monitor_probe_setup()
    patcher.get_constant_string_in_strcmp()
    patcher.control_flow_probe_patch()
    patcher.call_probe_patch()
    patcher.apply_patches()
    patcher.gen_monitor_config()
    patcher.gen_fuzzer_config()

    # 分析指令
    # print(patcher.arm_inst_analysis(0x1057c))
    # print(patcher.arm_inst_analysis(0x10580))
    # print(patcher.arm_inst_analysis(0x104cc))
    # print(patcher.arm_inst_analysis(0x10690))

    # print(patcher.arm_inst_analysis(0x104C0))
    # print(patcher.arm_inst_analysis(0x105BC))
    # print(patcher.arm_inst_analysis(0x105FC))
    # print(patcher.arm_inst_analysis(0x1065C))
    # patcher.arm_inst_analysis(0x1072C)
    # patcher.arm_inst_analysis(0x1065C)

    # 查找illegal指令
    # from tqdm import *
    # start = 0xffe00000
    # end = 0xffefffff
    # from tqdm import *
    # for i in tqdm(range(start,end+1)):
    #     patch_inst = patcher.inst_to_list(i)
    #     for j in range(len(patch_inst)):
    #         ida_bytes.patch_byte(0x1670+j,patch_inst[j])
    #     if ida_ua.can_decode(0x1670):
    #         print(f'true {i:x} {idc.GetDisasm(0x1670)}')
    # print(ida_ua.can_decode(0x1670))
    # print(patcher.arm_inst_analysis(0x1670))
    # print(patcher.arm_inst_analysis(0x1764))
