// sudo /usr/local/arm_uclibc_buildroot/bin/arm-buildroot-linux-uclibcgnueabihf-gcc monitor.c cJSON.c -lm -g -fPIC -shared -o ../../test/libmonitor.so.uclibcarm
// sudo /usr/local/arm_uclibc_buildroot/bin/arm-buildroot-linux-uclibcgnueabihf-gcc monitor.c hashtable.c -g -fPIC -shared -o ../../test/libmonitor.so.uclibcarm
// sudo /usr/local/arm_uclibc_buildroot/bin/arm-buildroot-linux-uclibcgnueabihf-gcc monitor.c hashtable.c cJSON.c -lm -g -fPIC -shared -o ../../tenda_ac9/libmonitor.so

// arm-glibc:

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/ucontext.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hashtable.h"
#include "cJSON.h"

char *proc_name_ptr;
char *conn_ip;
int conn_port;
int is_pie_enabled = 0;
unsigned long long int proc_addr_base = 0;
HashTable call_table;
HashTable control_flow_table;
char *maps_ptr;

/**
 * 定义一个枚举类型 PROBE_INST，用于表示不同的探针指令。
 * 每个枚举成员代表一种指令类型，其值为对应的整数值。
 */
enum PROBE_INST
{

  // NOP
  NOP = 1,
  // 移动寄存器到寄存器的指令
  MOVR,
  // 移动立即数到寄存器的指令
  MOVI,
  // 寄存器间的加法的指令
  ADDR,
  // 立即数和寄存器的加法的指令
  ADDI,
  // 寄存器间的减法的指令
  SUBR,
  // 立即数到寄存器的减法的指令
  SUBI,
  // 寄存器间的比较的指令
  CMPR,
  // 寄存器和立即数的比较的指令
  CMPI,
  // 无条件跳转的指令
  B,
  // 从立即数地址加载内存到寄存器的指令
  LDRI,
  // 从基址寄存器和偏移寄存器地址加载内存到寄存器的指令
  LDRR,
  // 从基址寄存器和立即数偏移地址加载内存到寄存器的指令
  LDRO,
  // 从寄存器及偏移地址加载内存到寄存器的指令（目标寄存器是PC寄存器）
  LDRPC,

};

/**
 * 获取程序基地址
 *
 * 该函数通过读取/proc/self/maps文件来查找程序的基地址。
 *
 * @param proc_name 程序的名称
 * @return 返回程序的基地址，如果失败则返回0
 */
unsigned long long int get_program_base_address(char *proc_name)
{
  // 打开/proc/self/maps文件
  FILE *fp = fopen("/proc/self/maps", "r");
  // 检查文件是否成功打开
  if (fp == NULL)
  {
    // 打印错误信息
    perror("[-] Failed to open /proc/self/maps");
    // 返回0表示失败
    return 0;
  }

  // 定义一个缓冲区来存储读取的每一行
  char line[256];
  // 逐行读取文件内容
  while (fgets(line, sizeof(line), fp))
  {
    // 查找包含程序名称的行，即可执行的代码段
    if (strstr(line, proc_name) != NULL)
    {
      // 定义变量来存储起始地址和结束地址
      unsigned long long int start_address, end_address;
      // 从行中提取起始地址和结束地址
      sscanf(line, "%llx-%llx", &start_address, &end_address);
      // 关闭文件
      fclose(fp);
      // 返回起始地址作为程序基地址
      return start_address;
    }
  }
  // 如果没有找到匹配的行，关闭文件并返回0
  fclose(fp);
  return 0;
}

/**
 * 判断给定地址是否在/proc/self/maps中的某个映射地址范围内
 *
 * @param address 要检查的地址
 * @return 如果地址在映射范围内返回1，否则返回0
 */
int is_in_proc_maps_range(unsigned long long address)
{
  // 打开/proc/self/maps文件
  FILE *fp;
  // 定义一个缓冲区来存储读取的每一行
  char line[0x1000];
  // 定义一个指针来存储解析后的token
  void *token;
  // 定义变量来存储起始地址和结束地址
  unsigned long long start_addr, end_addr;

  // 打开/proc/self/maps文件
  fp = fopen("/proc/self/maps", "r");
  // 检查文件是否成功打开
  if (fp == NULL)
  {
    // 打印错误信息
    perror("[-] Failed to open /proc/self/maps");
    // 返回0表示失败
    return 0;
  }

  // 逐行读取文件内容
  while (fgets(line, 1024, fp) != NULL)
  {
    // 使用strtok函数解析起始地址
    token = strtok((char *)line, "-");
    // 检查解析结果是否为空
    if (token != NULL)
    {
      // 将解析后的字符串转换为无符号长整型
      start_addr = strtoull(token, NULL, 16);
      // 使用strtok函数解析结束地址
      token = strtok(NULL, " ");
      // 检查解析结果是否为空
      if (token != NULL)
      {
        // 将解析后的字符串转换为无符号长整型
        end_addr = strtoull(token, NULL, 16);
        // 检查地址是否在映射范围内
        if (address >= start_addr && address <= end_addr)
        {
          // 关闭文件
          fclose(fp);
          // 返回1表示地址在映射范围内
          return 1;
        }
      }
    }
  }
  // 关闭文件
  fclose(fp);
  // 返回0表示地址不在映射范围内
  return 0;
}

/**
 * 发送UDP消息到指定的目标IP和端口
 *
 * @param target_ip 目标IP地址
 * @param target_port 目标端口号
 * @param message 要发送的消息内容
 * @return 成功发送返回0，否则返回-1
 */
int send_udp_message(const char *target_ip, int target_port, const char *message)
{
  // 创建UDP套接字
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  // 检查套接字是否创建成功
  if (sockfd < 0)
  {
    perror("[-] socket creation failed");
    return -1;
  }

  // 配置目标地址结构体
  struct sockaddr_in server_addr;
  // 清空结构体
  memset(&server_addr, 0, sizeof(server_addr));
  // 设置地址族为IPv4
  server_addr.sin_family = AF_INET;
  // 设置端口号
  server_addr.sin_port = htons(target_port);
  // 将目标IP地址转换为网络字节序并存储在结构体中
  if (inet_pton(AF_INET, target_ip, &server_addr.sin_addr) <= 0)
  {
    // 打印错误信息
    perror("[-] inet_pton error");
    // 关闭套接字
    close(sockfd);
    // 返回-1表示失败
    return -1;
  }

  // 发送UDP数据报
  ssize_t bytes_sent = sendto(sockfd, message, strlen(message), 0,
                              (struct sockaddr *)&server_addr, sizeof(server_addr));
  // 检查数据是否发送成功
  if (bytes_sent < 0)
  {
    // 打印错误信息
    perror("sendto failed");
    // 关闭套接字
    close(sockfd);
    // 返回-1表示失败
    return -1;
  }

  // 关闭套接字
  close(sockfd);
  // 返回0表示成功
  return 0;
}

#ifdef __aarch64__
#elif __ARM_ARCH
#elif _MIPS_ARCH
#endif

void call_monitor_handler(int sig_no, siginfo_t *info, void *vcontext)
{
  cJSON *root, *parameter_reg_item[5];
  unsigned long long int pc, parameter_reg_value[10], call_addr;
  char temp[0x10], temp2[0x10];
  int i;
  ucontext_t *context = (ucontext_t *)vcontext;
// record context register value
#ifdef __aarch64__
  pc = context->uc_mcontext.pc;
  for (i = 0; i < 8; i++)
  {
    parameter_reg_value[i] = context->uc_mcontext.regs[i];
  }
#elif __ARM_ARCH
  pc = (unsigned long int)context->uc_mcontext.arm_pc;
  parameter_reg_value[0] = context->uc_mcontext.arm_r0;
  parameter_reg_value[1] = context->uc_mcontext.arm_r1;
  parameter_reg_value[2] = context->uc_mcontext.arm_r2;
  parameter_reg_value[3] = context->uc_mcontext.arm_r3;
#elif _MIPS_ARCH
  pc = (unsigned int)context->uc_mcontext.pc;
  for (i = 0; i < 4; i++)
  {
    parameter_reg_value[i] = context->uc_mcontext.gregs[4 + i]; // a0～a3 4～7
  }
#endif

#ifdef __aarch64__
  // lr = pc+4 ? lr = pc - 4
  context->uc_mcontext.regs[30] = pc + 4;
  // pc = call_funtion_addr
  // 预存目标函数地址直接设为 pc
  if (hashtable_search(&call_table, *(unsigned int *)pc, SEARCH_NUMBER, &call_addr))
  {
    // printf("[*] new_pc(0x%llx)\n", proc_addr_base + call_addr);
    context->uc_mcontext.pc = proc_addr_base + call_addr;
  }
  else
  {
    printf("[-] call hash table did not record call addr(0x%x)\n", *(unsigned int *)pc);
  }
  // context->uc_mcontext.pc = proc_addr_base + 0x1968;
#elif __ARM_ARCH
  // lr = pc+4
  context->uc_mcontext.arm_lr = (unsigned long int)pc + 4;

  // pc = call_funtion_addr
  // 预存目标函数地址直接设为 pc
  if (hashtable_search(&call_table, *(unsigned int *)pc, SEARCH_NUMBER, &call_addr))
  {
    // context->uc_mcontext.arm_pc = (unsigned long int)proc_addr_base + (unsigned long int)call_addr;
    context->uc_mcontext.arm_pc = (unsigned long int)proc_addr_base + (unsigned long int)call_addr;
    // printf("[*] new_pc(0x%lx)\n", context->uc_mcontext.arm_pc);
  }
  else
  {
    printf("[-] call hash table did not record call addr(0x%x)\n", *(unsigned int *)pc);
    exit(-1);
  }
#elif _MIPS_ARCH
#endif

  root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "type", "call_probe");
  memset(temp, 0, sizeof(temp));
#ifdef __aarch64__
  snprintf(temp, 0x10, "%llx", pc - proc_addr_base);
#elif __ARM_ARCH
  snprintf(temp, 0x10, "%lx", (unsigned long int)(pc - proc_addr_base));
#elif _MIPS_ARCH
  snprintf(temp, 0x10, "%x", (unsigned int)(pc - proc_addr_base));
#endif
  cJSON_AddStringToObject(root, "pc", temp);

  memset(temp2, 0, sizeof(temp2));
#ifdef __aarch64__
  snprintf(temp2, 0x10, "%llx", call_addr);
#elif __ARM_ARCH
  snprintf(temp2, 0x10, "%lx", (unsigned long int)call_addr);
#elif _MIPS_ARCH
  snprintf(temp2, 0x10, "%x", (unsigned int)call_addr);
#endif
  cJSON_AddStringToObject(root, "call_addr", temp2);

  for (i = 0; i < 4; i++)
  {
    snprintf(temp, 8, "a%d", i);
    cJSON_AddItemToObject(root, temp, parameter_reg_item[i] = cJSON_CreateObject());
    if (is_in_proc_maps_range(parameter_reg_value[i]))
    {
      cJSON_AddStringToObject(parameter_reg_item[i], "type", "pointer");
      memset(temp, 0, sizeof(temp));
      snprintf(temp, 0x10, "%llx", parameter_reg_value[i]);
      cJSON_AddStringToObject(parameter_reg_item[i], "addr", temp);
      cJSON_AddStringToObject(parameter_reg_item[i], "value", (char *)parameter_reg_value[i]);
    }
    else
    {
      cJSON_AddStringToObject(parameter_reg_item[i], "type", "value");
      memset(temp, 0, sizeof(temp));
      snprintf(temp, 0x10, "%llx", parameter_reg_value[i]);
      cJSON_AddStringToObject(parameter_reg_item[i], "value", temp);
    }
  }
  char *s = cJSON_PrintUnformatted(root);
  if (s)
  {
    send_udp_message(conn_ip, conn_port, s);
    // printf("%s\n", s);
    free(s);
  }
  if (root)
  {
    cJSON_Delete(root);
  }
}

void control_flow_monitor_handler(int sig_no, siginfo_t *info, void *vcontext)
{
  cJSON *root;
  unsigned long long int pc, opcode, operand1, operand2, operand3;
  unsigned long int *arm_regs;
  char temp[0x100], *probe_inst, *token, *next_token;

  int i;
  ucontext_t *context = (ucontext_t *)vcontext;
#ifdef __aarch64__
  pc = context->uc_mcontext.pc;
#elif __ARM_ARCH
  pc = context->uc_mcontext.arm_pc;
  arm_regs = (unsigned long int *)&context->uc_mcontext.arm_r0;
#elif _MIPS_ARCH
  pc = context->uc_mcontext.pc;
#endif
  if (hashtable_search(&control_flow_table, *(unsigned int *)pc, SEARCH_STRING, &probe_inst))
  {
    token = probe_inst;
    opcode = strtoull(token, &next_token, 16);
    token = next_token + 1;

    operand1 = strtoull(token, &next_token, 16);
    token = next_token + 1;

    operand2 = strtoull(token, &next_token, 16);
    token = next_token + 1;

    operand3 = strtoull(token, &next_token, 16);
    token = next_token + 1;
    // printf("[!!!!!!!] LDRO : %llx: %llx %llx %llx\n", opcode, operand1, operand2, operand3);
    switch (opcode)
    {
#ifdef __aarch64__
    // todo: arm64架构指令
    case NOP:
      context->uc_mcontext.pc = pc + 4;
      break;
#elif __ARM_ARCH
    case NOP:
      context->uc_mcontext.arm_pc = (unsigned long int)pc + 4;
      break;
    case MOVR:
      arm_regs[operand1] = arm_regs[operand2];
      // ((unsigned long int *)&context->uc_mcontext.arm_r0)[operand1] = ((unsigned long *)&context->uc_mcontext.arm_r0)[operand2];
      context->uc_mcontext.arm_pc = (unsigned long int)pc + 4;
      break;
    case MOVI:
      arm_regs[operand1] = (unsigned long int)operand2;
      // ((unsigned long int *)&context->uc_mcontext.arm_r0)[operand1] = (unsigned long int)operand2;
      context->uc_mcontext.arm_pc = (unsigned long int)pc + 4;
      break;
    case ADDR:
      arm_regs[operand1] = arm_regs[operand2] + arm_regs[operand3];
      // ((unsigned long int *)&context->uc_mcontext.arm_r0)[operand1] = ((unsigned long *)&context->uc_mcontext.arm_r0)[operand2] + ((unsigned long *)&context->uc_mcontext.arm_r0)[operand2];
      context->uc_mcontext.arm_pc = (unsigned long int)pc + 4;
      break;
    case ADDI:
      arm_regs[operand1] = arm_regs[operand2] + (unsigned long int)operand3;
      // ((unsigned long int *)&context->uc_mcontext.arm_r0)[operand1] = ((unsigned long *)&context->uc_mcontext.arm_r0)[operand2] + (unsigned long int)operand3;
      context->uc_mcontext.arm_pc = (unsigned long int)pc + 4;
      break;
    case SUBR:
      arm_regs[operand1] = arm_regs[operand2] - arm_regs[operand3];
      // ((unsigned long int *)&context->uc_mcontext.arm_r0)[operand1] = ((unsigned long *)&context->uc_mcontext.arm_r0)[operand2] - ((unsigned long *)&context->uc_mcontext.arm_r0)[operand2];
      context->uc_mcontext.arm_pc = (unsigned long int)pc + 4;
      break;
    case SUBI:
      arm_regs[operand1] = arm_regs[operand2] - (unsigned long int)operand3;
      // ((unsigned long int *)&context->uc_mcontext.arm_r0)[operand1] = ((unsigned long *)&context->uc_mcontext.arm_r0)[operand2] - (unsigned long int)operand3;
      context->uc_mcontext.arm_pc = (unsigned long int)pc + 4;
      break;
    case B:
      context->uc_mcontext.arm_pc = (unsigned long int)operand1 + (unsigned long int)proc_addr_base;
      break;
    case LDRI:
      arm_regs[operand1] = *(unsigned long *)((unsigned long int)operand2 + (unsigned long int)proc_addr_base);
      // ((unsigned long int *)&context->uc_mcontext.arm_r0)[operand1] = *(unsigned long *)((unsigned long int)operand2 + (unsigned long int)proc_addr_base);
      context->uc_mcontext.arm_pc = (unsigned long int)pc + 4;
      break;
    case LDRR:
      arm_regs[operand1] = *(unsigned long *)((unsigned long int)arm_regs[operand2] + (unsigned long int)arm_regs[operand3]);
      // ((unsigned long int *)&context->uc_mcontext.arm_r0)[operand1] = *(unsigned long *)(((unsigned long *)&context->uc_mcontext.arm_r0)[operand2] + ((unsigned long *)&context->uc_mcontext.arm_r0)[operand3]);
      context->uc_mcontext.arm_pc = (unsigned long int)pc + 4;
      break;
    case LDRO:
      arm_regs[operand1] = *(unsigned long *)((unsigned long int)arm_regs[operand2] + (unsigned long int)operand3);
      // printf("[*] LDRO: %lx %lx %lx %lx\n", arm_regs[operand1], arm_regs[operand2], (unsigned long int)operand3, *(unsigned long *)((unsigned long int)arm_regs[operand2] + (unsigned long int)operand3));
      // printf("[*] LDRO: %llx %llx %llx %llx\n", arm_regs[operand1], arm_regs[operand2], (unsigned long int)operand3, *(unsigned long *)((unsigned long int)arm_regs[operand2] + (unsigned long int)operand3));
      // ((unsigned long int *)&context->uc_mcontext.arm_r0)[operand1] = *(unsigned long *)((unsigned long *)&context->uc_mcontext.arm_r0)[operand2] + ((unsigned long int)operand3);
      context->uc_mcontext.arm_pc = (unsigned long int)pc + 4;
      break;
#elif _MIPS_ARCH
    // todo: mips架构指令
    case NOP:
      context->uc_mcontext.pc = pc + 4;
      break;
#endif
    default:
      puts("[-] Unsupported Probe instruction");
      exit(0);
      break;
    }
    free(probe_inst);
  }
  else
  {
    printf("[-] control flow hash table did not record probe inst(0x%x)\n", *(unsigned int *)pc);
    exit(1);
  }

  root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "type", "cf_probe");
  memset(temp, 0, sizeof(temp));
#ifdef __aarch64__
  snprintf(temp, 0x10, "%llx", pc - proc_addr_base);
#elif __ARM_ARCH
  snprintf(temp, 0x10, "%lx", (unsigned long int)(pc - proc_addr_base));
#elif _MIPS_ARCH
  snprintf(temp, 0x10, "%x", (unsigned int)(pc - proc_addr_base));
#endif
  cJSON_AddStringToObject(root, "pc", temp);

  char *s = cJSON_PrintUnformatted(root);
  if (s)
  {
    send_udp_message(conn_ip, conn_port, s);
    // printf("%s\n", s);
    free(s);
  }
  if (root)
  {
    cJSON_Delete(root);
  }
}

/**
 * 信号处理函数，用于处理非法指令信号
 *
 * @param sig_no 信号编号
 * @param info 信号信息结构体
 * @param vcontext 上下文信息
 * @return 无返回值
 */
void monitor_handler(int sig_no, siginfo_t *info, void *vcontext)
{
  // 将上下文信息转换为ucontext_t类型
  ucontext_t *context = (ucontext_t *)vcontext;
  // 定义变量存储程序计数器（PC）的值
  unsigned long long int pc;
  // 定义变量存储处理类型，1表示调用监控类型，2表示控制流监控类型
  int handle_type = 0;

#ifdef __aarch64__
  // 获取程序计数器（PC）的值
  pc = context->uc_mcontext.pc;
  // 检查非法指令是否与0xffe00000匹配，表示调用监控类型
  if ((*(unsigned int *)pc & 0xffe00000) == 0xffe00000)
  {
    handle_type = 1;
  }
  // 检查非法指令是否与0xffd00000匹配，表示控制流监控类型
  else if ((*(unsigned int *)pc & 0xffd00000) == 0xffd00000)
  {
    handle_type = 2;
  }
  // printf("[*] illegal_ins pc:%llx handle_type:%d pc_value:%x\n", pc, handle_type, *(unsigned int *)pc);
#elif __ARM_ARCH
  // 获取程序计数器（PC）的值
  pc = context->uc_mcontext.arm_pc;
  // 检查非法指令是否与0xffe00000匹配，表示调用监控类型
  if ((*(unsigned int *)pc & 0xffe00000) == 0xffe00000)
  {
    handle_type = 1;
  }
  // 检查非法指令是否与0xffd00000匹配，表示控制流监控类型
  else if ((*(unsigned int *)pc & 0xffd00000) == 0xffd00000)
  {
    handle_type = 2;
  }
  // printf("[*] illegal_ins pc:%lx handle_type:%d pc_value:%x\n", (unsigned long int)pc, handle_type, *(unsigned int *)pc);
#elif _MIPS_ARCH
  // 获取程序计数器（PC）的值
  pc = context->uc_mcontext.pc;
  // todo: 添加MIPS架构下的处理逻辑

  // printf("[*] illegal_ins pc:%lx handle_type:%d pc_value:%x\n", (unsigned int)pc, handle_type, *(unsigned int *)pc);
#endif

  // 根据处理类型调用相应的处理函数
  if (handle_type == 1)
  {
    call_monitor_handler(sig_no, info, vcontext);
  }
  else if (handle_type == 2)
  {
    control_flow_monitor_handler(sig_no, info, vcontext);
  }
  else
  {
    puts("[*]Illegal instruction");
    exit(-1);
  }
}

/**
 * 初始化监控器配置
 *
 * 该函数从配置文件和进程信息中读取必要的参数，用于初始化监控器的配置。
 *
 * @return 无返回值
 */
void init_config()
{
  FILE *fd_monitor_conf, *fd_proc_comm;
  char line[0x1000], *s_value;
  void *token;
  unsigned int key, value;
  int len;

  // 打开/proc/self/comm文件以读取进程名称
  fd_proc_comm = fopen("/proc/self/comm", "r");
  // 检查文件是否成功打开
  if (fd_proc_comm == NULL)
  {
    // 打印错误信息
    perror("Failed to open /proc/self/comm");
    // 退出程序，返回错误码-1
    exit(-1);
  }
  // 逐行读取文件内容
  while (fgets(line, 1024, fd_proc_comm) != NULL)
  {
    // 将读取的行复制到proc_name_ptr中
    proc_name_ptr = strdup(line);
    // 获取字符串长度
    len = strlen(proc_name_ptr);
    // 检查字符串是否以换行符结尾
    if (len > 0 && proc_name_ptr[len - 1] == '\n')
    {
      // 去除换行符
      proc_name_ptr[len - 1] = '\0';
    }
  }
  // 关闭文件
  fclose(fd_proc_comm);

  // 打开/tmp/monitor.conf文件以读取监控器配置
  fd_monitor_conf = fopen("/tmp/monitor.conf", "r");
  // 检查文件是否成功打开
  if (fd_monitor_conf == NULL)
  {
    // 打印错误信息
    perror("Failed to open /tmp/monitor.conf");
    // 退出程序，返回错误码-1
    exit(-1);
  }

  // 逐行读取文件内容
  while (fgets(line, 1024, fd_monitor_conf) != NULL)
  {
    // 检查是否是conn_addr配置项
    if (!strncmp(line, "conn_addr", 9))
    {
      // 使用strtok函数解析配置项
      token = strtok(line, ":");
      token = strtok(NULL, ":");
      // 将解析后的IP地址复制到conn_ip中
      conn_ip = strdup(token);
      token = strtok(NULL, ":"); // port
      // 将解析后的端口号转换为整数并存储在conn_port中
      conn_port = strtol(token, NULL, 10);
    }
    // 检查是否是is_pie_enable配置项
    else if (!strncmp(line, "pie", 3))
    {
      // 使用strtok函数解析配置项
      token = strtok(line, ":"); // is_pie_enable
      token = strtok(NULL, ":");
      // 将解析后的字符串转换为整数并存储在is_pie_enabled中
      is_pie_enabled = strtol(token, NULL, 10);
    }
    // 检查是否是call配置项
    else if (!strncmp(line, "call", 4))
    {
      // 使用strtok函数解析配置项
      token = strtok(line, ":");
      token = strtok(NULL, ":");
      // 检查解析结果是否为空
      if (token != NULL)
      {
        // 将解析后的字符串转换为无符号整数并存储在key中
        key = strtoull(token, NULL, 16);
        token = strtok(NULL, ":");
        // 检查解析结果是否为空
        if (token != NULL)
        {
          // 将解析后的字符串转换为无符号整数并存储在value中
          value = strtoull(token, NULL, 16);

          // 将键值对插入到call_table哈希表中
          hashtable_insert_number(&call_table, key, value);
        }
      }
    }
    // 检查是否是control_flow配置项
    else if (!strncmp(line, "cf", 2))
    {
      // 使用strtok函数解析配置项
      token = strtok(line, ":");
      token = strtok(NULL, ":");
      // 检查解析结果是否为空
      if (token != NULL)
      {
        // 将解析后的字符串转换为无符号整数并存储在key中
        key = strtoull(token, NULL, 16);
        token = strtok(NULL, ":");
        // 检查解析结果是否为空
        if (token != NULL)
        {
          // 将解析后的字符串复制到s_value中
          s_value = strdup(token);

          // 将键值对插入到control_flow_table哈希表中
          hashtable_insert_string(&control_flow_table, key, s_value);
          // 释放s_value的内存
          free(s_value);
        }
      }
    }
  }
  // 关闭文件
  fclose(fd_monitor_conf);
}

/**
 * 初始化监控器
 *
 * 该函数在库加载时被调用，用于初始化监控器的配置和信号处理。
 *
 * @return 无返回值
 */
void __attribute__((constructor)) init_monitor()
{
  // 定义一个sigaction结构体，用于配置信号处理
  struct sigaction sig_action;
  printf("[*] libmonitor.so loaded!\n");

  // 调用init_config函数，初始化监控器的配置
  init_config();
  // 检查proc_name_ptr是否为空
  if (proc_name_ptr)
  {
    printf("[*] proc name: %s\n", proc_name_ptr);

    // 检查是否启用PIE（Position Independent Executable）
    if (is_pie_enabled)
    {
      // 获取程序的基地址
      proc_addr_base = get_program_base_address(proc_name_ptr);
      printf("[*] PIE is enabled, proc addr base: 0x%llx\n", proc_addr_base);
    }
    else
    {
      // 将程序基地址设置为0
      proc_addr_base = 0;
      printf("[*] PIE is disable.\n");
    }

    // 清空sig_action结构体
    memset(&sig_action, 0, sizeof(sig_action));
    // 设置信号处理函数为monitor_handler
    sig_action.sa_sigaction = monitor_handler;
    // 设置信号处理标志为SA_RESTART和SA_SIGINFO
    sig_action.sa_flags = SA_RESTART | SA_SIGINFO;
    // 清空信号掩码
    sigemptyset(&sig_action.sa_mask);
    // 注册SIGILL信号的处理函数
    sigaction(SIGILL, &sig_action, 0);
    // while(1){
    // }
  }
  else
  {
    puts("[-] proc_name_ptr is NULL");
    exit(-1);
  }
}
