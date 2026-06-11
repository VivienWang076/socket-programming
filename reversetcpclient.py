#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TCP 客户端程序
功能：读取文件，按随机长度分块，发送给服务端反转，接收并保存反转后的完整文件
"""

import socket
import struct
import sys
import os
import random
from datetime import datetime

# ==================== 报文类型常量 ====================
TYPE_INITIALIZATION = 1   # 初始化报文
TYPE_AGREE = 2            # 同意报文
TYPE_REVERSE_REQUEST = 3  # 反转请求报文
TYPE_REVERSE_ANSWER = 4   # 反转应答报文

def write_log(message):
    """
    写入运行日志文件 tcp_run_log.txt
    与服务端一样，每条日志带时间戳
    """
    with open("tcp_run_log.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        f.write(f"[{timestamp}] {message}\n")

def read_file_content(filepath):
    """
    读取文件内容
    参数：filepath - 文件路径
    返回：文件内容字符串
    """
    try:
        # 使用 UTF-8 编码打开，符合课设要求的"全英文可打印字符"
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    except UnicodeDecodeError:
        print(f"[-] 文件 {filepath} 非UTF-8编码")
        write_log(f"文件 {filepath} 非UTF-8编码")
        sys.exit(1)
    except PermissionError:
        print(f"[-] 无权限读取文件 {filepath}")
        write_log(f"无权限读取文件 {filepath}")
        sys.exit(1)

def generate_chunk_lengths(total_length, lmin, lmax, seed):
    """
    生成各块的长度（课设核心算法）
    
    原理：
    1. 用给定的随机种子生成可重现的随机序列
    2. 每次在 [lmin, lmax] 区间随机取一个长度
    3. 如果剩余长度 <= lmax，则最后一块取剩余全部
    
    参数：
        total_length: 文件总字节数
        lmin: 最小块长度（除最后一块）
        lmax: 最大块长度
        seed: 随机种子（确保结果可重现）
    返回：
        chunk_lengths: 各块长度列表
        N: 块数
    """
    random.seed(seed)  # 设置随机种子，保证每次运行结果一样
    chunk_lengths = []
    remaining = total_length

    if remaining == 0:
        return chunk_lengths, 0

    while remaining > 0:
        # 如果剩余长度 <= lmax，作为最后一块
        if remaining <= lmax:
            chunk_lengths.append(remaining)
            break
        # 否则在 [lmin, lmax] 区间随机取一个长度
        cur_len = random.randint(lmin, lmax)
        chunk_lengths.append(cur_len)
        remaining -= cur_len

    return chunk_lengths, len(chunk_lengths)

def recv_exact(sock, size):
    """
    精准接收指定字节数
    与服务端的 recv_exact 功能相同
    
    为什么客户端也需要？
    因为接收 reverseAnswer 报文时，也需要收够指定长度的数据
    """
    data = b""
    while len(data) < size:
        try:
            buf = sock.recv(size - len(data))
        except socket.timeout:
            write_log("接收超时")
            return b""
        if not buf:
            write_log("连接断开，接收数据中断")
            return b""
        data += buf
    return data

def main():
    """
    主函数：解析命令行参数，执行分块发送和接收
    """
    # 检查命令行参数：共8个
    # 格式：python client.py <server_ip> <server_port> <file_path> <lmin> <lmax> <chunk_seed> <output_file>
    if len(sys.argv) != 8:
        print("用法: python reversetcpclient.py <server_ip> <server_port> <file_path> <lmin> <lmax> <chunk_seed> <output_file>")
        print("示例: python reversetcpclient.py 127.0.0.1 8888 input.txt 50 100 42 output.txt")
        sys.exit(1)

    # 解析命令行参数
    server_ip = sys.argv[1]           # 服务端 IP（课设要求：host OS 访问 guest OS）
    try:
        server_port = int(sys.argv[2])   # 服务端端口
        lmin = int(sys.argv[4])          # 最小块长度
        lmax = int(sys.argv[5])          # 最大块长度
        chunk_seed = int(sys.argv[6])    # 随机种子
    except ValueError:
        print("[-] 端口、lmin、lmax、seed 必须为整数")
        write_log("参数类型错误：非整数")
        sys.exit(1)

    file_path = sys.argv[3]       # 输入文件路径
    output_file = sys.argv[7]     # 输出文件路径

    # ============ 参数合法性校验 ============
    if not (0 < server_port < 65536):
        print("[-] 端口号范围必须是 1~65535")
        write_log("端口号非法")
        sys.exit(1)
    if lmin <= 0 or lmax < lmin:
        print("错误: lmin > 0 且 lmax >= lmin")
        sys.exit(1)

    # ============ 读取输入文件 ============
    if not os.path.exists(file_path):
        print(f"错误: 文件 {file_path} 不存在")
        sys.exit(1)
    content = read_file_content(file_path)
    total_length = len(content)
    if total_length == 0:
        print("[-] 输入文件为空")
        write_log("输入文件为空")
        sys.exit(1)
    print(f"[*] 文件总长度: {total_length} 字节")

    # ============ 检查输出文件是否已存在 ============
    if os.path.exists(output_file):
        choice = input(f"[!] 输出文件 {output_file} 已存在，是否覆盖？(y/n): ")
        if choice.lower() != 'y':
            print("[*] 程序退出")
            sys.exit(0)

    # ============ 生成分块长度 ============
    # 这是验收时老师会问的关键部分！
    chunk_lengths, N = generate_chunk_lengths(total_length, lmin, lmax, chunk_seed)
    print(f"[*] 块数 N = {N}")
    print(f"[*] 各块长度: {chunk_lengths}")

    # ============ 初始化日志文件 ============
    with open("tcp_run_log.txt", "w", encoding="utf-8") as f:
        f.write(f"=== Client 运行日志 ===\n")
        f.write(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Server: {server_ip}:{server_port}\n")
        f.write(f"文件: {file_path}, 总长度: {total_length}\n")
        f.write(f"Lmin={lmin}, Lmax={lmax}, Seed={chunk_seed}\n")
        f.write(f"N={N}, 各块长度: {chunk_lengths}\n\n")

    # ============ 连接服务端 ============
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(30.0)  # 设置超时30秒
        client_socket.connect((server_ip, server_port)) # 发起TCP三次握手
        print(f"[+] 已连接到服务器 {server_ip}:{server_port}")
        write_log(f"连接到服务器 {server_ip}:{server_port}")
    except socket.timeout:
        print(f"[-] 连接服务器超时")
        write_log("连接服务器超时")
        sys.exit(1)
    except Exception as e:
        print(f"[-] 连接服务器失败: {e}")
        write_log(f"连接失败: {e}")
        sys.exit(1)

    # ============ 第1步：发送 Initialization 报文 ============
    # 格式：Type(2字节) + N(4字节)
    # 告诉服务端要发送 N 块数据
    init_msg = struct.pack('!HI', TYPE_INITIALIZATION, N)
    client_socket.sendall(init_msg)
    print(f"[*] 发送 Initialization 报文: N={N}")
    write_log(f"发送 Initialization 报文: Type={TYPE_INITIALIZATION}, N={N}")

    # ============ 第2步：接收 Agree 报文 ============
    # 格式：Type(2字节)
    # 服务端确认收到初始化信息
    agree_data = recv_exact(client_socket, 2)
    if len(agree_data) != 2:
        print("[-] 未收到完整 Agree 报文")
        write_log("未收到完整 Agree 报文")
        client_socket.close()
        sys.exit(1)

    type_val = struct.unpack('!H', agree_data)[0]
    if type_val != TYPE_AGREE:
        print(f"[-] 期望 Agree 报文，收到 Type={type_val}")
        write_log(f"期望 Agree 报文，收到 Type={type_val}")
        client_socket.close()
        sys.exit(1)

    print(f"[*] 收到 Agree 报文")
    write_log(f"收到 Agree 报文: Type={TYPE_AGREE}")

    # ============ 第3步：循环发送每个数据块并接收反转结果 ============
    offset = 0          # 当前在文件中的偏移量
    # 记录当前读到文件的哪个位置，比如第一块读完 offset=90，第二块从第90字节开始读
    reversed_parts = [] # 收集所有反转后的文本片段，最后用 ''.join() 拼起来
    ok_flag = True      # 是否成功标志

    for i, length in enumerate(chunk_lengths, 1):  # i 从 1 开始
        # 从文件中取出当前块的数据
        # content 是文件内容字符串，用切片取从 offset 到 offset+length 的部分。
        chunk_text = content[offset:offset + length]

        # 编码为字节串（UTF-8）
        try:
            chunk_data = chunk_text.encode('utf-8')
        except Exception as e:
            print(f"[-] 第{i}块编码失败: {e}")
            write_log(f"第{i}块编码失败: {e}")
            ok_flag = False
            break

        # ----- 3.1 发送 reverseRequest 报文 -----
        # 格式：Type(2字节) + Length(4字节) + Data(变长)
        request_msg = struct.pack('!HI', TYPE_REVERSE_REQUEST, len(chunk_data)) + chunk_data
        client_socket.sendall(request_msg)
        print(f"[*] 发送第{i}块: length={len(chunk_data)}, text=\"{chunk_text[:50]}...\"")
        write_log(f"发送 reverseRequest 报文: Type={TYPE_REVERSE_REQUEST}, Length={len(chunk_data)}")

        # ----- 3.2 接收 reverseAnswer 报文头 -----
        # 格式：Type(2字节) + Length(4字节)
        header = recv_exact(client_socket, 6)
        if len(header) != 6:
            print(f"[-] 接收第{i}块应答头失败")
            ok_flag = False
            break

        ans_type, ans_len = struct.unpack('!HI', header)
        # ans_type 应该是 4，ans_len 是反转数据的长度
        
        # 验证报文类型
        if ans_type != TYPE_REVERSE_ANSWER:
            print(f"[-] 期望 reverseAnswer 报文，收到 Type={ans_type}")
            ok_flag = False
            break
        
        # 验证长度一致性（发送的长度和返回的长度应该相等）
        if ans_len != len(chunk_data):
            print(f"[-] 第{i}块长度不匹配：发送{len(chunk_data)}，接收{ans_len}")
            write_log(f"第{i}块长度校验失败")
            ok_flag = False
            break

        # ----- 3.3 接收反转后的数据 -----
        reversed_data = recv_exact(client_socket, ans_len)
        if len(reversed_data) != ans_len:
            print(f"[-] 第{i}块数据接收不完整")
            ok_flag = False
            break

        # 解码为字符串
        reversed_text = reversed_data.decode('utf-8', errors='replace')
        reversed_parts.append(reversed_text)

        # 按要求打印到终端：格式 "块号: 反转后的文本"
        print(f"{i}: {reversed_text}")
        write_log(f"收到 reverseAnswer 报文: Type={TYPE_REVERSE_ANSWER}, Length={ans_len}, Data={reversed_text[:50]}...")
        
        # 更新偏移量，准备处理下一块
        offset += length

    # 如果出错则退出
    if not ok_flag:
        client_socket.close()
        sys.exit(1)

    # ============ 第4步：写入输出文件 ============
    # 将所有反转后的文本片段拼接，写入文件
    full_reversed = ''.join(reversed_parts)
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(full_reversed)
    except PermissionError:
        print(f"[-] 无权限写入 {output_file}")
        write_log(f"写入文件 {output_file} 权限不足")
        client_socket.close()
        sys.exit(1)

    print(f"\n[*] 完成！输出文件: {output_file}")
    write_log(f"完成，输出文件: {output_file}")

    # 关闭连接
    client_socket.close()
    write_log("连接关闭")

if __name__ == "__main__":
    main()