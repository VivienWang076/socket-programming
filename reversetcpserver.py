#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TCP 服务端程序
功能：接收客户端的反转请求，将文本反转后返回
支持多客户端并发处理
"""

import socket      # 提供 TCP socket 编程接口
import threading   # 提供多线程支持，用于同时处理多个客户端
import struct      # 提供二进制数据的打包/解包功能（网络字节序）
import sys         # 提供命令行参数 sys.argv
from datetime import datetime  # 提供时间戳，用于日志记录

# ==================== 报文类型常量 ====================
# 定义4种报文类型，用数字区分
TYPE_INITIALIZATION = 1   # 初始化报文：客户端告诉服务端要发几块数据
TYPE_AGREE = 2            # 同意报文：服务端确认收到初始化信息
TYPE_REVERSE_REQUEST = 3  # 反转请求报文：客户端发送一块数据请求反转
TYPE_REVERSE_ANSWER = 4   # 反转应答报文：服务端返回反转后的数据

# 日志文件锁：防止多线程同时写入日志时内容混乱
# 因为服务端用多线程处理多个客户端，如果同时写日志会乱
# 这个锁保证同一时刻只有一个线程能写日志，其他线程必须等待
log_lock = threading.Lock()

def write_log(message):
    """
    写入运行日志文件 tcp_run_log.txt
    每条日志都带时间戳，精确到毫秒
    用于与 Wireshark 抓包的时间戳相互印证
    """
    with log_lock:  # 加锁，确保同一时间只有一个线程写日志
        with open("tcp_run_log.txt", "a", encoding="utf-8") as f:  # a 模式表示追加写入
            # 生成时间戳：年-月-日 时:分:秒.毫秒（取前3位毫秒）
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            f.write(f"[{timestamp}] {message}\n")

def reverse_string(s):
    """
    反转字符串
    例如：输入 "hello" 返回 "olleh"
    这是课设的核心功能
    """
    return s[::-1]  # Python 切片语法，从头到尾以步长-1反转

def recv_exact(sock, size):
    """
    精准接收指定字节数的数据
    为什么要这个函数？
    因为 TCP 是流式协议，sock.recv(1024) 可能只收到部分数据
    例如：服务器想收100字节，但网络慢可能只收到了50字节
    这个函数会循环接收，直到收够 size 字节才返回
    
    参数：
        sock: socket 对象
        size: 要接收的字节数
    返回：
        接收到的完整数据（字节串），如果失败则返回空字节串
    """
    data = b""  # 空字节串，用于累积接收的数据
    while len(data) < size:  # 只要还没收够size字节就继续循环
        try:
            # 尝试接收剩余的数据
            # size - len(data) = 还需要多少字节
            buf = sock.recv(size - len(data))
        except socket.timeout:
            write_log("接收超时")  # 超时记录日志
            return b"" # 超时返回空
        if not buf:  # 对方断开连接，buf 为空
            write_log("连接断开")
            return b""
        data += buf  # 把刚收到的数据拼接到已有数据后面
    return data

def handle_client(client_socket, client_address):
    """
    处理单个客户端的所有请求
    这个函数会在一个新的线程中运行，实现多客户端并发
    
    参数：
        client_socket: 与该客户端通信的 socket 对象
        client_address: 客户端的 IP 和端口，如 ('172.20.0.1', 61678)
    """
    # 第1段：超时设置&连接日志
    # 设置接收超时 30 秒，防止客户端恶意不发送数据导致线程卡死
    client_socket.settimeout(30.0) # 30 秒无数据则抛异常
    print(f"[+] 新客户端连接: {client_address}")
    write_log(f"客户端连接: {client_address}")

    # 第2段：收Initialization
    try: 
        # ============ 接收 Initialization 报文 ============
        # Initialization 报文格式：Type(2字节) + N(4字节) = 共6字节
        # Type=1, N 表示客户端要发多少块数据
        init_data = recv_exact(client_socket, 6) # 从client_socket这个网络连接中读取 6 字节数据
        if len(init_data) < 6:
            print(f"[-] 接收 Initialization 报文失败")
            return

        # 解包：! 表示网络字节序（大端），H 表示 unsigned short(2字节)，I 表示 unsigned int(4字节)
        # type_val !H解析前两个字节，N !I解析后4字节
        type_val, N = struct.unpack('!HI', init_data)
        
        # 验证报文类型是否正确
        if type_val != TYPE_INITIALIZATION: # 校验 Type == 1，否则非法连接直接退出
            print(f"[-] 期望 Initialization 报文，收到 Type={type_val}")
            return

        print(f"[*] 收到 Initialization 报文: N={N}")
        write_log(f"收到 Initialization 报文: Type={type_val}, N={N}")

        # ============ 发送 Agree 报文 ============
        # Agree 报文格式：Type(2字节) = 共2字节
        # Type=2
        agree_msg = struct.pack('!H', TYPE_AGREE)  # 打包：!H 表示2字节无符号整数
        client_socket.sendall(agree_msg)  # sendall 保证全部发送，不会只发一部分
        print(f"[*] 发送 Agree 报文")
        write_log(f"发送 Agree 报文: Type={TYPE_AGREE}")

        # ============ 循环处理每个数据块 ============
        # block_num 从 1 到 N，逐个处理
        for block_num in range(1, N + 1):
            
            # ----- 1 接收 reverseRequest 报文头 -----
            # reverseRequest 报文头：Type(2字节) + Length(4字节) = 共6字节
            # Type=3, Length 表示后面 Data 的长度
            header = recv_exact(client_socket, 6)
            if len(header) < 6:
                print(f"[-] 接收第{block_num}块报文头失败")
                return

            req_type, length = struct.unpack('!HI', header)
            
            # 验证报文类型
            if req_type != TYPE_REVERSE_REQUEST:
                print(f"[-] 期望 reverseRequest 报文，收到 Type={req_type}")
                return

            # ----- 2 接收 Data 数据体 -----
            # 根据报文头中的 Length 字段，接收对应长度的数据
            data = recv_exact(client_socket, length)
            if len(data) < length:
                print(f"[-] 第{block_num}块数据接收不完整")
                return

            # 将字节串解码为字符串（UTF-8 编码）
            text = data.decode('utf-8', errors='replace')
            print(f"[*] 收到第{block_num}块: length={length}, text=\"{text[:50]}...\"")
            write_log(f"收到 reverseRequest 报文: Type={req_type}, Length={length}, Data={text[:50]}...")

            # ----- 3 反转字符串 -----
            reversed_text = reverse_string(text)  # 调用反转函数
            reversed_data = reversed_text.encode('utf-8')  # 编码为字节串，发送到网络必须是字节串，不能直接发字符串
            reversed_len = len(reversed_data)

            # ----- 4 发送 reverseAnswer 报文 -----
            # reverseAnswer 报文格式：Type(2字节) + Length(4字节) + reverseData(变长)
            # Type=4, Length 表示后面 reverseData 的长度
            answer_msg = struct.pack('!HI', TYPE_REVERSE_ANSWER, reversed_len) + reversed_data
            client_socket.sendall(answer_msg)
            print(f"[*] 发送第{block_num}块应答: length={reversed_len}")
            write_log(f"发送 reverseAnswer 报文: Type={TYPE_REVERSE_ANSWER}, Length={reversed_len}, Data={reversed_text[:50]}...")

    except Exception as e:
        # 捕获任何异常，记录日志
        print(f"[-] 处理客户端时出错: {e}")
        write_log(f"错误: {e}")
    finally:
        # 无论成功还是失败，都要关闭 socket 连接
        client_socket.close()
        print(f"[-] 客户端断开: {client_address}")
        write_log(f"客户端断开: {client_address}")

def main():
    """
    主函数：启动服务端，监听端口，接受客户端连接
    """
    # 第1段：检查命令行参数：程序名 + 端口号 = 共2个参数
    if len(sys.argv) != 2:
        print("用法: python reversetcpserver.py <port>")
        print("示例: python reversetcpserver.py 8888")
        sys.exit(1)

    # 第2段：解析并验证端口号
    # 解析端口号
    try:
        port = int(sys.argv[1]) # 把用户输入的端口号（字符串）变成整数
    except ValueError: # 转不了就报错
        print("[-] 端口必须是整数")
        sys.exit(1)

    # 验证端口范围（1-65535）
    if not (0 < port < 65536):
        print("[-] 端口范围必须为 1~65535")
        sys.exit(1)

    # 第3段：创建日志文件
    # 清空或创建日志文件（w 模式会覆盖原有内容）
    with open("tcp_run_log.txt", "w", encoding="utf-8") as f:
        f.write(f"=== Server 运行日志 ===\n")
        f.write(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    # 第4段：创建 TCP socket
    # socket.AF_INET: 表示使用 IPv4 地址
    # socket.SOCK_STREAM: 表示使用 TCP 协议
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 第5段：SO_REUSEADDR: 允许端口重用（没有这段第4段跑不起来）
    # 这样程序退出后可以立即重新启动并绑定同一个端口，方便调试。
    # 如果不加这行，每次修改代码后都要等几十秒才能重新运行服务端。
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # 1表示true，代表启用端口重用功能
    
    # 第6段：bind: 绑定 IP 和端口
    # '0.0.0.0' 表示监听本机所有网卡，允许任何 IP 访问
    server_socket.bind(('0.0.0.0', port))
    
    # 第7段：listen: 开始监听，5 表示等待队列的最大长度。
    # 队列里面是已经完成TCP三次握手的连接，等待accept()取出
    server_socket.listen(5) # 如果有 5 个客户端在排队等待 accept，第 6 个会被拒绝。
    
    # 第8段：打印启动信息并写日志
    # 这时服务端已经准备好了，就等客户端来连接
    print(f"[*] Server 启动，监听端口 {port}")
    write_log(f"Server 启动，监听端口 {port}")

    # 第9段：主循环（核心！）
    try:
        # 主循环：不断接受新的客户端连接
        while True:
            '''
            accept: 这是一个阻塞调用。
            如果没有客户端连接，程序就停在这里"睡觉"。
            一旦有客户端发起连接，accept() 就会"醒来"，返回两个东西：
            client_socket：一个新的 socket 对象，专门用来和这个客户端通信，负责收发数据
            client_address：客户端的 IP 和端口，比如 ('172.20.0.1', 61678)
            '''
            client_socket, client_address = server_socket.accept()
            
            '''
            然后创建新线程：threading.Thread(target=handle_client, args=...)
            把 client_socket 和 client_address 传给 handle_client 函数。
            '''
            #  handle_client(client_socket, client_address)  
            #  这个是不创建新线程的写法，要很久等一个客户端处理完毕下一个客户端才能进来
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address)) # 创建新线程
            client_thread.daemon = True  # 设置为守护线程，主线程退出时自动结束
            client_thread.start()  # 启动线程，新线程会立刻去执行 handle_client() 里的代码。
            
            # 注意：这里不等待线程结束，直接继续循环接受下一个客户端
            # 从而实现多客户端并发处理
    # 第10段：退出处理      
    except KeyboardInterrupt:
        # 用户按 Ctrl+C 退出
        print("\n[*] Server 关闭")
        write_log("Server 关闭")
    finally:
        # 关闭服务器 socket
        server_socket.close()

if __name__ == "__main__":
    """
    Python 的特殊语法
    当直接运行这个文件时（python reversetcpserver.py），__name__ 等于 "__main__"
    当被其他文件导入时（import reversetcpserver），__name__ 等于 "reversetcpserver"
    这样可以防止被导入时自动运行
    """
    main()