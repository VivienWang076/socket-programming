#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UDP 服务端程序
功能：使用 UDP 模拟 TCP 可靠传输，实现连接建立、累积确认、模拟丢包
学号后4位：2723
"""

import socket
import struct
import sys
import random
from datetime import datetime

# ==================== 报文类型常量 ====================
TYPE_SYN = 1        # 同步报文：客户端发起连接请求
TYPE_SYN_ACK = 2    # 同步确认报文：确认连接请求
TYPE_ACK = 3        # 确认报文：确认收到数据
TYPE_DATA = 4       # 数据报文：携带实际文件数据
TYPE_FIN = 5        # 结束报文：客户端请求断开连接
TYPE_FIN_ACK = 6    # 结束确认报文：确认断开连接

# ==================== 协议参数配置 ====================
LOSS_RATE = 0.2     # 模拟丢包率 20%

# ==================== 学号相关 ====================
STUDENT_ID_LAST4 = 2723     # 学号后4位
XOR_MAGIC = 0x5A3C          # XOR 魔数


def calculate_student_id_field():
    """计算 StudentID 字段：学号后4位 XOR 0x5A3C"""
    return STUDENT_ID_LAST4 ^ XOR_MAGIC


def validate_student_id(value):
    """
    验证 StudentID 字段是否有效
    解码后应该在 0-9999 范围内
    """
    result = value ^ XOR_MAGIC
    return 0 <= result <= 9999


def write_log(message):
    """
    写入运行日志文件 run_log.txt
    每条日志带时间戳，精确到毫秒
    """
    with open("run_log.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        f.write(f"[{timestamp}] {message}\n")


def calculate_checksum(data):
    """
    计算校验和（单字节累加）
    用于检测数据在传输过程中是否损坏
    参数：data - 字节串
    返回：校验和（0-255）
    """
    checksum = 0
    for byte in data:
        checksum = (checksum + byte) & 0xFF
    return checksum


def get_server_time():
    """
    获取服务器当前时间（秒数）
    返回：从 00:00:00 开始到现在的秒数
    """
    now = datetime.now()
    return now.hour * 3600 + now.minute * 60 + now.second


class UDPServer:
    """UDP 服务端类，封装所有服务端功能"""

    def __init__(self, port):
        """
        初始化服务端
        参数：port - 监听端口号
        """
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建 UDP socket
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 端口重用
        self.sock.bind(('0.0.0.0', port))  # 绑定端口

        self.client_addr = None     # 客户端地址
        self.connected = False      # 连接状态
        self.received_packets = {}  # 接收缓冲区 {序号: 数据}
        self.expected_seq = 1       # 期望的下一个序号
        self.received_data = []     # 已接收的数据列表

        self.total_packets_received = 0  # 成功接收包数
        self.total_packets_dropped = 0   # 模拟丢弃包数

    def send_packet(self, packet_type, seq_num, ack_num, data=b""):
        """
        构造并打包固定首部的报文
        报文格式：首部18字节 + 数据体（变长）
        首部字段：Type(1) + StudentID(2) + Seq(4) + Ack(4) + Length(2) + Checksum(1) + ServerTime(4) = 18字节
        参数：
            packet_type - 报文类型（1-6）
            seq_num - 序列号
            ack_num - 确认号
            data - 数据体（字节串）
        返回：完整的报文（字节串）
        """
        student_id_field = calculate_student_id_field()
        length = len(data)
        checksum = calculate_checksum(data)
        server_time = get_server_time()

        # 打包：! 网络字节序（大端）
        # B=1字节, H=2字节, I=4字节
        header = struct.pack('!B H I I H B I',
                            packet_type, student_id_field, seq_num, ack_num,
                            length, checksum, server_time)
        return header + data

    def parse_packet(self, packet, addr):
        """
        解析收到的报文
        参数：packet - 收到的字节串
              addr - 发送方地址
        返回：解析后的字典，包含 type, student_id, seq, ack, length, data, server_time, addr
              如果解析失败返回 None
        """
        if len(packet) < 18:
            return None

        try:
            packet_type, student_id, seq_num, ack_num, length, checksum, server_time = \
                struct.unpack('!B H I I H B I', packet[:18])

            data = packet[18:18 + length] if length > 0 else b""

            # 校验数据长度
            if len(data) != length:
                return None

            # 校验和验证
            if calculate_checksum(data) != checksum:
                return None

            # SYN 报文需要验证 StudentID
            if packet_type == TYPE_SYN:
                if not validate_student_id(student_id):
                    write_log(f"StudentID验证失败 from {addr}")
                    return None

            write_log(f"收到包: type={packet_type}, seq={seq_num}, ack={ack_num}, len={length}")

            return {
                'type': packet_type,
                'student_id': student_id,
                'seq': seq_num,
                'ack': ack_num,
                'length': length,
                'data': data,
                'server_time': server_time,
                'addr': addr
            }
        except Exception:
            return None

    def should_drop_packet(self):
        """丢包模拟器：根据 LOSS_RATE 概率决定是否丢弃"""
        return random.random() < LOSS_RATE

    def handle_handshake(self, parsed):
        """
        处理三次握手
        参数：parsed - 解析后的报文
        返回：True 握手进行中，False 握手失败
        """
        # 处理 SYN 报文
        if parsed['type'] == TYPE_SYN:
            if self.should_drop_packet():
                write_log(f"【模拟丢包】丢弃 SYN 包 from {parsed['addr']}")
                return False

            print(f"[*] 收到 SYN 报文 from {parsed['addr']}")
            write_log(f"收到 SYN 报文 from {parsed['addr']}")

            self.client_addr = parsed['addr']

            # 发送 SYN-ACK 报文
            syn_ack_packet = self.send_packet(TYPE_SYN_ACK, 0, parsed['seq'] + 1)
            self.sock.sendto(syn_ack_packet, self.client_addr)
            print("[*] 发送 SYN-ACK 报文")
            write_log("发送 SYN-ACK 报文")
            return True

        # 处理 ACK 报文（三次握手的最后一步）
        elif parsed['type'] == TYPE_ACK and parsed['addr'] == self.client_addr:
            print(f"[+] 收到 ACK 报文，连接建立完成")
            write_log(f"收到 ACK 报文，连接建立完成")
            self.connected = True
            return True

        return False

    def handle_data(self, parsed):
        """
        处理数据报文（累积确认）
        参数：parsed - 解析后的报文
        返回：True 处理成功
        """
        if not self.connected or parsed['addr'] != self.client_addr:
            return False

        # 模拟丢包
        if self.should_drop_packet():
            self.total_packets_dropped += 1
            write_log(f"【模拟丢包】丢弃 DATA 包 seq={parsed['seq']}")
            return False

        self.total_packets_received += 1
        seq = parsed['seq']

        print(f"[*] 收到 DATA 包: seq={seq}, size={parsed['length']}")
        write_log(f"收到 DATA 包: seq={seq}, size={parsed['length']}")

        # 存入接收缓冲区
        self.received_packets[seq] = parsed['data']

        # 累积确认：按顺序交付数据
        while self.expected_seq in self.received_packets:
            data = self.received_packets[self.expected_seq]
            self.received_data.append(data)
            del self.received_packets[self.expected_seq]
            self.expected_seq += 1

        # 发送 ACK 报文（确认号 = 期望的下一个序号）
        ack_packet = self.send_packet(TYPE_ACK, 0, self.expected_seq)
        self.sock.sendto(ack_packet, self.client_addr)
        print(f"[*] 发送 ACK 报文: ack={self.expected_seq}")
        write_log(f"发送 ACK 报文: ack={self.expected_seq}")

        return True

    def handle_teardown(self, parsed):
        """
        处理连接断开（四次挥手）
        参数：parsed - 解析后的报文
        返回：True 断开处理完成
        """
        if parsed['type'] == TYPE_FIN and parsed['addr'] == self.client_addr:
            print(f"[*] 收到 FIN 报文")
            write_log("收到 FIN 报文")

            # 发送 FIN-ACK 报文
            fin_ack_packet = self.send_packet(TYPE_FIN_ACK, parsed['seq'] + 1, parsed['seq'] + 1)
            self.sock.sendto(fin_ack_packet, self.client_addr)
            print("[*] 发送 FIN-ACK 报文")
            write_log("发送 FIN-ACK 报文")

            # 等待客户端的最终 ACK（可选，超时就关闭）
            try:
                self.sock.settimeout(1.0)
                data, addr = self.sock.recvfrom(4096)
                final_parsed = self.parse_packet(data, addr)
                if final_parsed and final_parsed['type'] == TYPE_ACK:
                    print("[+] 收到最终 ACK，连接关闭")
                    write_log("收到最终 ACK，连接关闭")
            except socket.timeout:
                write_log("等待最终 ACK 超时，直接关闭")

            self.connected = False
            self.client_addr = None
            return True

        return False

    def print_statistics(self):
        """输出服务端统计信息"""
        print("\n" + "=" * 50)
        print("【服务端统计信息】")
        print("=" * 50)
        print(f"成功接收包数: {self.total_packets_received}")
        print(f"模拟丢弃包数: {self.total_packets_dropped}")
        print(f"期望序号: {self.expected_seq}")
        print(f"接收数据总字节: {sum(len(d) for d in self.received_data)}")

        write_log("=== 服务端统计 ===")
        write_log(f"成功接收包数: {self.total_packets_received}")
        write_log(f"模拟丢弃包数: {self.total_packets_dropped}")

    def run(self):
        """
        主循环：接收并处理所有报文
        """
        print(f"[*] UDP Server 启动，监听端口 {self.port}")
        print(f"[*] 模拟丢包率: {LOSS_RATE * 100}%")
        write_log(f"Server 启动，端口 {self.port}，丢包率 {LOSS_RATE * 100}%")

        while True:
            try:
                self.sock.settimeout(None)  # 无限等待
                data, addr = self.sock.recvfrom(65535)

                parsed = self.parse_packet(data, addr)
                if parsed is None:
                    continue

                # 根据报文类型分发处理
                if parsed['type'] == TYPE_SYN:
                    self.handle_handshake(parsed)
                elif parsed['type'] == TYPE_ACK and not self.connected:
                    self.handle_handshake(parsed)
                elif parsed['type'] == TYPE_DATA:
                    self.handle_data(parsed)
                elif parsed['type'] == TYPE_FIN:
                    self.handle_teardown(parsed)
                else:
                    write_log(f"未知报文类型: {parsed['type']}")

            except KeyboardInterrupt:
                print("\n[*] Server 关闭")
                write_log("Server 关闭")
                break
            except Exception as e:
                print(f"[-] 错误: {e}")
                write_log(f"错误: {e}")


def main():
    """
    主函数：解析命令行参数，启动服务端
    """
    # 检查命令行参数：程序名 + 端口号 = 共2个参数
    if len(sys.argv) != 2:
        print("用法: python udpserver.py <port>")
        print("示例: python udpserver.py 8888")
        sys.exit(1)

    # 解析端口号
    try:
        port = int(sys.argv[1])
    except ValueError:
        print("[-] 端口必须是整数")
        sys.exit(1)

    # 验证端口范围
    if not (0 < port < 65536):
        print("[-] 端口范围必须为 1~65535")
        sys.exit(1)

    # 创建日志文件
    with open("run_log.txt", "w", encoding="utf-8") as f:
        f.write(f"=== UDP Server 运行日志 ===\n")
        f.write(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"学号后4位: {STUDENT_ID_LAST4}\n\n")

    server = UDPServer(port)

    try:
        server.run()
    except KeyboardInterrupt:
        pass
    finally:
        server.print_statistics()
        server.sock.close()


if __name__ == "__main__":
    main()