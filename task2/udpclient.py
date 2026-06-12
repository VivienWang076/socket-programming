#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UDP 客户端程序
功能：使用 UDP 模拟 TCP 可靠传输，实现三次握手、GBN滑动窗口、流量控制、超时重传
学号后4位：2723
"""

import socket
import struct
import sys
import os
import random
import time
from datetime import datetime

# ==================== 报文类型常量 ====================
# 定义6种报文类型，模拟 TCP 的握手、数据传输、挥手
TYPE_SYN = 1        # 同步报文：发起连接请求
TYPE_SYN_ACK = 2    # 同步确认报文：确认连接请求
TYPE_ACK = 3        # 确认报文：确认收到数据
TYPE_DATA = 4       # 数据报文：携带实际文件数据
TYPE_FIN = 5        # 结束报文：请求断开连接
TYPE_FIN_ACK = 6    # 结束确认报文：确认断开连接
'''
fin_ack = self.send_packet(TYPE_FIN_ACK, parsed['seq'] + 1, parsed['seq'] + 1)
                             └─ Type ─┘        └─ Seq ─┘          └─ Ack ─┘
syn_ack = self.send_packet(TYPE_SYN_ACK, 0, parsed['seq'] + 1)
'''
# ==================== 协议参数配置 ====================
MAX_WINDOW_SIZE = 400       # 发送窗口大小（字节），用于流量控制
MIN_DATA_SIZE = 40          # 最小数据块大小（字节）
MAX_DATA_SIZE = 80          # 最大数据块大小（字节）
TIMEOUT = 0.3               # 初始超时时间 300ms
LOSS_RATE = 0.2             # 模拟丢包率 20%，用于测试重传机制

# ==================== 学号相关 ====================
STUDENT_ID_LAST4 = 2723     # 学号后4位
XOR_MAGIC = 0x5A3C          # XOR 魔数，用于 StudentID 字段的编码/解码


def calculate_student_id_field():
    """计算 StudentID 字段：学号后4位 XOR 0x5A3C"""
    return STUDENT_ID_LAST4 ^ XOR_MAGIC


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
    校验和计算：把数据每个字节累加，然后取低 8 位（& 0xFF）。
    发送前算一次放在首部，接收后重新算，对比是否一致，不一致说明数据损坏。
    """
    checksum = 0
    for byte in data:
        checksum = (checksum + byte) & 0xFF
    return checksum


def calculate_timeout(rtt_list):
    """
    根据历史 RTT 动态计算超时时间
    超时时间 = 2 × 平均 RTT，这样大部分正常但稍慢的包不会被误判为丢包。但不低于初始值 TIMEOUT
    参数：rtt_list - 历史 RTT 列表（毫秒）
    返回：超时时间（秒）
    """
    if not rtt_list:
        return TIMEOUT
    avg_rtt = sum(rtt_list) / len(rtt_list)
    timeout = (2 * avg_rtt) / 1000.0
    return max(TIMEOUT, min(2.0, timeout))


class UDPClient:
    """UDP 客户端类，封装所有客户端功能"""

    def __init__(self, server_ip, server_port):
        """
        初始化客户端
        参数：
            server_ip - 服务端 IP 地址
            server_port - 服务端端口号
        """
        self.server_addr = (server_ip, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建 UDP socket
        self.connected = False

        # GBN滑动窗口核心状态变量
        self.base = 0           # 窗口基序号（已确认的最大序号+1）
        self.next_seq = 0       # 下一个待发送序号
        # 缓存已发送但未确认的包，key 是序号，value 存数据和发送时间
        self.send_buffer = {}   # 发送缓冲区 {序号: 报文元数据}
        

        # 统计与辅助变量
        self.packet_data_map = {}       # 序号 -> 字节区间映射
        self.rtt_list = []              # 历史 RTT 列表，记录每次成功传输的 RTT（毫秒）。
        self.total_packets_sent = 0     # 原始发送包数（不含重传）
        self.total_retransmissions = 0  # 重传次数
        self.total_simulated_drops = 0  # 模拟丢包数

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
        length = len(data)
        checksum = calculate_checksum(data)
        student_id_field = calculate_student_id_field()

        # 打包：! 网络字节序（大端）
        # B=1字节, H=2字节, I=4字节
        header = struct.pack('!B H I I H B I',
                            packet_type, student_id_field, seq_num, ack_num,
                            length, checksum, 0)
        return header + data

    def parse_packet(self, packet):
        """
        解析收到的报文
        参数：packet - 收到的字节串
        返回：解析后的字典，包含 type, student_id, seq, ack, length, data, server_time
              如果解析失败返回 None
        """
        if len(packet) < 18:
            return None
        try:
            packet_type, student_id, seq_num, ack_num, length, checksum, server_time = \
                struct.unpack('!B H I I H B I', packet[:18])
            data = packet[18:18+length] if length > 0 else b""

            # 校验和验证
            if calculate_checksum(data) != checksum:
                return None

            return {
                'type': packet_type,
                'student_id': student_id,
                'seq': seq_num,
                'ack': ack_num,
                'length': length,
                'data': data,
                'server_time': server_time
            }
        except Exception:
            return None

    def send_with_loss_simulation(self, packet):
        """
        丢包模拟器
        根据 LOSS_RATE 概率决定是否丢弃数据包
        返回：True 表示实际发送，False 表示模拟丢包
        """
        if random.random() < LOSS_RATE:
            self.total_simulated_drops += 1
            write_log("【模拟丢包】数据包被丢弃")
            return False
        self.sock.sendto(packet, self.server_addr)
        return True

    def three_way_handshake(self):
        """
        建立连接（三次握手）
        模拟 TCP 的三次握手过程：
        1. 客户端发送 SYN
        2. 服务端回复 SYN-ACK
        3. 客户端发送 ACK
        返回：True 成功，False 失败
        """
        print("[*] 正在与服务器建立连接...")
        write_log("启动三次握手连接")

        retries = 0
        while retries < 5: # 最多尝试五次
            # 1.发送SYN
            syn_packet = self.send_packet(TYPE_SYN, 0, 0) # 打包SYN报文
            print(f"[*] 发送 SYN 报文 (尝试 {retries + 1}/5)")
            write_log(f"发送 SYN 报文 (尝试 {retries + 1}/5)")
            # 握手阶段不模拟丢包，直接发送
            self.sock.sendto(syn_packet, self.server_addr)

            self.sock.settimeout(TIMEOUT)
            try: # 等待服务端回复
                data, addr = self.sock.recvfrom(2048) # 从socket接收最多2048字节的数据
                parsed = self.parse_packet(data)  # 把收到的二进制数据解析成字典

                # 2.收到SYN-ACK
                if parsed and parsed['type'] == TYPE_SYN_ACK:
                    print(f"[+] 收到来自服务器的 SYN-ACK")
                    write_log("收到 SYN-ACK 报文")

                    # 3.发送ACK
                    ack_packet = self.send_packet(TYPE_ACK, 0, parsed['seq'] + 1)
                    self.sock.sendto(ack_packet, self.server_addr)
                    print("[*] 发送 ACK 报文，连接建立成功！")
                    write_log("发送 ACK 报文，建立连接")
                    self.connected = True
                    return True
            except socket.timeout:
                retries += 1
                print(f"[!] 连接超时，准备第 {retries + 1} 次重试...")
                write_log(f"连接超时，准备第 {retries + 1} 次重试")
                continue

        print("[-] 三次握手失败，服务器无响应")
        write_log("三次握手连接失败")
        return False

    def generate_data_segments(self, file_path, lmin, lmax):
        """
        读取文件并根据随机长度切割数据段
        参数：
            file_path - 输入文件路径
            lmin - 最小数据块长度
            lmax - 最大数据块长度
        返回：数据段列表，每个元素包含 seq, data, start_byte, end_byte, size
        """
        if not os.path.exists(file_path):
            print(f"[-] 文件不存在: {file_path}")
            sys.exit(1)

        with open(file_path, 'rb') as f:
            file_data = f.read()

        total_len = len(file_data)
        print(f"[*] 文件总长度: {total_len} 字节")

        segments = []
        offset = 0
        seq = 1

        while offset < total_len: # 只要还没读完整个文件，就继续切块
            # 随机取 [lmin, lmax] 之间的长度
            chunk_size = random.randint(lmin, lmax)
            if offset + chunk_size > total_len:
                chunk_size = total_len - offset  # 最后一块
            chunk = file_data[offset:offset+chunk_size] # 读取数据
            # 记录块信息
            segments.append({
                'seq': seq,
                'data': chunk,
                'start_byte': offset,
                'end_byte': offset + len(chunk) - 1,
                'size': len(chunk)
            })

            self.packet_data_map[seq] = (offset, offset + len(chunk) - 1, len(chunk))
            offset += len(chunk) # 指向下一个块
            seq += 1 # 下一个块的序号

        print(f"[*] 共分成 {len(segments)} 个数据包")
        write_log(f"数据分段完成，共 {len(segments)} 个包")
        return segments

    def send_data_with_gbn(self, segments):
        """
        GBN（Go-Back-N）协议流控发送核心函数
        实现滑动窗口、超时重传、累积确认
        参数：segments - 数据段列表
        返回：True 成功
        """
        print("\n[*] 开始基于滑动窗口(GBN)传输数据...")
        write_log("进入滑动窗口数据传输阶段")

        total_segments = len(segments) # 数据块总数
        # 窗口最多能装多少个包
        max_packets_in_window = max(1, MAX_WINDOW_SIZE // MAX_DATA_SIZE) # 400//80=5
        print(f"[*] 滑动窗口容量: {MAX_WINDOW_SIZE} 字节 (最多容纳 {max_packets_in_window} 个未确认包)")

        while self.base < total_segments: # 只要还有未确认的包就继续循环
            # ---------- 1. 发送流控阶段 ----------
            # 只要窗口没满，就发送新数据包
            while (self.next_seq < total_segments and 
                   (self.next_seq - self.base) < max_packets_in_window):

                seg = segments[self.next_seq] #下一个要发的序号
                data_packet = self.send_packet(TYPE_DATA, seg['seq'], 0, seg['data']) # 取出这个序号对应的数据块。调用send_packet打包成DATA报文

                # 打印当前发送的包的信息：序号、在文件中的起止位置
                print(f"[发送] 序列号={seg['seq']}, 字节区间=[{seg['start_byte']}~{seg['end_byte']}]")

                # 模拟丢包判断
                if self.send_with_loss_simulation(data_packet): # 20% 概率丢包
                    # 发送成功
                    self.send_buffer[self.next_seq] = {
                        'data': seg['data'],
                        'send_time': time.time(),
                        'retries': 0,
                        'size': len(seg['data'])
                    }
                    self.total_packets_sent += 1
                    print(f"       => [已发送] 窗口内未确认数 = {(self.next_seq - self.base) + 1}")
                    write_log(f"成功发送 DATA 包: seq={seg['seq']}")
                else:
                    # 丢包
                    print(f"       => [模拟丢包] 该包被丢弃")
                    write_log(f"DATA 包 seq={seg['seq']} 被模拟丢包")

                self.next_seq += 1 # 无论是否丢包，next_seq 都递增。因为丢包也要消耗一个序号，超时后要重传这个序号。

            # ---------- 2. 接收 ACK 阶段 ----------
            # 设置超时
            current_timeout = calculate_timeout(self.rtt_list)
            self.sock.settimeout(current_timeout)

            try:
                # 接收数据
                data, addr = self.sock.recvfrom(4096)
                parsed = self.parse_packet(data)
                
                # 确认是ACK报文
                if parsed and parsed['type'] == TYPE_ACK:
                    ack_num = parsed['ack']
                    ack_index = ack_num - 1

                    # 只有 ack_index > base，窗口才能向前滑动。
                    # 如果收到重复的 ACK（比如 ack_index == base），不处理
                    if ack_index > self.base: # 确认窗口是否真的向前滑动了
                        if ack_index - 1 in self.send_buffer:
                            # 计算RTT
                            # ack_index - 1 是最后一个被确认的包的序号。从缓冲区取出它的发送时间，用当前时间减一下，得到 RTT（毫秒），记录到 RTT 列表。
                            rtt = (time.time() - self.send_buffer[ack_index - 1]['send_time']) * 1000
                            self.rtt_list.append(rtt)
                            print(f"[收到ACK] 累积确认至序号 {ack_num - 1}，RTT = {rtt:.2f} ms")
                            write_log(f"收到 ACK: ack={ack_num}, RTT={rtt:.2f}ms")

                            if parsed['server_time']:
                                s_hour = parsed['server_time'] // 3600
                                s_min = (parsed['server_time'] % 3600) // 60
                                s_sec = parsed['server_time'] % 60
                                print(f"        [服务器时间] {s_hour:02d}:{s_min:02d}:{s_sec:02d}")

                        # 滑动窗口：删除已确认的包
                        for idx in range(self.base, ack_index):
                            if idx in self.send_buffer:
                                del self.send_buffer[idx]

                        self.base = ack_index
                        print(f"[*] 窗口滑动，base={self.base}, next_seq={self.next_seq}")

            # ---------- 3. 超时重传（GBN核心：回退N步） ----------
            except socket.timeout:
                print(f"[超时] 超过 {current_timeout:.2f}s 未收到 ACK，触发 GBN 重传！")
                write_log(f"超时触发，base={self.base}，开始重传窗口内所有包")

                # 回退到 base，重传窗口内所有包
                self.next_seq = self.base

                for idx in range(self.base, min(self.base + max_packets_in_window, total_segments)):
                    # 重传数据包
                    # 取出数据块，打包成 DATA 报文，直接发送（不经过丢包模拟器），因为重传不能再丢了。
                    seg = segments[idx]
                    data_packet = self.send_packet(TYPE_DATA, seg['seq'], 0, seg['data'])
                    self.sock.sendto(data_packet, self.server_addr)

                    self.total_retransmissions += 1

                    if idx in self.send_buffer:
                        self.send_buffer[idx]['send_time'] = time.time()
                        self.send_buffer[idx]['retries'] += 1
                    else:
                        self.send_buffer[idx] = {
                            'data': seg['data'],
                            'send_time': time.time(),
                            'retries': 1,
                            'size': len(seg['data'])
                        }

                    print(f"    [重传] 序列号={seg['seq']}, 重传次数={self.send_buffer[idx]['retries']}")
                    write_log(f"重传 DATA 包: seq={seg['seq']}")

                continue

        print("\n[+] 所有数据发送完成！")
        write_log("数据段传输全部完成")
        return True

    def disconnect(self):
        """
        释放连接（四次挥手）
        模拟 TCP 的四次挥手过程：
        1. 客户端发送 FIN
        2. 服务端回复 FIN-ACK
        """
        print("\n[*] 正在向服务器请求断开连接...")
        write_log("发起连接断开阶段")

        for attempt in range(3): # 最多尝试 3 次，attempt 从 0 到 2
            # 1.发送FIN
            # 打包 FIN 报文（Type=5），发送给服务端，告诉对方自己要断开连接
            fin_packet = self.send_packet(TYPE_FIN, 0, 0)
            print(f"[*] 发送 FIN 报文 (尝试 {attempt + 1}/3)")
            write_log(f"发送 FIN 报文 (尝试 {attempt + 1}/3)")
            self.sock.sendto(fin_packet, self.server_addr)

            # 2.等待FIN-ACK
            self.sock.settimeout(TIMEOUT) # 设置 0.3 秒超时，等待服务端的回复；如果超时，跳到 except。
            try:
                data, addr = self.sock.recvfrom(2048)
                parsed = self.parse_packet(data)

                if parsed and parsed['type'] == TYPE_FIN_ACK:
                    print("[+] 收到 FIN-ACK，断开成功！")
                    write_log("收到 FIN-ACK 报文，正常断开连接")
                    self.connected = False
                    return True
            except socket.timeout:
                print(f"[!] 断开超时，重试 {attempt + 1}/3")
                write_log(f"断开超时，重试 {attempt + 1}/3")
                continue

        print("[-] 服务器无回应，本地强制关闭")
        write_log("挥手超时，本地强制关闭")
        self.sock.close()

    def print_statistics(self):
        """输出最终的统计报表"""
        total_original = self.total_packets_sent
        total_actual = total_original + self.total_retransmissions
        actual_loss_rate = (self.total_retransmissions / total_actual * 100) if total_actual > 0 else 0

        print("\n" + "="*20 + " 传输实验统计总结 " + "="*20)
        print(f" 1. 原始数据包数（不含重传）: {total_original}")
        print(f" 2. 触发超时引发的重传帧数 : {self.total_retransmissions}")
        print(f" 3. 实际网络发送总包数     : {total_actual}")
        print(f" 4. 客户端模拟丢包数       : {self.total_simulated_drops}")
        print(f" 5. 实际丢包率（重传/总发）: {actual_loss_rate:.2f}%")
        print("="*58 + "\n")

        if self.rtt_list:
            print(f"RTT 统计信息:")
            print(f"  最大 RTT: {max(self.rtt_list):.2f} ms")
            print(f"  最小 RTT: {min(self.rtt_list):.2f} ms")
            print(f"  平均 RTT: {sum(self.rtt_list)/len(self.rtt_list):.2f} ms")

        write_log(f"=== 运行总结报表 ===")
        write_log(f"原始包数: {total_original}, 重传次数: {self.total_retransmissions}, 丢包率: {actual_loss_rate:.2f}%")


def main():
    """
    主函数：解析命令行参数，执行数据传输
    """
    # 检查命令行参数：共7个
    if len(sys.argv) != 7:
        print("用法提示: python udpclient.py <server_ip> <server_port> <file_path> <lmin> <lmax> <seed>")
        print("运行示例: python udpclient.py 127.0.0.1 8888 input.txt 40 80 42")
        sys.exit(1)

    # 解析命令行参数
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    file_path = sys.argv[3]
    lmin = int(sys.argv[4])
    lmax = int(sys.argv[5])
    seed = int(sys.argv[6])

    # 设置随机种子，保证可重现
    random.seed(seed)

    print(f"\n[*] UDP 可靠传输客户端启动")
    print(f"[*] 服务器: {server_ip}:{server_port}")
    print(f"[*] 文件: {file_path}")
    print(f"[*] 数据块大小: {lmin}-{lmax} 字节")
    print(f"[*] 发送窗口: {MAX_WINDOW_SIZE} 字节")
    print(f"[*] 模拟丢包率: {LOSS_RATE * 100}%")

    # 创建客户端对象
    client = UDPClient(server_ip, server_port) 

    # 三次握手建立连接
    if not client.three_way_handshake():
        sys.exit(1)

    # 读取并分割数据
    segments = client.generate_data_segments(file_path, lmin, lmax)

    # GBN 传输数据
    if client.send_data_with_gbn(segments):
        client.disconnect()

    # 打印统计信息
    client.print_statistics()
    print("\n[*] 程序结束")


if __name__ == "__main__":
    main()