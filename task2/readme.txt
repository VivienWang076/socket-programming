UDP可靠传输说明文档

一、运行环境

操作系统：
   客户端：Windows 11
   服务端：Ubuntu 24.04（虚拟机）
Python 版本：3.12 或更高
依赖库：不需要额外安装，用的都是标准库（socket、struct、sys、os、random、time、datetime）

二、文件列表

udpclient.py          - 客户端程序，在 Windows 上运行
udpserver.py         - 服务端程序，在 Ubuntu 虚拟机上运行
input.txt                - 输入文件，需要自己创建，内容任意
run_log.txt            - 运行日志，程序自动生成

三、命令行参数

服务端：
  python udpserver.py <端口号>
  示例：python udpserver.py 8888

客户端：
  python udpclient.py <服务端IP> <端口> <输入文件> <最小块长> <最大块长> <随机种子>
  示例：python udpclient.py 172.20.7.159 8888 input.txt 40 80 42

参数说明：
  server_ip          - 服务端 IP 地址（虚拟机的 IP）
  server_port      - 服务端端口号
  file_path          - 输入文件路径
  lmin                - 最小数据块长度（字节）
  lmax               - 最大数据块长度（字节）
  seed               - 随机种子，保证分块结果可重现

四、运行步骤

1. 在虚拟机中启动服务端
   python udpserver.py 8888

2. 在物理机中创建输入文件 input.txt，内容任意

3. 在物理机中运行客户端
   python udpclient.py 172.20.7.159 8888 input.txt 40 80 42

4. 查看结果
   - 终端会打印传输进度和统计信息
   - run_log.txt 记录了所有报文的收发事件
   - 服务端会把接收到的数据拼接保存

五、注意事项

1. 确保 Windows 和 Ubuntu 网络互通
2. 必须先启动服务端，再启动客户端，否则客户端连接不上
3. UDP 是 unreliable 的，本程序通过模拟丢包和超时重传来实现可靠传输
4. 服务端按 Ctrl+C 可退出