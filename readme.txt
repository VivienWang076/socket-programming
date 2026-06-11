TCP说明文档

一、运行环境

操作系统：
   客户端：Windows 11
   服务端：Ubuntu 24.04（虚拟机）
Python 版本：3.12 或更高
依赖库：不需要额外安装，用的都是标准库（socket、threading、struct、sys、os、random、datetime）

二、文件列表

reversetcpclient.py    - 客户端程序，在 Windows 上运行
reversetcpserver.py   - 服务端程序，在 Ubuntu 虚拟机上运行
input.txt                    - 输入文件，需要自己创建，内容必须是英文
output.txt                  - 输出文件，程序自动生成
tcp_run_log.txt          - 运行日志，程序自动生成

三、命令行参数

服务端：
  python reversetcpserver.py <端口号>
  eg：python reversetcpserver.py 8888

客户端：
  python reversetcpclient.py <服务端IP> <端口> <输入文件> <最小块长> <最大块长> <随机种子> <输出文件>
  eg：python reversetcpclient.py 172.20.7.159 8888 input.txt 50 100 42 output.txt

四、运行步骤

1. 在虚拟机中启动服务端
   python reversetcpserver.py 8888

2. 在物理机中运行客户端
   python reversetcpclient.py 172.20.7.159 8888 input.txt 50 100 42 output.txt

3. 查看结果
   - 终端会打印每块反转后的文本
   - output.txt 是完整的反转后文件
   - tcp_run_log.txt 记录了所有报文的收发事件

五、注意事项

1. 确保 Windows 和 Ubuntu 网络互通
2. 必须先启动服务端，再启动客户端，否则客户端连接不上
3. 输入文件必须是英文，用 UTF-8 编码保存
