import json
import struct
import socket
import ssl
import sys
import time
import logging
import threading
import random
import hashlib
from queue import Queue

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S'
)

# --------------------------
# 协议消息构造优化
# --------------------------
def create_message(msg_type, payload=None, **kwargs):
    """通用消息构造函数"""
    message = {'Type': msg_type}
    if payload is None:
        payload = kwargs
    if payload:
        message['Payload'] = payload
    return json.dumps(message)

# 特定消息类型快捷方法
AuthResp = lambda **kw: create_message('AuthResp', **kw)
NewTunnel = lambda **kw: create_message('NewTunnel', **kw)
ReqProxy = lambda: create_message('ReqProxy')
StartProxy = lambda **kw: create_message('StartProxy', **kw)
Pong = lambda: create_message('Pong')

# --------------------------
# 网络工具函数优化
# --------------------------
def lentobyte(length):
    """封装长度打包逻辑"""
    return struct.pack('<LL', length, 0)

def sendpack(sock, msg, isblock=False):
    """优化后的数据包发送"""
    try:
        if isblock:
            sock.setblocking(True)
        
        # 先发送长度头
        header = lentobyte(len(msg))
        sock.sendall(header)
        
        # 发送消息体
        sock.sendall(msg.encode('utf-8'))
    finally:
        if isblock:
            sock.setblocking(False)

def tolen(header_bytes):
    """优化长度解析"""
    if len(header_bytes) == 8:
        return struct.unpack('<I', header_bytes[:4])[0]
    return 0

# --------------------------
# 工具函数优化
# --------------------------
def get_rand_char(length):
    """生成随机字符串"""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
    return ''.join(random.choices(chars, k=length))

def md5_hash(s):
    """MD5哈希函数"""
    return hashlib.md5(s.encode('utf-8')).hexdigest().lower()

def parse_http_header(request):
    """优化HTTP头解析"""
    try:
        header_part, _, data = request.partition('\r\n\r\n')
        headers = {}
        for line in header_part.split('\r\n')[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        return headers, data
    except Exception as e:
        logging.error(f"Error parsing HTTP header: {str(e)}")
        return {}, ''

# --------------------------
# Socket监听器类优化
# --------------------------
class SocketListener:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.ssl_context = None
        self.server_socket = None

    def set_ssl(self, certfile, keyfile):
        """配置SSL"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.ssl_context = context

    def start(self, handler, protocol_name):
        """启动监听线程"""
        self._create_socket()
        threading.Thread(
            target=self._accept_connections,
            args=(handler, protocol_name),
            daemon=True
        ).start()

    def _create_socket(self):
        """创建并绑定socket"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logging.info(f"Listening on {self.host}:{self.port}")

    def _accept_connections(self, handler, protocol_name):
        """接受连接并处理"""
        try:
            while True:
                conn, addr = self.server_socket.accept()
                try:
                    if self.ssl_context:
                        conn = self.ssl_context.wrap_socket(conn, server_side=True)
                    threading.Thread(
                        target=handler,
                        args=(conn, addr, protocol_name),
                        daemon=True
                    ).start()
                except Exception as e:
                    logging.error(f"Connection error: {str(e)}")
        finally:
            self.server_socket.close()

# --------------------------
# 主服务类优化
# --------------------------
class NgrokServer:
    def __init__(self, config):
        self.config = config
        self.tunnels = {}
        self.host_mappings = {}
        self.tcp_mappings = {}
        self.registration_queues = {}

    def run_service(self):
        """启动所有服务"""
        services = [
            (self.config.http_port, False, 'http'),
            (self.config.https_port, True, 'https'),
            (self.config.control_port, True, 'control')
        ]
        
        for port, use_ssl, name in services:
            listener = SocketListener(self.config.host, port)
            if use_ssl:
                listener.set_ssl(self.config.cert_file, self.config.key_file)
            listener.start(
                self.handle_control_connection if name == 'control' else self.handle_proxy_connection,
                name
            )

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Server shutdown requested")

    def handle_proxy_connection(self, conn, addr, protocol):
        """处理代理连接"""
        logger = logging.getLogger(f'{protocol}:{conn.fileno()}')
        logger.debug(f"New connection from {addr}")
        
        try:
            # 处理逻辑...
            pass
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
        finally:
            conn.close()

    def handle_control_connection(self, conn, addr, protocol):
        """处理控制连接"""
        # 完整处理逻辑...
        pass

# --------------------------
# 配置类和主程序入口
# --------------------------
class ServerConfig:
    def __init__(self):
        self.host = ''
        self.http_port = 80
        self.https_port = 443
        self.control_port = 4443
        self.domain = 'ngrok.example.com'
        self.cert_file = 'server.crt'
        self.key_file = 'server.key'
        self.buffer_size = 4096

if __name__ == '__main__':
    config = ServerConfig()
    server = NgrokServer(config)
    server.run_service()