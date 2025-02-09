#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 3.12.0 以上运行
# 项目地址: https://github.com/hauntek/python-ngrokd
# Version: v2.00
import socket
import ssl
import sys
import json
import struct
import time
import logging
import threading
import secrets
import asyncio
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Tuple, Optional, List, Deque

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S'
)
logger = logging.getLogger('ngrokd')

class TunnelManager:
    """管理所有隧道和客户端连接"""
    def __init__(self, domain: str):
        self.domain = domain  # 服务域名
        self.tunnels: Dict[str, dict] = {}  # client_id: tunnel_info
        self.conn_map: Dict[str, ssl.SSLSocket] = {}  # client_id: control_conn
        self.host_map: Dict[str, str] = {}  # hostname: client_id
        self.subdomain_map: Dict[str, str] = {}  # subdomain: client_id
        self.tcp_map: Dict[int, str] = {}  # remote_port: client_id
        self.port_pool = deque(range(10000, 60000))  # 可用端口池
        self.lock = threading.RLock()

    def register_tunnel(self, client_id: str, tunnel_type: str, config: dict) -> dict:
        """注册新隧道（添加重复检查）"""
        with self.lock:
            # 生成URL前先检查是否已存在
            url = self._generate_url(tunnel_type, config)
            if url in self.tunnels:
                raise ValueError(f"Tunnel {url} already registered")

            if tunnel_type == 'tcp':
                if config['RemotePort'] == 0:
                    if not self.port_pool:
                        raise ValueError("No available ports")
                    config['RemotePort'] = self.port_pool.popleft()
                elif config['RemotePort'] in self.tcp_map:
                    raise ValueError(f"Port {config['RemotePort']} already in use")
                self.tcp_map[config['RemotePort']] = client_id
            
            tunnel_info = {
                'client_id': client_id,
                'type': tunnel_type,
                'url': url,
                'config': config,
                'created_at': time.time(),
                'last_active': time.time()
            }
            self.tunnels[url] = tunnel_info
            return tunnel_info

    def _generate_url(self, tunnel_type: str, config: dict) -> str:
        """生成隧道URL"""
        if tunnel_type == 'http':
            if config['Subdomain']:
                return f"http://{config['Subdomain']}.{self.domain}"
            return f"http://{config['Hostname']}" if config['Hostname'] else f"http://{secrets.token_hex(8)}.{self.domain}"
        elif tunnel_type == 'https':
            if config['Subdomain']:
                return f"https://{config['Subdomain']}.{self.domain}"
            return f"https://{config['Hostname']}" if config['Hostname'] else f"https://{secrets.token_hex(8)}.{self.domain}"
        elif tunnel_type == 'tcp':
            return f"tcp://{self.domain}:{config['RemotePort']}"
        else:
            raise ValueError(f"Unsupported tunnel type: {tunnel_type}")

    def unregister_client(self, client_id: str):
        """注销客户端所有隧道"""
        with self.lock:
            to_remove = [url for url, info in self.tunnels.items() if info['client_id'] == client_id]
            for url in to_remove:
                if self.tunnels[url]['type'] == 'tcp':
                    port = self.tunnels[url]['config']['RemotePort']
                    self.port_pool.append(port)
                    del self.tcp_map[port]
                del self.tunnels[url]
            
            if client_id in self.conn_map:
                del self.conn_map[client_id]

class HttpTunnelHandler:
    """处理HTTP/HTTPS请求转发"""
    def __init__(self, tunnel_mgr: TunnelManager, ssl_cert: str, ssl_key: str, bufsize: int):
        self.tunnel_mgr = tunnel_mgr
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.bufsize = bufsize
        self.executor = ThreadPoolExecutor(max_workers=100)
        self.ssl_ctx = self._create_ssl_context()

    def _create_ssl_context(self):
        """创建SSL上下文"""
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile=self.ssl_cert, keyfile=self.ssl_key)
        return ctx

    async def handle_http_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理HTTP请求"""
        try:
            header = await reader.readuntil(b'\r\n\r\n')
            headers = self._parse_headers(header.decode())
            host = headers.get('Host', '')
            
            with self.tunnel_mgr.lock:
                if host not in self.tunnel_mgr.host_map:
                    writer.write(b'HTTP/1.1 404 Not Found\r\n\r\n')
                    await writer.drain()
                    return
                
                client_id = self.tunnel_mgr.host_map[host]
                control_conn = self.tunnel_mgr.conn_map.get(client_id)
                
                if not control_conn:
                    writer.write(b'HTTP/1.1 503 Service Unavailable\r\n\r\n')
                    await writer.drain()
                    return

            proxy_conn = await self._create_proxy_connection(control_conn, host)
            await self._bridge_connections(reader, writer, proxy_conn)
            
        except Exception as e:
            logger.error(f"HTTP处理错误: {str(e)}")
        finally:
            writer.close()

    async def _create_proxy_connection(self, control_conn: ssl.SSLSocket, host: str):
        """通过控制连接建立代理通道"""
        req_id = secrets.token_hex(4)
        msg = {
            'Type': 'StartProxy',
            'Payload': {
                'ReqId': req_id,
                'Url': f"http://{host}",
                'ClientAddr': 'remote'
            }
        }
        self._send_control_message(control_conn, msg)
        return await self._wait_for_proxy_connection(req_id)

    async def _wait_for_proxy_connection(self, req_id: str):
        """等待客户端建立代理连接"""
        loop = asyncio.get_event_loop()
        future = loop.create_future()

        def on_proxy_connected(conn: socket.socket):
            if not future.done():
                future.set_result(conn)

        # 模拟等待客户端连接（实际实现需要与客户端协议配合）
        await asyncio.sleep(1)  # 模拟等待
        proxy_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_conn.connect(('localhost', 12345))  # 模拟连接
        on_proxy_connected(proxy_conn)

        return await future

    def _send_control_message(self, conn: ssl.SSLSocket, msg: dict):
        """发送控制消息"""
        try:
            data = json.dumps(msg).encode()
            header = struct.pack('<II', len(data), 0)
            conn.send(header + data)
        except ssl.SSLWantWriteError:
            pass

    async def _bridge_connections(self, client_reader, client_writer, proxy_conn):
        """桥接客户端和代理连接"""
        async def forward(src, dst):
            try:
                while True:
                    data = await src.read(self.bufsize)
                    if not data:
                        break
                    dst.send(data)
            except:
                pass

        await asyncio.gather(
            forward(client_reader, proxy_conn),
            forward(proxy_conn, client_writer)
        )

class TcpTunnelHandler:
    """处理TCP隧道转发"""
    def __init__(self, tunnel_mgr: TunnelManager, bufsize: int):
        self.tunnel_mgr = tunnel_mgr
        self.bufsize = bufsize
        self.listeners: Dict[int, socket.socket] = {}
        self.executor = ThreadPoolExecutor(max_workers=100)
        self.lock = threading.RLock()  # 显式初始化锁

    def start_tcp_listener(self, port: int):
        """启动TCP端口监听"""
        with self.lock:  # 使用初始化好的锁
            if port in self.listeners:
                raise ValueError(f"Port {port} already in use")
            
            def _listen():
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((self.tunnel_mgr.config['host'], port))
                    sock.listen(100)
                    self.listeners[port] = sock
                    logger.info(f"TCP监听已启动 port:{port}")
                    
                    while True:
                        try:
                            client_conn, addr = sock.accept()
                            self.executor.submit(
                                self._handle_tcp_connection, 
                                client_conn, 
                                port
                            )
                        except OSError:
                            break

            thread = threading.Thread(target=_listen, daemon=True)
            thread.start()
            return thread

    def _handle_tcp_connection(self, client_conn: socket.socket, remote_port: int):
        """处理TCP连接请求"""
        try:
            with self.lock:
                if remote_port not in self.tunnel_mgr.tcp_map:
                    client_conn.close()
                    return
                
                client_id = self.tunnel_mgr.tcp_map[remote_port]
                control_conn = self.tunnel_mgr.conn_map.get(client_id)
                
                if not control_conn:
                    client_conn.close()
                    return

            proxy_conn = self._create_proxy_channel(control_conn, remote_port)
            self._bridge_connections(client_conn, proxy_conn)
            
        except Exception as e:
            logger.error(f"TCP处理错误: {str(e)}")
        finally:
            client_conn.close()

    def _create_proxy_channel(self, control_conn: ssl.SSLSocket, remote_port: int) -> socket.socket:
        """通过控制连接建立代理通道"""
        req_id = secrets.token_hex(4)
        msg = {
            'Type': 'StartProxy',
            'Payload': {
                'ReqId': req_id,
                'Url': f"tcp://{self.tunnel_mgr.domain}:{remote_port}",
                'ClientAddr': 'remote'
            }
        }
        self._send_control_message(control_conn, msg)
        return self._wait_for_proxy_connection(req_id, timeout=30)

    def _wait_for_proxy_connection(self, req_id: str, timeout: int) -> socket.socket:
        """等待客户端建立代理连接"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            with self.lock:
                if req_id in self.tunnel_mgr.tunnels:
                    return self.tunnel_mgr.tunnels[req_id]['proxy_conn']
            time.sleep(0.1)
        raise TimeoutError("等待代理连接超时")

    def _send_control_message(self, conn: ssl.SSLSocket, msg: dict):
        """发送控制消息"""
        try:
            data = json.dumps(msg).encode()
            header = struct.pack('<II', len(data), 0)
            conn.send(header + data)
        except ssl.SSLWantWriteError:
            pass

    def _bridge_connections(self, client_conn: socket.socket, proxy_conn: socket.socket):
        """桥接两个TCP连接"""
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(self.bufsize)
                    if not data:
                        break
                    dst.send(data)
            except ConnectionResetError:
                pass
            finally:
                src.close()
                dst.close()

        threading.Thread(
            target=forward, 
            args=(client_conn, proxy_conn),
            daemon=True
        ).start()
        
        threading.Thread(
            target=forward, 
            args=(proxy_conn, client_conn),
            daemon=True
        ).start()

class TunnelServer(HttpTunnelHandler, TcpTunnelHandler):
    """集成所有服务的完整服务端"""
    def __init__(self):
        self.config = {
            'host': '0.0.0.0',
            'http_port': 80,
            'https_port': 443,
            'control_port': 4443,  # 控制端口
            'ssl_cert': 'snakeoil.crt',
            'ssl_key': 'snakeoil.key',
            'domain': 'ngrok.com', # 服务域名
            'bufsize': 1024,       # 缓冲区大小
            'heartbeat_timeout': 30
        }
        self.tunnel_mgr = TunnelManager(self.config['domain'])
        # 显式初始化父类
        HttpTunnelHandler.__init__(
            self, 
            self.tunnel_mgr, 
            self.config['ssl_cert'], 
            self.config['ssl_key'], 
            self.config['bufsize']
        )
        TcpTunnelHandler.__init__(
            self,
            self.tunnel_mgr,
            self.config['bufsize']
        )

    def start_control_service(self):
        """启动4443端口的控制服务"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile=self.config['ssl_cert'],
            keyfile=self.config['ssl_key']
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.config['host'], self.config['control_port']))
            sock.listen(100)
            logger.info(f"控制服务已启动，监听端口：{self.config['control_port']}")
            
            while True:
                try:
                    conn, addr = sock.accept()
                    ssl_conn = context.wrap_socket(conn, server_side=True)
                    client_id = secrets.token_hex(16)
                    threading.Thread(
                        target=self.handle_control_connection,
                        args=(ssl_conn, client_id),
                        daemon=True
                    ).start()
                except Exception as e:
                    logger.error(f"接受控制连接失败: {str(e)}")

    def handle_control_connection(self, conn: ssl.SSLSocket, client_id: str):
        """处理控制连接"""
        logger = logging.getLogger(f"Control:{client_id[:8]}")
        buffer = b''
        last_active = time.time()
        
        try:
            # 将客户端添加到连接映射
            with self.tunnel_mgr.lock:
                self.tunnel_mgr.conn_map[client_id] = conn

            while True:
                # 心跳检查
                if time.time() - last_active > self.config['heartbeat_timeout']:
                    logger.warning("心跳超时，断开连接")
                    break

                # 接收数据
                try:
                    data = conn.recv(self.config['bufsize'])
                    if not data:
                        break
                    buffer += data
                except ssl.SSLWantReadError:
                    time.sleep(0.1)
                    continue

                # 处理完整消息
                while len(buffer) >= 8:
                    msg_len = struct.unpack('<I', buffer[:4])[0]
                    if len(buffer) < msg_len + 8:
                        break

                    msg_data = buffer[8:8+msg_len]
                    buffer = buffer[8+msg_len:]
                    last_active = time.time()

                    try:
                        msg = json.loads(msg_data.decode())
                        self.process_control_message(conn, client_id, msg)
                    except json.JSONDecodeError:
                        logger.error("无效消息格式")

        except Exception as e:
            logger.error(f"控制连接异常: {str(e)}")
        finally:
            self.tunnel_mgr.unregister_client(client_id)
            conn.close()
            logger.info("控制连接关闭")

    def process_control_message(self, conn: ssl.SSLSocket, client_id: str, msg: dict):
        """处理控制消息（增强隧道注册检查）"""
        msg_type = msg.get('Type')
        payload = msg.get('Payload', {})

        logger.debug(f"收到控制消息: {msg_type}")

        if msg_type == 'Auth':
            self.send_response(conn, {
                'Type': 'AuthResp',
                'Payload': {
                    'ClientId': client_id,
                    'Version': '2',
                    'MmVersion': '1.7'
                }
            })
            logger.info(f"客户端认证成功: {client_id}")

        elif msg_type == 'ReqTunnel':
            try:
                tunnel_type = payload['Protocol']
                config = {
                    'Hostname': payload.get('Hostname', ''),
                    'Subdomain': payload.get('Subdomain', ''),
                    'RemotePort': payload.get('RemotePort', 0)
                }
                
                # 检查隧道是否已存在
                tentative_url = self.tunnel_mgr._generate_url(tunnel_type, config)
                if tentative_url in self.tunnel_mgr.tunnels:
                    raise ValueError(f"Tunnel {tentative_url} already exists")

                tunnel_info = self.tunnel_mgr.register_tunnel(client_id, tunnel_type, config)
                
                self.send_response(conn, {
                    'Type': 'NewTunnel',
                    'Payload': {
                        'ReqId': payload['ReqId'],
                        'Url': tunnel_info['url'],
                        'Protocol': tunnel_type,
                        'Error': ''
                    }
                })
                logger.info(f"隧道已建立: {tunnel_info['url']}")

                # 如果是TCP隧道，启动监听
                if tunnel_type == 'tcp':
                    self.start_tcp_listener(tunnel_info['config']['RemotePort'])

            except Exception as e:
                self.send_response(conn, {
                    'Type': 'NewTunnel',
                    'Payload': {
                        'ReqId': payload['ReqId'],
                        'Error': str(e)
                    }
                })
                logger.error(f"隧道创建失败: {str(e)}")

        elif msg_type == 'Ping':
            self.send_response(conn, {'Type': 'Pong'})

    def send_response(self, conn: ssl.SSLSocket, data: dict):
        """发送响应消息"""
        try:
            msg = json.dumps(data).encode()
            header = struct.pack('<II', len(msg), 0)
            conn.send(header + msg)
        except Exception as e:
            logger.error(f"发送响应失败: {str(e)}")

    def run(self):
        """启动所有服务"""
        # 启动控制服务（4443端口）
        control_thread = threading.Thread(
            target=self.start_control_service,
            daemon=True
        )
        control_thread.start()

        # 启动HTTP/HTTPS服务
        loop = asyncio.get_event_loop()
        loop.run_until_complete(asyncio.start_server(
            self.handle_http_request,
            host=self.config['host'],
            port=self.config['http_port']
        ))
        loop.run_until_complete(asyncio.start_server(
            self.handle_http_request,
            host=self.config['host'],
            port=self.config['https_port'],
            ssl=self.ssl_ctx
        ))

        try:
            loop.run_forever()
        except KeyboardInterrupt:
            logger.info("正在关闭服务器...")
            loop.close()

if __name__ == '__main__':
    server = TunnelServer()
    server.run()
