#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 3.12.0 以上运行
# 项目地址: https://github.com/hauntek/python-ngrokd
# Version: v2.00
# ngrokd_final.py
import socket
import ssl
import json
import struct
import time
import logging
import threading
import secrets
import asyncio
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Deque

# === 日志配置 ===
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S'
)
logger = logging.getLogger('ngrokd')

# === 隧道管理器 ===
class TunnelManager:
    def __init__(self, domain: str):
        self.domain = domain
        self.tunnels: Dict[str, dict] = {}
        self.conn_map: Dict[str, ssl.SSLSocket] = {}
        self.host_map: Dict[str, str] = {}
        self.subdomain_map: Dict[str, str] = {}
        self.tcp_map: Dict[int, str] = {}
        self.port_pool = deque(range(10000, 60000))
        self.lock = threading.RLock()
        
        # 请求队列管理
        self.pending_requests = defaultdict(deque)  # client_id: Deque[dict]
        self.ready_clients = set()

    def register_tunnel(self, client_id: str, tunnel_type: str, config: dict) -> dict:
        with self.lock:
            # Hostname唯一性检查
            if tunnel_type in ['http', 'https'] and config.get('Hostname'):
                if config['Hostname'] in self.host_map:
                    raise ValueError(f"Hostname {config['Hostname']} already exists")
                self.host_map[config['Hostname']] = client_id
            
            # 生成URL
            url = self._generate_url(tunnel_type, config)
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
        if tunnel_type == 'http':
            host_part = config.get('Hostname') or f"{config.get('Subdomain', secrets.token_hex(4))}.{self.domain}"
            return f"http://{host_part}"
        elif tunnel_type == 'https':
            host_part = config.get('Hostname') or f"{config.get('Subdomain', secrets.token_hex(4))}.{self.domain}"
            return f"https://{host_part}"
        elif tunnel_type == 'tcp':
            return f"tcp://{self.domain}:{config['RemotePort']}"
        raise ValueError(f"Unsupported tunnel type: {tunnel_type}")

    def add_pending_request(self, client_id: str, request: dict):
        with self.lock:
            self.pending_requests[client_id].append(request)

    def get_pending_request(self, client_id: str) -> dict:
        with self.lock:
            return self.pending_requests[client_id].popleft()

    def mark_client_ready(self, client_id: str):
        with self.lock:
            self.ready_clients.add(client_id)

    def unregister_client(self, client_id: str):
        with self.lock:
            # 清理host映射
            to_remove = [host for host, cid in self.host_map.items() if cid == client_id]
            for host in to_remove:
                del self.host_map[host]
            
            # 清理隧道记录
            for url in list(self.tunnels.keys()):
                if self.tunnels[url]['client_id'] == client_id:
                    if self.tunnels[url]['type'] == 'tcp':
                        port = self.tunnels[url]['config']['RemotePort']
                        self.port_pool.append(port)
                        del self.tcp_map[port]
                    del self.tunnels[url]
            
            if client_id in self.conn_map:
                del self.conn_map[client_id]
            
            # 清理等待队列
            del self.pending_requests[client_id]
            self.ready_clients.discard(client_id)

# === HTTP/HTTPS处理 ===
class HttpTunnelHandler:
    def __init__(self, tunnel_mgr: TunnelManager, ssl_cert: str, ssl_key: str, bufsize: int):
        self.tunnel_mgr = tunnel_mgr
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.bufsize = bufsize
        self.executor = ThreadPoolExecutor(max_workers=100)
        self.ssl_ctx = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile=self.ssl_cert, keyfile=self.ssl_key)
        return ctx

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            # 检测HTTPS请求
            peek_data = await reader.read(1024)
            is_https = peek_data.startswith(b'\x16\x03')
            reader._buffer = peek_data + reader._buffer  # 回退数据

            if is_https:
                await self.handle_https(reader, writer)
            else:
                await self.handle_http(reader, writer)
        except Exception as e:
            logger.error(f"连接处理失败: {str(e)}")
            writer.close()

    async def handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            header = await reader.readuntil(b'\r\n\r\n')
            headers = self.parse_headers(header.decode())
            host = headers.get('Host', '')
            await self.process_request(host, reader, writer)
        except asyncio.IncompleteReadError:
            pass

    async def handle_https(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            ssl_reader, ssl_writer = await asyncio.wait_for(
                asyncio.start_ssl(
                    reader, writer,
                    sslcontext=self.ssl_ctx,
                    server_side=True
                ),
                timeout=10
            )
            sni = ssl_writer.get_extra_info('ssl_object').sni_callback
            await self.process_request(sni, ssl_reader, ssl_writer)
        except (asyncio.TimeoutError, ssl.SSLError) as e:
            logger.error(f"SSL握手失败: {str(e)}")
            writer.close()

    def parse_headers(self, header_str: str) -> dict:
        headers = {}
        for line in header_str.split('\r\n')[1:]:  # 跳过请求行
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.strip()] = value.strip()
        return headers

    async def process_request(self, host: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if not host:
            writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            await writer.drain()
            writer.close()
            return

        # 查找对应的客户端
        with self.tunnel_mgr.lock:
            client_id = self.tunnel_mgr.host_map.get(host)
            if not client_id or client_id not in self.tunnel_mgr.conn_map:
                writer.write(b'HTTP/1.1 404 Not Found\r\n\r\n')
                await writer.drain()
                writer.close()
                return

        # 生成客户端地址
        client_addr = f"{secrets.token_hex(4)}.{self.tunnel_mgr.domain}:{secrets.randbelow(20000)+40000}"
        
        # 发送ReqProxy
        control_conn = self.tunnel_mgr.conn_map[client_id]
        self.send_control_message(control_conn, {'Type': 'ReqProxy', 'Payload': {}})
        
        # 记录待处理请求
        request_data = {
            'client_addr': client_addr,
            'host': host,
            'reader': reader,
            'writer': writer,
            'timestamp': time.time()
        }
        self.tunnel_mgr.add_pending_request(client_id, request_data)

    def send_control_message(self, conn: ssl.SSLSocket, msg: dict):
        try:
            data = json.dumps(msg).encode()
            header = struct.pack('<I', len(data))
            conn.sendall(header + data)
        except (ssl.SSLWantWriteError, BrokenPipeError) as e:
            logger.warning(f"控制消息发送失败: {str(e)}")

# === TCP隧道处理 ===
class TcpTunnelHandler:
    def __init__(self, tunnel_mgr: TunnelManager, bufsize: int):
        self.tunnel_mgr = tunnel_mgr
        self.bufsize = bufsize
        self.listeners: Dict[int, socket.socket] = {}
        self.executor = ThreadPoolExecutor(max_workers=100)
        self.lock = threading.Lock()

    def start_tcp_listener(self, port: int):
        with self.lock:
            if port in self.listeners:
                return

            def listen_task():
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind(('0.0.0.0', port))
                    sock.listen(100)
                    self.listeners[port] = sock
                    logger.info(f"TCP监听启动: {port}")

                    while True:
                        try:
                            client_conn, addr = sock.accept()
                            self.executor.submit(
                                self.handle_tcp_connection,
                                client_conn,
                                port
                            )
                        except OSError:
                            break

            threading.Thread(target=listen_task, daemon=True).start()

    def handle_tcp_connection(self, client_conn: socket.socket, port: int):
        try:
            with self.lock:
                client_id = self.tunnel_mgr.tcp_map.get(port)
                if not client_id or client_id not in self.tunnel_mgr.conn_map:
                    client_conn.close()
                    return

            # 发送ReqProxy
            control_conn = self.tunnel_mgr.conn_map[client_id]
            self.send_control_message(control_conn, {'Type': 'ReqProxy', 'Payload': {}})
            
            # 记录待处理请求
            client_addr = f"{client_conn.getpeername()[0]}:{port}"
            request_data = {
                'client_addr': client_addr,
                'connection': client_conn,
                'timestamp': time.time()
            }
            self.tunnel_mgr.add_pending_request(client_id, request_data)

        except Exception as e:
            logger.error(f"TCP处理失败: {str(e)}")
            client_conn.close()

    def send_control_message(self, conn: ssl.SSLSocket, msg: dict):
        try:
            data = json.dumps(msg).encode()
            header = struct.pack('<I', len(data))
            conn.sendall(header + data)
        except (ssl.SSLWantWriteError, BrokenPipeError) as e:
            logger.warning(f"TCP控制消息发送失败: {str(e)}")

# === 主服务 ===
class TunnelServer(HttpTunnelHandler, TcpTunnelHandler):
    def __init__(self):
        self.config = {
            'host': '0.0.0.0',
            'http_port': 80,
            'https_port': 443,
            'control_port': 4443,
            'ssl_cert': 'server.crt',
            'ssl_key': 'server.key',
            'domain': 'ngrok.example.com',
            'bufsize': 4096,
            'heartbeat_timeout': 30
        }
        self.tunnel_mgr = TunnelManager(self.config['domain'])
        
        HttpTunnelHandler.__init__(
            self,
            self.tunnel_mgr,
            self.config['ssl_cert'],
            self.config['ssl_key'],
            self.config['bufsize']
        )
        TcpTunnelHandler.__init__(self, self.tunnel_mgr, self.config['bufsize'])

    async def handle_control_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_id = secrets.token_hex(16)
        logger.info(f"新控制连接: {client_id[:8]}")

        try:
            # 认证处理
            auth_msg = await reader.readuntil(b'\r\n\r\n')
            auth_data = json.loads(auth_msg.decode().strip())
            if auth_data.get('Type') != 'Auth':
                raise ValueError("需要先进行认证")

            # 发送认证响应
            resp = {
                'Type': 'AuthResp',
                'Payload': {
                    'ClientId': client_id,
                    'Version': '2',
                    'MmVersion': '1.7'
                }
            }
            writer.write(json.dumps(resp).encode() + b'\r\n\r\n')
            await writer.drain()
            logger.info(f"客户端认证成功: {client_id[:8]}")

            # 注册控制连接
            ssl_socket = writer.get_extra_info('ssl_object')
            with self.tunnel_mgr.lock:
                self.tunnel_mgr.conn_map[client_id] = ssl_socket

            # 消息处理循环
            while True:
                try:
                    header = await reader.readexactly(4)
                    msg_len = struct.unpack('<I', header)[0]
                    msg_data = await reader.readexactly(msg_len)
                    msg = json.loads(msg_data.decode())
                    await self.process_control_message(client_id, msg, writer)
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    break

        except Exception as e:
            logger.error(f"控制连接错误: {str(e)}")
        finally:
            self.tunnel_mgr.unregister_client(client_id)
            writer.close()
            logger.info(f"控制连接关闭: {client_id[:8]}")

    async def process_control_message(self, client_id: str, msg: dict, writer):
        msg_type = msg.get('Type')
        payload = msg.get('Payload', {})

        if msg_type == 'ReqTunnel':
            try:
                tunnel_type = payload.get('Protocol')
                config = {
                    'Hostname': payload.get('Hostname', ''),
                    'Subdomain': payload.get('Subdomain', ''),
                    'RemotePort': payload.get('RemotePort', 0)
                }
                tunnel_info = self.tunnel_mgr.register_tunnel(client_id, tunnel_type, config)
                
                response = {
                    'Type': 'NewTunnel',
                    'Payload': {
                        'Url': tunnel_info['url'],
                        'Protocol': tunnel_type,
                        'Error': ''
                    }
                }

                if tunnel_type == 'tcp':
                    self.start_tcp_listener(config['RemotePort'])

            except Exception as e:
                response = {
                    'Type': 'NewTunnel',
                    'Payload': {
                        'Error': str(e)
                    }
                }

            writer.write(json.dumps(response).encode() + b'\r\n\r\n')
            await writer.drain()

        elif msg_type == 'RegProxy':
            logger.info(f"客户端 {client_id[:8]} 注册代理")
            self.tunnel_mgr.mark_client_ready(client_id)
            
            # 处理等待中的请求
            try:
                request = self.tunnel_mgr.get_pending_request(client_id)
                self.send_start_proxy(client_id, request)
            except IndexError:
                pass

        elif msg_type == 'Ping':
            writer.write(json.dumps({'Type': 'Pong'}).encode() + b'\r\n\r\n')
            await writer.drain()

    def send_start_proxy(self, client_id: str, request: dict):
        control_conn = self.tunnel_mgr.conn_map.get(client_id)
        if not control_conn:
            return

        # HTTP/HTTPS处理
        if 'host' in request:
            msg = {
                'Type': 'StartProxy',
                'Payload': {
                    'Url': f"http://{request['host']}",
                    'ClientAddr': request['client_addr']
                }
            }
            self.send_control_message(control_conn, msg)
            
            # 启动数据桥接
            asyncio.create_task(self.bridge_http_connection(
                request['reader'],
                request['writer'],
                request['client_addr']
            ))

        # TCP处理
        elif 'connection' in request:
            msg = {
                'Type': 'StartProxy',
                'Payload': {
                    'Url': f"tcp://{self.tunnel_mgr.domain}:{request['client_addr'].split(':')[1]}",
                    'ClientAddr': request['client_addr']
                }
            }
            self.send_control_message(control_conn, msg)
            
            # 启动数据桥接
            self.bridge_tcp_connection(
                request['connection'],
                request['client_addr']
            )

    async def bridge_http_connection(self, reader, writer, client_addr):
        try:
            host, port = client_addr.split(':')
            proxy_reader, proxy_writer = await asyncio.open_connection(host, int(port))

            async def forward(src, dst):
                try:
                    while True:
                        data = await src.read(self.config['bufsize'])
                        if not data:
                            break
                        dst.write(data)
                        await dst.drain()
                except:
                    pass

            await asyncio.gather(
                forward(reader, proxy_writer),
                forward(proxy_reader, writer)
            )

        except Exception as e:
            logger.error(f"HTTP桥接失败: {str(e)}")
        finally:
            writer.close()
            proxy_writer.close()

    def bridge_tcp_connection(self, client_conn: socket.socket, client_addr: str):
        try:
            host, port = client_addr.split(':')
            proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_sock.connect((host, int(port)))

            def forward(src, dst):
                try:
                    while True:
                        data = src.recv(self.config['bufsize'])
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
                args=(client_conn, proxy_sock),
                daemon=True
            ).start()
            
            threading.Thread(
                target=forward,
                args=(proxy_sock, client_conn),
                daemon=True
            ).start()

        except Exception as e:
            logger.error(f"TCP桥接失败: {str(e)}")
            client_conn.close()

    async def start_servers(self):
        # 启动控制服务
        control_server = await asyncio.start_server(
            self.handle_control_connection,
            host=self.config['host'],
            port=self.config['control_port']
        )

        # 启动HTTP服务
        http_server = await asyncio.start_server(
            self.handle_connection,
            host=self.config['host'],
            port=self.config['http_port']
        )

        # 启动HTTPS服务
        https_server = await asyncio.start_server(
            self.handle_connection,
            host=self.config['host'],
            port=self.config['https_port'],
            ssl=self.ssl_ctx
        )

        async with control_server, http_server, https_server:
            logger.info("服务器已启动")
            await asyncio.gather(
                control_server.serve_forever(),
                http_server.serve_forever(),
                https_server.serve_forever()
            )

if __name__ == '__main__':
    server = TunnelServer()
    asyncio.run(server.start_servers())
