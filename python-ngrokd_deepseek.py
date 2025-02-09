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
    def __init__(self):
        self.tunnels: Dict[str, dict] = {}  # client_id: tunnel_info
        self.conn_map: Dict[str, ssl.SSLSocket] = {}  # client_id: control_conn
        self.host_map: Dict[str, str] = {}  # hostname: client_id
        self.subdomain_map: Dict[str, str] = {}  # subdomain: client_id
        self.tcp_map: Dict[int, str] = {}  # remote_port: client_id
        self.port_pool = deque(range(10000, 60000))  # 可用端口池
        self.lock = threading.RLock()

    def register_tunnel(self, client_id: str, tunnel_type: str, config: dict) -> dict:
        """注册新隧道"""
        with self.lock:
            url = self._generate_url(tunnel_type, config)
            
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
                return f"http://{config['Subdomain']}.ngrok.io"
            return f"http://{config['Hostname']}" if config['Hostname'] else f"http://{secrets.token_hex(8)}.ngrok.io"
        elif tunnel_type == 'tcp':
            return f"tcp://ngrok.io:{config['RemotePort']}"
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
    def __init__(self, tunnel_mgr: TunnelManager):
        self.tunnel_mgr = tunnel_mgr
        self.executor = ThreadPoolExecutor(max_workers=100)
        self.ssl_ctx = self._create_ssl_context()

    def _create_ssl_context(self):
        """创建SSL上下文"""
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile='server.crt', keyfile='server.key')
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
                    data = await src.read(4096)
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
    def __init__(self, tunnel_mgr: TunnelManager):
        self.tunnel_mgr = tunnel_mgr
        self.listeners: Dict[int, socket.socket] = {}
        self.executor = ThreadPoolExecutor(max_workers=100)
        self.lock = threading.RLock()

    def start_tcp_listener(self, port: int):
        """启动TCP端口监听"""
        with self.lock:
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
                                self.handle_tcp_connection, 
                                client_conn, 
                                port
                            )
                        except OSError:
                            break

            thread = threading.Thread(target=_listen, daemon=True)
            thread.start()
            return thread

    def handle_tcp_connection(self, client_conn: socket.socket, remote_port: int):
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

            proxy_conn = self.create_proxy_channel(control_conn, remote_port)
            self.bridge_connections(client_conn, proxy_conn)
            
        except Exception as e:
            logger.error(f"TCP处理错误: {str(e)}")
        finally:
            client_conn.close()

    def create_proxy_channel(self, control_conn: ssl.SSLSocket, remote_port: int) -> socket.socket:
        """通过控制连接建立代理通道"""
        req_id = secrets.token_hex(4)
        msg = {
            'Type': 'StartProxy',
            'Payload': {
                'ReqId': req_id,
                'Url': f"tcp://ngrok.io:{remote_port}",
                'ClientAddr': 'remote'
            }
        }
        self.send_control_message(control_conn, msg)
        return self.wait_for_proxy_connection(req_id, timeout=30)

    def bridge_connections(self, client_conn: socket.socket, proxy_conn: socket.socket):
        """桥接两个TCP连接"""
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
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
    """集成HTTP和TCP功能的服务端"""
    def __init__(self):
        self.config = {
            'host': '',
            'http_port': 80,
            'https_port': 443,
            'control_port': 4443,
            'ssl_cert': 'server.crt',
            'ssl_key': 'server.key',
            'max_workers': 100,
            'heartbeat_timeout': 30
        }
        self.tunnel_mgr = TunnelManager()
        super().__init__(self.tunnel_mgr)

    def run(self):
        """启动所有服务"""
        loop = asyncio.get_event_loop()
        
        # 启动HTTP服务
        loop.run_until_complete(asyncio.start_server(
            self.handle_http_request,
            host=self.config['host'],
            port=self.config['http_port']
        ))
        
        # 启动HTTPS服务
        loop.run_until_complete(asyncio.start_server(
            self.handle_http_request,
            host=self.config['host'],
            port=self.config['https_port'],
            ssl=self.ssl_ctx
        ))
        
        # 启动控制服务
        control_thread = threading.Thread(target=self.start_control_service)
        control_thread.start()

        try:
            loop.run_forever()
        except KeyboardInterrupt:
            logger.info("正在关闭服务器...")
            loop.close()

if __name__ == '__main__':
    server = TunnelServer()
    server.run()