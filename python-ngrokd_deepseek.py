#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 3.10.0 以上运行
# 项目地址: https://github.com/hauntek/python-ngrokd
# Version: v2.00
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
from typing import Dict, Deque, List

# === Global Configuration ===
CONFIG = {
    'host': '0.0.0.0',
    'http_port': 80,
    'https_port': 443,
    'control_port': 4443,
    'domain': 'ngrok.com',
    'bufsize': 8192,
    'min_port': 10000,
    'max_port': 60000,
    'ssl_cert': 'snakeoil.crt',
    'ssl_key': 'snakeoil.key'
}

# === Logging Configuration ===
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S'
)
logger = logging.getLogger('ngrokd')

# === Tunnel Management Core ===
class TunnelManager:
    def __init__(self):
        self.tunnels: Dict[str, dict] = {}
        self.client_tunnels: Dict[str, List[str]] = defaultdict(list)
        self.writer_map: Dict[str, asyncio.StreamWriter] = {}
        self.reader_map: Dict[str, asyncio.StreamReader] = {}
        self.port_pool = deque(range(CONFIG['min_port'], CONFIG['max_port']))
        self.lock = threading.RLock()
        self.pending_requests = defaultdict(deque)
        self.ready_clients = set()

    def register_tunnel(self, client_id: str, tunnel_type: str, config: dict) -> dict:
        with self.lock:
            # Validate and generate URL
            url = self._generate_url(tunnel_type, config)
            if url in self.tunnels:
                raise ValueError(f"Tunnel {url} already registered")

            if tunnel_type == 'tcp':
                if (port := config.get('RemotePort', 0)) == 0:
                    if not self.port_pool:
                        raise ValueError("No available ports")
                    port = self.port_pool.popleft()
                elif self.tunnels.get(f"tcp://{CONFIG['domain']}:{port}"):
                    raise ValueError(f"Port {port} already in use")
                config['RemotePort'] = port

            # Generate tunnel URL
            tunnel_info = {
                'client_id': client_id,
                'type': tunnel_type,
                'url': url,
                'config': config,
                'created_at': time.time()
            }
            self.tunnels[url] = tunnel_info
            self.client_tunnels[client_id].append(url)
            return tunnel_info

    def _generate_url(self, tunnel_type: str, config: dict) -> str:
        if tunnel_type == 'http':
            if config['Subdomain']:
                return f"http://{config['Subdomain']}.{CONFIG['domain']}"
            return f"http://{config['Hostname']}" if config['Hostname'] else f"http://{secrets.token_hex(4)}.{CONFIG['domain']}"
        elif tunnel_type == 'https':
            if config['Subdomain']:
                return f"https://{config['Subdomain']}.{CONFIG['domain']}"
            return f"https://{config['Hostname']}" if config['Hostname'] else f"https://{secrets.token_hex(4)}.{CONFIG['domain']}"

        elif tunnel_type == 'tcp':
            return f"tcp://{CONFIG['domain']}:{config['RemotePort']}"
        raise ValueError(f"Invalid tunnel type: {tunnel_type}")

    def cleanup_client(self, client_id: str):
        with self.lock:
            # Release TCP ports
            for url in list(self.tunnels.keys()):
                if self.tunnels[url]['client_id'] == client_id:
                    if self.tunnels[url]['type'] == 'tcp':
                        port = self.tunnels[url]['config']['RemotePort']
                        self.port_pool.append(port)
                    del self.tunnels[url]
            
            # Clear connection records
            if client_id in self.writer_map:
                del self.writer_map[client_id]
            if client_id in self.reader_map:
                del self.reader_map[client_id]
            self.pending_requests.pop(client_id, None)
            self.ready_clients.discard(client_id)
            self.client_tunnels.pop(client_id, None)

# === TCP Tunnel Handler ===
class TcpTunnelHandler:
    def __init__(self, tunnel_mgr: TunnelManager):
        self.tunnel_mgr = tunnel_mgr
        self.listeners: Dict[int, socket.socket] = {}
        self.lock = threading.Lock()

    def start_listener(self, port: int):
        with self.lock:
            if port in self.listeners:
                return

            def listen_thread():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('0.0.0.0', port))
                sock.listen(100)
                self.listeners[port] = sock
                logger.info(f"TCP监听已启动 port:{port}")

                while True:
                    try:
                        conn, _ = sock.accept()
                        self.handle_tcp_connection(conn, port)
                    except OSError:
                        break

            threading.Thread(target=listen_thread, daemon=True).start()

    def handle_tcp_connection(self, conn: socket.socket, port: int):
        try:
            protocol = 'tcp'
            lookup_url = f"{protocol}://{CONFIG['domain']}:{port}"
            with self.tunnel_mgr.lock:
                tunnel_info = self.tunnel_mgr.tunnels.get(lookup_url)
                if not tunnel_info:
                    conn.close()
                    return

                client_id = tunnel_info.get('client_id', '')
                tunnel_url = tunnel_info.get('url', '')

            client_addr = f"{conn.getpeername()[0]}:{port}"
            
            # Send ReqProxy
            self._send_control_msg(
                self.tunnel_mgr.writer_map[client_id],
                {'Type': 'ReqProxy', 'Payload': {}}
            )
            
            # Store request with tunnel URL
            self.tunnel_mgr.pending_requests[client_id].append({
                'type': 'tcp',
                'conn': conn,
                'client_addr': client_addr,
                'tunnel_url': tunnel_url,
                'time': time.time()
            })

        except Exception as e:
            logger.error(f"TCP处理错误: {str(e)}")
            conn.close()

    def _send_control_msg(self, writer: asyncio.StreamWriter, msg: dict):
        try:
            data = json.dumps(msg).encode()
            header = struct.pack('<II', len(data), 0)
            writer.write(header + data)
        except (ssl.SSLWantWriteError, BrokenPipeError):
            pass

# === HTTP/HTTPS Handler ===
class HttpTunnelHandler:
    def __init__(self, tunnel_mgr: TunnelManager):
        self.tunnel_mgr = tunnel_mgr
        self.ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_ctx.load_cert_chain(CONFIG['ssl_cert'], CONFIG['ssl_key'])

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            # Detect SSL
            is_ssl = await self._detect_ssl(reader)
            
            # Get host from request
            host = await self._get_host(reader, is_ssl)
            if not host:
                writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                await writer.drain()
                return

            protocol = 'https' if is_ssl else 'http'
            lookup_url = f"{protocol}://{host}"

            # Find client and tunnel URL
            with self.tunnel_mgr.lock:
                tunnel_info = self.tunnel_mgr.tunnels.get(lookup_url)
                if not tunnel_info:

                    html = 'Tunnel %s not found' % host
                    header = "HTTP/1.0 404 Not Foun" + "\r\n"
                    header += "Content-Length: %d" + "\r\n"
                    header += "\r\n" + "%s"
                    header_data = header % (len(html.encode('utf-8')), html)

                    writer.write(header_data.encode('utf-8'))
                    await writer.drain()
                    return
                
                client_id = tunnel_info.get('client_id', '')
                tunnel_url = tunnel_info.get('url', '')

            # Generate client address
            peer_info = writer.get_extra_info('peername')
            client_ip, client_port = peer_info
            client_addr = f"{client_ip}:{client_port}"

            # Send ReqProxy
            self._send_control_msg(
                self.tunnel_mgr.writer_map[client_id],
                {'Type': 'ReqProxy', 'Payload': {}}
            )
            
            # Store request with tunnel URL
            self.tunnel_mgr.pending_requests[client_id].append({
                'type': ('https' if is_ssl else 'http'),
                'reader': reader,
                'writer': writer,
                'client_addr': client_addr,
                'tunnel_url': tunnel_url,
                'time': time.time()
            })

        except Exception as e:
            logger.error(f"HTTP处理错误: {str(e)}")
            writer.close()

    async def _detect_ssl(self, reader: asyncio.StreamReader) -> bool:
        peek_data = await reader.read(1024)
        is_ssl = peek_data.startswith(b'\x16\x03')
        reader.feed_data(peek_data)
        return is_ssl

    async def _get_host(self, reader: asyncio.StreamReader, is_ssl: bool) -> str:
        if is_ssl:
            return await self._get_sni_host(reader)
        else:
            return await self._parse_http_host(reader)

    async def _get_sni_host(self, reader: asyncio.StreamReader) -> str:
        try:
            ssl_reader = await reader.start_tls(
                ssl_context=self.ssl_ctx,
                server_side=True
            )
            return ssl_reader._sslobj.server_side_context.get_servername() or ''
        except Exception:
            return ''

    async def _parse_http_host(self, reader: asyncio.StreamReader) -> str:
        headers = {}
        peek_data = await reader.read(1024)
        reader.feed_data(peek_data)
        while True:
            try:
                line = await reader.readuntil(b'\r\n')
                if line == b'\r\n':
                    break

                key, value = line.decode().strip().split(': ', 1)
                headers[key] = value
            except Exception:
                pass

        reader.feed_data(peek_data)

        return headers.get('Host', '')

    def _send_control_msg(self, writer: asyncio.StreamWriter, msg: dict):
        try:
            data = json.dumps(msg).encode()
            header = struct.pack('<II', len(data), 0)
            writer.write(header + data)
        except (ssl.SSLWantWriteError, BrokenPipeError):
            pass

# === Main Server Implementation ===
class TunnelServer:
    def __init__(self):
        self.tunnel_mgr = TunnelManager()
        self.tcp_handler = TcpTunnelHandler(self.tunnel_mgr)
        self.http_handler = HttpTunnelHandler(self.tunnel_mgr)
        self.ssl_ctx = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CONFIG['ssl_cert'], CONFIG['ssl_key'])
        return ctx

    async def start_servers(self):
        async with await asyncio.start_server(
            self._handle_control,
            host=CONFIG['host'],
            port=CONFIG['control_port'],
            ssl=self.ssl_ctx
        ) as ctrl_srv, \
        await asyncio.start_server(
            self.http_handler.handle_connection,
            host=CONFIG['host'],
            port=CONFIG['http_port']
        ) as http_srv, \
        await asyncio.start_server(
            self.http_handler.handle_connection,
            host=CONFIG['host'],
            port=CONFIG['https_port'],
            ssl=self.http_handler.ssl_ctx
        ) as https_srv:
            logger.info(f"控制服务已启动，监听端口: {CONFIG['control_port']}")
            logger.info(f"HTTP服务已启动，监听端口: {CONFIG['http_port']}")
            logger.info(f"HTTPS服务已启动，监听端口: {CONFIG['https_port']}")
            await asyncio.gather(
                ctrl_srv.serve_forever(),
                http_srv.serve_forever(),
                https_srv.serve_forever()
            )

    async def _handle_control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_id = secrets.token_hex(16)
        logger = logging.getLogger(f"Control:{client_id[:8]}")
        try:
            # Authentication phase
            header = await reader.read(8)
            msg_len, _ = struct.unpack('<II', header)
            auth_msg = json.loads(await reader.read(msg_len))

            logger.debug(f"收到消息: {auth_msg}")

            if auth_msg['Type'] == 'Auth':
                resp = {
                    'Type': 'AuthResp',
                    'Payload': {
                        'Version': '2',
                        'MmVersion': '1.7',
                        'ClientId': client_id
                    }
                }
                self._send_msg(writer, resp)

                logger.info(f"客户端认证成功: {client_id}")

            elif auth_msg['Type'] == 'RegProxy':
                top_client_id = auth_msg['Payload'].get('ClientId', '')
                with self.tunnel_mgr.lock:
                    self.tunnel_mgr.writer_map[client_id] = writer
                    self.tunnel_mgr.reader_map[client_id] = reader
                    self.tunnel_mgr.ready_clients.add(client_id)
            
                # Process pending requests
                while self.tunnel_mgr.pending_requests[top_client_id]:
                    req = self.tunnel_mgr.pending_requests[top_client_id].popleft()
                    await self._start_proxy(client_id, req)

            elif auth_msg['Type'] != 'Auth':
                raise ValueError("First message must be Auth")

            # Register control connection
            with self.tunnel_mgr.lock:
                self.tunnel_mgr.writer_map[client_id] = writer
                self.tunnel_mgr.reader_map[client_id] = reader
            
            # Main message loop
            while True:
                try:
                    if auth_msg['Type'] == 'RegProxy':
                        break
                    header = await reader.read(8)
                    if not header:
                        break
                    msg_len, _ = struct.unpack('<II', header)
                    msg = json.loads(await reader.read(msg_len))
                    logger.debug(f"收到消息: {msg}")
                    await self._process_msg(client_id, msg, writer)
                except (ConnectionResetError, BrokenPipeError):
                    break

        except Exception as e:
            logger.error(f"Control connection error: {str(e)}")
        finally:
            self.tunnel_mgr.cleanup_client(client_id)
            writer.close()
            logger.info("控制连接关闭")

    async def _process_msg(self, client_id: str, msg: dict, writer: asyncio.StreamWriter):
        if msg['Type'] == 'ReqTunnel':
            try:
                tunnel = self.tunnel_mgr.register_tunnel(
                    client_id,
                    msg['Payload']['Protocol'],
                    msg['Payload']
                )
                resp = {
                    'Type': 'NewTunnel',
                    'Payload': {
                        'Url': tunnel['url'],
                        'Protocol': tunnel['type'],
                        'ReqId': msg['Payload'].get('ReqId', ''),
                        'Error': ''
                    }
                }
                if tunnel['type'] == 'tcp':
                    self.tcp_handler.start_listener(tunnel['config']['RemotePort'])

                logger.info(f"隧道已建立: {tunnel['url']}")
            except Exception as e:
                resp = {
                    'Type': 'NewTunnel',
                    'Payload': {
                        'Error': str(e),
                        'ReqId': msg['Payload'].get('ReqId', '')
                    }
                }

                logger.error(f"隧道创建失败: {str(e)}")
            
            self._send_msg(writer, resp)

        elif msg['Type'] == 'Ping':
            self._send_msg(writer, {'Type': 'Pong'})

    async def _start_proxy(self, client_id: str, req: dict):
        writer_conn = self.tunnel_mgr.writer_map.get(client_id)
        if not writer_conn:
            return

        reader_conn = self.tunnel_mgr.reader_map.get(client_id)
        if not reader_conn:
            return

        # Send StartProxy with Url and ClientAddr
        self._send_msg(writer_conn, {
            'Type': 'StartProxy',
            'Payload': {
                'Url': req['tunnel_url'],
                'ClientAddr': req['client_addr']
            }
        })

        # Start data bridging
        if req['type'] == 'tcp':
            await self._bridge_tcp_optimized(req['conn'], reader_conn, writer_conn)
        else:
             await self._bridge_http(
                req['reader'], req['writer'],
                reader_conn, writer_conn
            )

    def _send_msg(self, writer: asyncio.StreamWriter, msg: dict):
        try:
            data = json.dumps(msg).encode()
            writer.write(struct.pack('<II', len(data), 0) + data)
        except (ssl.SSLWantWriteError, BrokenPipeError):
            pass

    async def _bridge_http(self, src_reader, src_writer, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            async def forward(src, dst):
                try:
                    while data := await src.read(CONFIG['bufsize']):
                        dst.write(data)
                        await dst.drain()
                except (ConnectionResetError, BrokenPipeError):
                    pass
                finally:
                    await dst.wait_closed()
            
            await asyncio.gather(
                forward(src_reader, writer),
                forward(reader, src_writer)
            )
        except Exception as e:
            logger.error(f"HTTP桥接处理错误: {str(e)}")
        finally:
            src_writer.close()

    async def _bridge_tcp_optimized(self, local_conn: socket.socket, reader: asyncio.StreamReader,writer: asyncio.StreamWriter):
        """优化后的TCP桥接实现"""
        loop = asyncio.get_running_loop()
        try:
            # 创建双向桥接任务
            async def local_to_remote():
                while True:
                    try:
                        # 在线程池中执行同步recv
                        data = await loop.run_in_executor(
                            None,
                            lambda: local_conn.recv(CONFIG['bufsize'])
                        )
                        if not data:
                            break
                    
                        # 异步写入远程
                        writer.write(data)
                        await writer.drain()
                    except (ConnectionResetError, BrokenPipeError):
                        break

            async def remote_to_local():
                while True:
                    try:
                        # 异步读取远程数据
                        data = await reader.read(CONFIG['bufsize'])
                        if not data:
                            break

                        # 在线程池中执行同步send
                        await loop.run_in_executor(
                            None,
                            lambda: local_conn.sendall(data)
                        )
                    except (ConnectionResetError, BrokenPipeError):
                        break

            # 3. 并行执行双向传输
            await asyncio.gather(
                local_to_remote(),
                remote_to_local()
            )

        except Exception as e:
            logger.error(f"TCP桥接处理错误: {str(e)}")
        finally:
            # 4. 安全关闭连接
            await self._safe_close(local_conn, writer)


    async def _safe_close(self, local_conn: socket.socket, writer: asyncio.StreamWriter):
        """安全关闭连接的封装方法"""
        # 关闭本地socket
        try:
            local_conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        local_conn.close()


if __name__ == '__main__':
    server = TunnelServer()
    try:
        asyncio.run(server.start_servers())
    except KeyboardInterrupt:
        logger.info("Server shutdown gracefully")
