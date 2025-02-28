#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 3.10.0 以上运行
# 项目地址: https://github.com/hauntek/python-ngrokd
# Version: 2.4.0
import asyncio
import ssl
import json
import base64
import struct
import time
import secrets
import logging
from collections import defaultdict, deque

# === 全局配置 ===
CONFIG = {
    'host': '0.0.0.0',
    'http_port': 80,
    'https_port': 443,
    'control_port': 4443,
    'domain': 'ngrok.com',
    'bufsize': 8192,
    'timeout': 60,
    'authtoken': [],
    'min_port': 10000,
    'max_port': 60000,
    'ssl_cert': 'snakeoil.crt',
    'ssl_key': 'snakeoil.key'
}

# === 日志配置 ===
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S'
)
logger = logging.getLogger('ngrokd')

# === 隧道管理器 ===
class TunnelManager:
    def __init__(self):
        self.tunnels: dict[str, dict] = {}
        self.client_tunnels: dict[str, list[str]] = defaultdict(list)
        self.tcp_listeners: dict[int, asyncio.Server] = {}
        self.udp_listeners: dict[int, asyncio.DatagramTransport] = {}
        self.udp_connections = defaultdict(lambda: defaultdict(asyncio.Queue))
        self.writer_map: dict[str, asyncio.StreamWriter] = {}
        self.reader_map: dict[str, asyncio.StreamReader] = {}
        self.tcp_port_pool = deque(range(CONFIG['min_port'], CONFIG['max_port']))
        self.udp_port_pool = deque(range(CONFIG['min_port'], CONFIG['max_port']))
        self.pending_queues = defaultdict(asyncio.Queue)
        self.auth_clients = list()
        self.lock = asyncio.Lock()

    async def register_tunnel(self, client_id: str, tunnel_type: str, config: dict) -> dict:
        async with self.lock:
            # 生成并验证隧道URL唯一性
            url = self._generate_url(tunnel_type, config)
            if url in self.tunnels:
                raise ValueError(f"Tunnel {url} already registered")

            if tunnel_type == 'tcp':
                if (port := config.get('RemotePort', 0)) == 0:
                    if not self.tcp_port_pool:
                        raise ValueError("No available ports")
                    port = self.tcp_port_pool.popleft()
                elif self.tunnels.get(f"tcp://{CONFIG['domain']}:{port}"):
                    raise ValueError(f"Port {port} already in use")
                config['RemotePort'] = port

            if tunnel_type == 'udp':
                if (port := config.get('RemotePort', 0)) == 0:
                    if not self.udp_port_pool:
                        raise ValueError("No available ports")
                    port = self.udp_port_pool.popleft()
                elif self.tunnels.get(f"udp://{CONFIG['domain']}:{port}"):
                    raise ValueError(f"Port {port} already in use")
                config['RemotePort'] = port

            if config['HttpAuth']:
                config['HttpAuth'] = "Basic " + base64.b64encode(config['HttpAuth'].encode('utf-8')).decode('utf-8')

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
        elif tunnel_type == 'udp':
            return f"udp://{CONFIG['domain']}:{config['RemotePort']}"
        raise ValueError(f"Invalid tunnel type: {tunnel_type}")

    async def _cleanup_tcp_tunnel(self, port: int):
        if port in self.tcp_listeners:
            try:
                listener = self.tcp_listeners[port]
                if listener.is_serving():
                    listener.close()
                    await listener.wait_closed()
                logger.info(f"TCP监听已关闭 port:{port}")
            except Exception as e:
                logger.error(f"关闭TCP监听器时出错 port:{port}, error: {e}")
            self.tcp_listeners.pop(port, None)

    async def _cleanup_udp_tunnel(self, port: int):
        if port in self.udp_listeners:
            try:
                transport = self.udp_listeners[port]
                transport.close()
                logger.info(f"UDP监听已关闭 port:{port}")
            except Exception as e:
                logger.error(f"关闭UDP监听器时出错 port:{port}, error: {e}")
            self.udp_listeners.pop(port, None)
        # 清理UDP连接
        if port in self.udp_connections:
            for addr in list(self.udp_connections[port].keys()):
                queue = self.udp_connections[port][addr]
                if queue is not None:
                    try:
                        queue.put_nowait(None)
                    except asyncio.QueueFull:
                        await queue.put(None)
                self.udp_connections[port].pop(addr, None)
            # 移除空隧道条目
            if not self.udp_connections[port]:
                self.udp_connections.pop(port, None)

    async def cleanup_client(self, client_id: str):
        async with self.lock:
            # 清理隧道记录及监听
            for url in list(self.tunnels.keys()):
                if self.tunnels[url]['client_id'] == client_id:
                    if self.tunnels[url]['type'] == 'tcp':
                        port = self.tunnels[url]['config']['RemotePort']
                        self.tcp_port_pool.append(port)
                        await self._cleanup_tcp_tunnel(port)
                    if self.tunnels[url]['type'] == 'udp':
                        port = self.tunnels[url]['config']['RemotePort']
                        self.udp_port_pool.append(port)
                        await self._cleanup_udp_tunnel(port)
                    del self.tunnels[url]

            # 清理读写记录
            if client_id in self.writer_map:
                del self.writer_map[client_id]
            if client_id in self.reader_map:
                del self.reader_map[client_id]

            # 清理等待队列，并注入终止标记
            queue = self.pending_queues.get(client_id)
            if queue is not None:
                try:
                    queue.put_nowait(None)
                except asyncio.QueueFull:
                    await queue.put(None)

            # 清理认证客户端记录
            self.pending_queues.pop(client_id, None)

            # 清理客户端隧道记录
            if client_id in self.auth_clients:
                self.auth_clients.remove(client_id)
            self.client_tunnels.pop(client_id, None)

# === UDP隧道处理 ===
class UdpTunnelHandler:
    def __init__(self, tunnel_mgr: TunnelManager):
        self.tunnel_mgr = tunnel_mgr

    async def start_listener(self, port: int):
        async with self.tunnel_mgr.lock:
            if port in self.tunnel_mgr.udp_listeners:
                return

            class ServerProtocol(asyncio.DatagramProtocol):
                def __init__(self, handler: UdpTunnelHandler):
                    self.handler = handler

                def datagram_received(self, data: bytes, addr: tuple[str, int]):
                    asyncio.create_task(self.handler._handle_udp_connection(data, addr, port))

                def error_received(self, exc: OSError):
                    logger.error(f"UDP错误: {exc}")

            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: ServerProtocol(self),
                local_addr=('0.0.0.0', port)
            )
            self.tunnel_mgr.udp_listeners[port] = transport
            logger.info(f"UDP监听已启动 port:{port}")

    async def _handle_udp_connection(self, data: bytes, addr: tuple, port: int):
        try:
            # 如果已有连接，直接转发
            if addr in self.tunnel_mgr.udp_connections[port]:
                queue = self.tunnel_mgr.udp_connections[port][addr]
                await queue.put(data)
                return

            # 创建数据通道
            queue = asyncio.Queue()

            # 存入初始数据
            await queue.put(data)

            # 存储连接信息
            self.tunnel_mgr.udp_connections[port][addr] = queue

            lookup_url = f"udp://{CONFIG['domain']}:{port}"
            # 查找对应的客户端
            async with self.tunnel_mgr.lock:
                tunnel_info = self.tunnel_mgr.tunnels.get(lookup_url)
                if not tunnel_info:
                    return

                client_id = tunnel_info['client_id']

            # 生成客户端地址
            client_addr = f"{addr[0]}:{addr[1]}"

            # 记录待处理请求
            await self.tunnel_mgr.pending_queues[client_id].put({
                'queue': queue,
                'rport': port,
                'client_addr': client_addr,
                'tunnel_url': lookup_url,
                'time': time.time()
            })

        except Exception as e:
            logger.error(f"UDP处理连接失败: {str(e)}")

    async def _send_control_msg(self, writer: asyncio.StreamWriter, msg: dict):
        try:
            data = json.dumps(msg).encode()
            header = struct.pack('<II', len(data), 0)
            writer.write(header + data)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError) as e:
            logger.warning(f"UDP控制消息发送失败: {str(e)}")

# === TCP隧道处理 ===
class TcpTunnelHandler:
    def __init__(self, tunnel_mgr: TunnelManager):
        self.tunnel_mgr = tunnel_mgr

    async def start_listener(self, port: int):
        async with self.tunnel_mgr.lock:
            if port in self.tunnel_mgr.tcp_listeners:
                return

            async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                await self._handle_tcp_connection(reader, writer, port)

            server = await asyncio.start_server(
                handle_connection,
                host='0.0.0.0',
                port=port,
                reuse_address=True
            )
            self.tunnel_mgr.tcp_listeners[port] = server
            logger.info(f"TCP监听已启动 port:{port}")

    async def _handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
        try:
            lookup_url = f"tcp://{CONFIG['domain']}:{port}"
            # 查找对应的客户端
            async with self.tunnel_mgr.lock:
                tunnel_info = self.tunnel_mgr.tunnels.get(lookup_url)
                if not tunnel_info:
                    writer.close()
                    await writer.wait_closed()
                    return

                client_id = tunnel_info['client_id']

            # 生成客户端地址
            peer_info = writer.get_extra_info('peername')
            client_addr = f"{peer_info[0]}:{peer_info[1]}"

            # 记录待处理请求
            async with self.tunnel_mgr.lock:
                await self.tunnel_mgr.pending_queues[client_id].put({
                    'reader': reader,
                    'writer': writer,
                    'client_addr': client_addr,
                    'tunnel_url': lookup_url,
                    'time': time.time()
                })

        except Exception as e:
            logger.error(f"TCP处理连接失败: {str(e)}")
            writer.close()
            await writer.wait_closed()

    async def _send_control_msg(self, writer: asyncio.StreamWriter, msg: dict):
        try:
            data = json.dumps(msg).encode()
            header = struct.pack('<II', len(data), 0)
            writer.write(header + data)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError) as e:
            logger.warning(f"TCP控制消息发送失败: {str(e)}")
            writer.close()
            await writer.wait_closed()

# === HTTP/HTTPS处理 ===
class HttpTunnelHandler:
    def __init__(self, tunnel_mgr: TunnelManager):
        self.tunnel_mgr = tunnel_mgr
        self.ssl_ctx = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(CONFIG['ssl_cert'], CONFIG['ssl_key'])
        # ctx.set_alpn_protocols(['h2', 'http/1.1'])
        return ctx

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            # 判断是否为TLS
            is_ssl = writer.get_extra_info('sslcontext') is not None

            # 读取数据
            initial_data = await reader.read(4096)
            if not initial_data:
                return
            # 恢复数据
            reader.feed_data(initial_data)

            host = await self._parse_http_host(initial_data, "Host")
            if not host:
                await self._send_bad_request(writer)
                return

            auth = await self._parse_http_host(initial_data, "Authorization")

            protocol = 'https' if is_ssl else 'http'
            lookup_url = f"{protocol}://{host}"
            # 查找对应的客户端
            async with self.tunnel_mgr.lock:
                tunnel_info = self.tunnel_mgr.tunnels.get(lookup_url)
                if not tunnel_info:
                    await self._send_not_found(writer, host)
                    return
                httpauth = tunnel_info['config']['HttpAuth']
                if httpauth and auth != httpauth:
                    await self._send_not_authorized(writer)
                    return
                client_id = tunnel_info['client_id']

            # 生成客户端地址
            peer_info = writer.get_extra_info('peername')
            client_addr = f"{peer_info[0]}:{peer_info[1]}"

            # 记录待处理请求
            async with self.tunnel_mgr.lock:
                await self.tunnel_mgr.pending_queues[client_id].put({
                    'reader': reader,
                    'writer': writer,
                    'client_addr': client_addr,
                    'tunnel_url': lookup_url,
                    'time': time.time()
                })

        except Exception as e:
            logger.error(f"HTTP处理连接失败: {str(e)}")
            writer.close()
            await writer.wait_closed()

    async def _parse_http_host(self, data: bytes, header_name: str) -> str:
        try:
            # 按行分割数据
            headers = data.split(b'\r\n')

            # 跳过首行（请求行），从第二行开始解析头部
            for header in headers[1:]:
                if header.lower().startswith(header_name.lower().encode() + b':'):
                    # 提取并返回头部值
                    return header.split(b':', 1)[1].strip().decode(errors='ignore')
            return ''
        except Exception as e:
            logger.debug(f"解析头部字段 {header_name} 失败: {str(e)}")
            return ''

    async def _send_bad_request(self, writer: asyncio.StreamWriter):
        response = (
            b'HTTP/1.1 400 Bad Request\r\n'
            b'Content-Length: 12\r\n'
            b"Content-Type: text/html\r\n\r\n"
            b'Bad Request'
        )
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def _send_not_authorized(self, writer: asyncio.StreamWriter):
        response = (
            b'HTTP/1.1 401 Not Authorized\r\n'
            b'WWW-Authenticate: Basic realm="ngrok"\r\n'
            b'Content-Length: 23\r\n'
            b"Content-Type: text/html\r\n\r\n"
            b'Authorization required'
        )
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def _send_not_found(self, writer: asyncio.StreamWriter, host: str):
        html = f"Tunnel {host} not found"
        response = (
            "HTTP/1.1 404 Not Found\r\n"
            f"Content-Length: {len(html.encode())}\r\n"
            "Content-Type: text/html\r\n\r\n"
            f"{html}"
        )
        writer.write(response.encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def _send_control_msg(self, writer: asyncio.StreamWriter, msg: dict):
        try:
            data = json.dumps(msg).encode()
            header = struct.pack('<II', len(data), 0)
            writer.write(header + data)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError) as e:
            logger.warning(f"HTTP控制消息发送失败: {str(e)}")
            writer.close()
            await writer.wait_closed()

# === 主服务 ===
class TunnelServer:
    def __init__(self):
        self.tunnel_mgr = TunnelManager()
        self.tcp_handler = TcpTunnelHandler(self.tunnel_mgr)
        self.udp_handler = UdpTunnelHandler(self.tunnel_mgr)
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
            ssl=self.ssl_ctx,
            reuse_address=True
        ) as ctrl_srv, \
        await asyncio.start_server(
            self.http_handler.handle_connection,
            host=CONFIG['host'],
            port=CONFIG['http_port'],
            reuse_address=True
        ) as http_srv, \
        await asyncio.start_server(
            self.http_handler.handle_connection,
            host=CONFIG['host'],
            port=CONFIG['https_port'],
            ssl=self.http_handler.ssl_ctx,
            reuse_address=True
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
            # 认证处理
            header = await asyncio.wait_for(reader.read(8), timeout=CONFIG['timeout'])
            msg_len, _ = struct.unpack('<II', header)
            auth_msg = json.loads(await asyncio.wait_for(reader.read(msg_len), timeout=CONFIG['timeout']))

            logger.debug(f"收到消息: {auth_msg}")

            if auth_msg['Type'] == 'Auth':
                try:
                    user = auth_msg['Payload'].get('User', '')
                    if CONFIG['authtoken'] and user not in CONFIG['authtoken']:
                        raise ValueError(f"User token {user} not authorized")

                    resp = {
                        'Type': 'AuthResp',
                        'Payload': {
                            'Version': '2',
                            'MmVersion': '1.7',
                            'ClientId': client_id
                        }
                    }
                    logger.info(f"客户端认证成功: {client_id}")
                    async with self.tunnel_mgr.lock:
                        # 注册控制连接
                        self.tunnel_mgr.writer_map[client_id] = writer
                        self.tunnel_mgr.reader_map[client_id] = reader
                        self.tunnel_mgr.auth_clients.append(client_id)
                    await self._send_msg(writer, resp)
                    # 提前请求代理连接
                    await self._send_msg(writer, {'Type': 'ReqProxy', 'Payload': {}})
                except Exception as e:
                    resp = {
                        'Type': 'AuthResp',
                        'Payload': {
                            'Error': str(e)
                        }
                    }
                    logger.error(f"客户端认证失败: {str(e)}")
                    await self._send_msg(writer, resp)
                    return

            elif auth_msg['Type'] == 'RegProxy':
                proxy_id = auth_msg['Payload'].get('ClientId', '')
                if proxy_id not in self.tunnel_mgr.auth_clients:
                    raise ValueError(f"No client found for identifier: {proxy_id}")

                logger.info(f"代理端认证成功: {client_id}")
                async with self.tunnel_mgr.lock:
                    # 注册控制连接
                    self.tunnel_mgr.writer_map[client_id] = writer
                    self.tunnel_mgr.reader_map[client_id] = reader
                # 处理代理客户端
                req = await self.tunnel_mgr.pending_queues[proxy_id].get()
                if req is None:
                    return
                # 替换请求代理连接
                await self._send_msg(self.tunnel_mgr.writer_map[proxy_id], {'Type': 'ReqProxy', 'Payload': {}})
                # 发送StartProxy
                await self._send_msg(writer, {
                    'Type': 'StartProxy',
                    'Payload': {
                        'Url': req['tunnel_url'],
                        'ClientAddr': req['client_addr']
                    }
                })

                # 启动数据桥接
                queue = req.get('queue')
                if queue:
                    rport = int(req.get('rport'))
                    client_addr = req['client_addr'].split(':')
                    await self._bridge_data_udp(queue, client_addr, rport, reader, writer)
                    return
                await self._bridge_data_tcp(req['reader'], req['writer'], reader, writer)
                return

            elif auth_msg['Type'] != 'Auth':
                raise ValueError("First message must be Auth")

            # 消息处理循环
            while True:
                try:
                    header = await asyncio.wait_for(reader.read(8), timeout=CONFIG['timeout'])
                    if not header:
                        break
                    msg_len, _ = struct.unpack('<II', header)
                    msg = json.loads(await asyncio.wait_for(reader.read(msg_len), timeout=CONFIG['timeout']))
                    logger.debug(f"收到消息: {msg}")
                    await self._process_msg(client_id, msg, writer)
                except (ConnectionResetError, BrokenPipeError):
                    break

        except Exception as e:
            logger.error(f"控制连接错误: {str(e)}")
        finally:
            await self.tunnel_mgr.cleanup_client(client_id)
            writer.close()
            logger.info("控制连接关闭")

    async def _process_msg(self, client_id: str, msg: dict, writer: asyncio.StreamWriter):
        if msg['Type'] == 'ReqTunnel':
            try:
                tunnel = await self.tunnel_mgr.register_tunnel(
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
                logger.info(f"隧道已建立: {tunnel['url']}")
                if tunnel['type'] == 'tcp':
                    await self.tcp_handler.start_listener(tunnel['config']['RemotePort'])
                if tunnel['type'] == 'udp':
                    await self.udp_handler.start_listener(tunnel['config']['RemotePort'])
                await self._send_msg(writer, resp)

            except Exception as e:
                resp = {
                    'Type': 'NewTunnel',
                    'Payload': {
                        'Error': str(e),
                        'ReqId': msg['Payload'].get('ReqId', '')
                    }
                }
                logger.error(f"隧道创建失败: {str(e)}")
                await self._send_msg(writer, resp)

        elif msg['Type'] == 'Ping':
            await self._send_msg(writer, {'Type': 'Pong'})

    async def _send_msg(self, writer: asyncio.StreamWriter, msg: dict):
        try:
            data = json.dumps(msg).encode()
            header = struct.pack('<II', len(data), 0)
            writer.write(header + data)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass

    async def _bridge_data_udp(self, queue: asyncio.Queue, addr: tuple[str, str], rport: int, dst_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter):
        try:
            udp_transport = self.tunnel_mgr.udp_listeners.get(rport)
            if not udp_transport:
                return

            target_addr = (addr[0], int(addr[1]))

            loop = asyncio.get_running_loop()
            last_active = loop.time()

            async def tcp_to_udp(src: asyncio.StreamReader, label: str):
                nonlocal last_active
                try:
                    buffer = b''
                    while data := await src.read(CONFIG['bufsize']):
                        if not data:
                            logger.debug(f"{label} 连接正常关闭")
                            break
                        last_active = loop.time()
                        buffer += data
                        while len(buffer) >= 8:
                            pkt_len, _ = struct.unpack('<II', buffer[:8])
                            if len(buffer) < 8 + pkt_len:
                                break
                            udp_data = buffer[8:8+pkt_len]
                            if udp_transport and target_addr:
                                udp_transport.sendto(udp_data, target_addr)
                                logger.debug(f"{label} 转发 {len(udp_data)} bytes")
                            buffer = buffer[8+pkt_len:]
                except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                    pass

            async def udp_to_tcp(src: asyncio.Queue, label: str):
                nonlocal last_active
                try:
                    while data := await src.get():
                        if data is None:
                            logger.debug(f"{label} 收到终止信号")
                            break
                        last_active = loop.time()
                        header = struct.pack('<LL', len(data), 0)
                        dst_writer.write(header + data)
                        await dst_writer.drain()
                        logger.debug(f"{label} 转发 {len(data)} bytes")
                except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                    pass

            udp_task = asyncio.create_task(udp_to_tcp(queue, "服务端 UDP -> 客户端 TCP"))
            tcp_task = asyncio.create_task(tcp_to_udp(dst_reader, "客户端 TCP -> 服务端 UDP"))

            async def timeout_monitor():
                check_interval = max(0.1, CONFIG['timeout'] / 10)
                while True:
                    now = loop.time()
                    if now - last_active > CONFIG['timeout']:
                        udp_task.cancel()
                        tcp_task.cancel()
                        break
                    await asyncio.sleep(check_interval)

            done, pending = await asyncio.wait(
                {udp_task, tcp_task, asyncio.create_task(timeout_monitor())},
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        except Exception as e:
            logger.error(f"UDP桥接处理错误: {str(e)}")
        finally:
            if rport in self.tunnel_mgr.udp_connections:
                self.tunnel_mgr.udp_connections[rport].pop(addr, None)

    async def _bridge_data_tcp(self, src_reader: asyncio.StreamReader, src_writer: asyncio.StreamWriter, dst_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter):
        try:
            async def forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter, label: str):
                try:
                    while data := await src.read(CONFIG['bufsize']):
                        if not data:
                            logger.debug(f"{label} 连接正常关闭")
                            break
                        dst.write(data)
                        await dst.drain()
                        logger.debug(f"{label} 转发 {len(data)} bytes")
                except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                    pass
                finally:
                    try:
                        if not dst.is_closing():
                            dst.close()
                            await dst.wait_closed()
                    except Exception:
                        pass

            task1 = asyncio.create_task(forward(src_reader, dst_writer, "服务端 TCP -> 客户端 TCP"))
            task2 = asyncio.create_task(forward(dst_reader, src_writer, "客户端 TCP -> 服务端 TCP"))

            done, pending = await asyncio.wait({task1, task2}, return_when=asyncio.FIRST_COMPLETED)

            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        except Exception as e:
            logger.error(f"TCP桥接处理错误: {str(e)}")
        finally:
            try:
                if not src_writer.is_closing():
                    src_writer.close()
                    await src_writer.wait_closed()
            except Exception:
                pass

if __name__ == '__main__':
    server = TunnelServer()
    try:
        asyncio.run(server.start_servers())
    except KeyboardInterrupt:
        logger.info("服务已关闭")
