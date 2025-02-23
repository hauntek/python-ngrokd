#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 3.10.0 以上运行
# 项目地址: https://github.com/hauntek/python-ngrokd
# Version: 2.2.0 test
import asyncio
import ssl
import json
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
        self.listeners: dict[int, asyncio.Server] = {}
        self.writer_map: dict[str, asyncio.StreamWriter] = {}
        self.reader_map: dict[str, asyncio.StreamReader] = {}
        self.port_pool = deque(range(CONFIG['min_port'], CONFIG['max_port']))
        self.auth_clients = list()
        self.pending_queues = defaultdict(asyncio.Queue)
        self.lock = asyncio.Lock()

    async def register_tunnel(self, client_id: str, tunnel_type: str, config: dict) -> dict:
        async with self.lock:
            # 生成并验证隧道URL唯一性
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

    async def cleanup_client(self, client_id: str):
        async with self.lock:
            # 清理隧道记录
            for url in list(self.tunnels.keys()):
                if self.tunnels[url]['client_id'] == client_id:
                    if self.tunnels[url]['type'] == 'tcp':
                        port = self.tunnels[url]['config']['RemotePort']
                        self.port_pool.append(port)
                        if self.listeners[port].is_serving():
                            self.listeners[port].close()
                            await self.listeners[port].wait_closed()
                        del self.listeners[port]
                        logger.info(f"TCP监听已关闭 port:{port}")
                    del self.tunnels[url]

            # 清理读写记录
            if client_id in self.writer_map:
                del self.writer_map[client_id]
            if client_id in self.reader_map:
                del self.reader_map[client_id]

            # 清理等待队列
            self.pending_queues.pop(client_id, None)
            if client_id in self.auth_clients:
                self.auth_clients.remove(client_id)
            self.client_tunnels.pop(client_id, None)

# === TCP隧道处理 ===
class TcpTunnelHandler:
    def __init__(self, tunnel_mgr: TunnelManager):
        self.tunnel_mgr = tunnel_mgr

    async def start_listener(self, port: int):
        async with self.tunnel_mgr.lock:
            if port in self.tunnel_mgr.listeners:
                return

            async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                await self.handle_tcp_connection(reader, writer, port)

            server = await asyncio.start_server(
                handle_connection,
                host='0.0.0.0',
                port=port,
                reuse_address=True
            )
            self.tunnel_mgr.listeners[port] = server
            logger.info(f"TCP监听已启动 port:{port}")

    async def handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
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

            # 发送ReqProxy
            await self._send_control_msg(
                self.tunnel_mgr.writer_map[client_id],
                {'Type': 'ReqProxy', 'Payload': {}}
            )

            # 等待代理端连接
            queue = self.tunnel_mgr.pending_queues[client_id]
            try:
                proxy_client_id = await asyncio.wait_for(queue.get(), timeout=CONFIG['timeout'])
            except asyncio.TimeoutError:
                logger.warning("等待RegProxy超时")
                writer.close()
                await writer.wait_closed()
                return

            if not proxy_client_id:
                writer.close()
                await writer.wait_closed()
                return

            if proxy_client_id not in self.tunnel_mgr.writer_map or proxy_client_id not in self.tunnel_mgr.reader_map:
                writer.close()
                await writer.wait_closed()
                return

            proxy_writer = self.tunnel_mgr.writer_map[proxy_client_id]
            proxy_reader = self.tunnel_mgr.reader_map[proxy_client_id]

            # 发送StartProxy
            await self._send_control_msg(proxy_writer, {
                'Type': 'StartProxy',
                'Payload': {
                    'Url': lookup_url,
                    'ClientAddr': client_addr
                }
            })

            # 启动数据桥接
            await self._bridge_data(reader, writer, proxy_reader, proxy_writer)

            # 关闭RegProxy通道
            await self.tunnel_mgr.cleanup_client(proxy_client_id)
            proxy_writer.close()
            logger = logging.getLogger(f"Control:{proxy_client_id[:8]}")
            logger.info("控制连接关闭")

        except Exception as e:
            logger.error(f"TCP处理连接失败: {str(e)}")
            writer.close()
            await writer.wait_closed()

    async def _bridge_data(self, src_reader: asyncio.StreamReader, src_writer: asyncio.StreamWriter, dst_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter):
        try:
            async def forward(src, dst):
                try:
                    while data := await src.read(CONFIG['bufsize']):
                        dst.write(data)
                        await dst.drain()
                except (ConnectionResetError, BrokenPipeError):
                    pass
                finally:
                    try:
                        if not dst.is_closing():
                            dst.close()
                            await dst.wait_closed()
                    except Exception:
                        pass

            await asyncio.gather(
                forward(src_reader, dst_writer),
                forward(dst_reader, src_writer)
            )
        except Exception as e:
            logger.error(f"桥接处理错误: {str(e)}")
        finally:
            try:
                if not src_writer.is_closing():
                    src_writer.close()
                    await src_writer.wait_closed()
            except Exception:
                pass

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
        return ctx

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            host = ''

            is_ssl = False
            if is_ssl:
                host = await self._get_https_host(reader, writer)
            else:
                host = await self._parse_http_host(reader)

            if not host:
                await self._send_bad_request(writer)
                return

            protocol = 'https' if is_ssl else 'http'
            lookup_url = f"{protocol}://{host}"
            # 查找对应的客户端
            async with self.tunnel_mgr.lock:
                tunnel_info = self.tunnel_mgr.tunnels.get(lookup_url)
                if not tunnel_info:
                    await self._send_not_found(writer, host)
                    return
                client_id = tunnel_info['client_id']

            # 生成客户端地址
            peer_info = writer.get_extra_info('peername')
            client_addr = f"{peer_info[0]}:{peer_info[1]}"

            # 发送ReqProxy
            await self._send_control_msg(
                self.tunnel_mgr.writer_map[client_id],
                {'Type': 'ReqProxy', 'Payload': {}}
            )

            # 等待代理端连接
            queue = self.tunnel_mgr.pending_queues[client_id]
            try:
                proxy_client_id = await asyncio.wait_for(queue.get(), timeout=CONFIG['timeout'])
            except asyncio.TimeoutError:
                logger.warning("等待RegProxy超时")
                writer.close()
                await writer.wait_closed()
                return

            if not proxy_client_id:
                writer.close()
                await writer.wait_closed()
                return

            if proxy_client_id not in self.tunnel_mgr.writer_map or proxy_client_id not in self.tunnel_mgr.reader_map:
                writer.close()
                await writer.wait_closed()
                return

            proxy_writer = self.tunnel_mgr.writer_map[proxy_client_id]
            proxy_reader = self.tunnel_mgr.reader_map[proxy_client_id]

            # 发送StartProxy
            await self._send_control_msg(proxy_writer, {
                'Type': 'StartProxy',
                'Payload': {
                    'Url': lookup_url,
                    'ClientAddr': client_addr
                }
            })

            # 启动数据桥接
            await self._bridge_data(reader, writer, proxy_reader, proxy_writer)

            # 关闭RegProxy通道
            await self.tunnel_mgr.cleanup_client(proxy_client_id)
            proxy_writer.close()
            logger = logging.getLogger(f"Control:{proxy_client_id[:8]}")
            logger.info("控制连接关闭")

        except Exception as e:
            logger.error(f"HTTP处理连接失败: {str(e)}")
            writer.close()
            await writer.wait_closed()

    async def _bridge_data(self, src_reader: asyncio.StreamReader, src_writer: asyncio.StreamWriter, dst_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter):
        try:
            async def forward(src, dst):
                try:
                    while data := await src.read(CONFIG['bufsize']):
                        dst.write(data)
                        await dst.drain()
                except (ConnectionResetError, BrokenPipeError):
                    pass
                finally:
                    try:
                        if not dst.is_closing():
                            dst.close()
                            await dst.wait_closed()
                    except Exception:
                        pass

            await asyncio.gather(
                forward(src_reader, dst_writer),
                forward(dst_reader, src_writer)
            )
        except Exception as e:
            logger.error(f"桥接处理错误: {str(e)}")
        finally:
            try:
                if not src_writer.is_closing():
                    src_writer.close()
                    await src_writer.wait_closed()
            except Exception:
                pass

    async def _get_https_host(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
        try:
            transport = writer.transport
            protocol = asyncio.StreamReaderProtocol(reader)

            new_transport = await asyncio.get_running_loop().start_tls(
                transport=transport,
                protocol=protocol,
                sslcontext=self.ssl_ctx,
                server_side=True
            )

            ssl_socket: ssl.SSLSocket = new_transport.get_extra_info('ssl_object')

            sni = ssl_socket.server_side and ssl_socket.context.get_servername()
            return sni.decode() if sni else ''

        except Exception as e:
            logger.error(f"获取SNI失败: {str(e)}")
            return ''

    async def _detect_ssl(self, reader: asyncio.StreamReader) -> bool:
        peek_data = await reader.read(4096)
        reader.feed_data(peek_data)
        return peek_data.startswith(b'\x16\x03')

    async def _parse_http_host(self, reader: asyncio.StreamReader) -> str:
        try:
            # 读取并恢复数据
            data = await reader.read(4096)
            reader.feed_data(data)

            # 解析首行和Host头
            headers = data.split(b'\r\n')
            for header in headers[1:]:
                if header.lower().startswith(b'host:'):
                    return header[5:].strip().decode(errors='ignore')
            return ''
        except Exception as e:
            logger.debug(f"解析Host失败: {str(e)}")
            return ''

    async def _send_bad_request(self, writer: asyncio.StreamWriter):
        writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def _send_not_found(self, writer: asyncio.StreamWriter, host: str):
        html = f'Tunnel {host} not found'
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

            elif auth_msg['Type'] == 'RegProxy':
                proxy_id = auth_msg['Payload'].get('ClientId', '')
                async with self.tunnel_mgr.lock:
                    if proxy_id not in self.tunnel_mgr.auth_clients:
                        raise ValueError("First message must be Auth")

                logger.info(f"桥接端认证成功: {client_id}")

                # 记录代理客户端
                async with self.tunnel_mgr.lock:
                    # 注册控制连接
                    self.tunnel_mgr.writer_map[client_id] = writer
                    self.tunnel_mgr.reader_map[client_id] = reader
                    await self.tunnel_mgr.pending_queues[proxy_id].put(client_id)
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
            if client_id not in self.tunnel_mgr.auth_clients:
                return
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

if __name__ == '__main__':
    server = TunnelServer()
    try:
        asyncio.run(server.start_servers())
    except KeyboardInterrupt:
        logger.info("服务已关闭")
