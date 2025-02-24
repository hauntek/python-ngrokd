#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 2.7.9 或 Python 3.4.2 以上运行
# 项目地址: https://github.com/hauntek/python-ngrokd
# Version: v1.46
import socket
import ssl
import sys
import json
import time
import struct
import logging
import threading

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s', datefmt='%Y/%m/%d %H:%M:%S')

# 判断解释器版本
if not sys.version_info >= (3, 0):
    from Queue import Queue
else:
    from queue import Queue

def AuthResp(ClientId = '', Version = '2', MmVersion = '1.7', Error = ''):
    Payload = dict()
    Payload['ClientId'] = ClientId
    Payload['Version'] = Version
    Payload['MmVersion'] = MmVersion
    Payload['Error'] = Error
    body = dict()
    body['Type'] = 'AuthResp'
    body['Payload'] = Payload
    buffer = json.dumps(body)
    return(buffer)

def NewTunnel(ReqId = '', Url = '', Protocol = '', Error = ''):
    Payload = dict()
    Payload['ReqId'] = ReqId
    Payload['Url'] = Url
    Payload['Protocol'] = Protocol
    Payload['Error'] = Error
    body = dict()
    body['Type'] = 'NewTunnel'
    body['Payload'] = Payload
    buffer = json.dumps(body)
    return(buffer)

def ReqProxy():
    Payload = dict()
    body = dict()
    body['Type'] = 'ReqProxy'
    body['Payload'] = Payload
    buffer = json.dumps(body)
    return(buffer)

def StartProxy(Url, ClientAddr):
    Payload = dict()
    Payload['Url'] = Url
    Payload['ClientAddr'] = ClientAddr
    body = dict()
    body['Type'] = 'StartProxy'
    body['Payload'] = Payload
    buffer = json.dumps(body)
    return(buffer)

def Pong():
    Payload = dict()
    body = dict()
    body['Type'] = 'Pong'
    body['Payload'] = Payload
    buffer = json.dumps(body)
    return(buffer)

def lentobyte(len):
    return struct.pack('<LL', len, 0)

def sendbuf(sock, buf, isblock = False):
    if isblock:
        sock.setblocking(1)

    buffer = buf
    butlen = 0
    while True:
        sendlen = sock.send(buffer[butlen:butlen + 1024])
        butlen += sendlen
        if butlen == len(buffer):
            break

    if isblock:
        sock.setblocking(0)

def sendpack(sock, msg, isblock = False):
    if isblock:
        sock.setblocking(1)
    sock.sendall(lentobyte(len(msg)))
    sock.sendall(msg.encode('utf-8'))
    if isblock:
        sock.setblocking(0)

def tolen(v):
    if len(v) == 8:
        return struct.unpack('<II', v)[0]
    return 0

def getRandChar(length):
    import random
    _chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
    return ''.join(random.sample(_chars, length))

def md5(s):
    import hashlib
    return hashlib.md5(s.encode('utf-8')).hexdigest().lower()

def httphead(request):
    header, data = request.split('\r\n\r\n', 1)
    headers = dict()
    for line in header.split('\r\n')[1:]:
        key, val = line.split(': ', 1)
        headers[key] = val

    return headers

class NgrokServiceFX:
    def __init__(self):
        self.DOMAIN = 'ngrok.com' # 服务域名
        self.HOST = ''
        self.HTTP = 80
        self.HTTPS = 443
        self.PORT = 4443

        self.pemfile = 'snakeoil.crt' # 服务证书公钥
        self.keyfile = 'snakeoil.key' # 服务证书密钥

        self.bufsize = 1024 # 吞吐量

        self.CommonFX = NgrokCommonFX(self)

    def Http(self):
        ListenFX = NgrokListenFX(self.HOST, self.HTTP)
        ListenFX.run(self.CommonFX.HHServer, 'http')
    def Https(self):
        ListenFX = NgrokListenFX(self.HOST, self.HTTPS)
        ListenFX.set_cert(self.pemfile, self.keyfile)
        ListenFX.run(self.CommonFX.HHServer, 'https')
    def Service(self):
        ListenFX = NgrokListenFX(self.HOST, self.PORT)
        ListenFX.set_cert(self.pemfile, self.keyfile)
        ListenFX.run(self.CommonFX.HKServer, 'service')
    def run(self):
        while True:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                sys.exit()

class NgrokListenFX:
    def __init__(self, host, port):
        self.host = host
        self.port = port

        self.ssl = False

    def set_cert(self, certfile, keyfile):
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.ssl = True

    def run(self, obj, agre):
        self.obj = obj
        self.agre = agre

        self.listen()

        self.thread = threading.Thread(target=self.accept)
        self.thread.setDaemon(True)
        self.thread.start()

    def listen(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)

    def accept(self):
        logging.debug('[%s:%d] listen port success' % (self.host, self.port))
        try:
            while True:
                conn, addr = self.server.accept()
                try:
                    if self.ssl:
                        conn = self.context.wrap_socket(conn, server_side=True)
                    threading.Thread(target=self.obj, args=(conn, addr, self.agre)).start()

                except Exception:
                    pass

        except Exception:
            pass

        logging.debug('[%s:%d] listen port close' % (self.host, self.port))

class NgrokCommonFX:
    def __init__(self, cfg):
        self.cfg = cfg

        self.HOSTS = dict()
        self.TCPS = dict()
        self.Tunnels = dict()

        self.reglist = dict()

    # 服务端程序处理过程
    def HTServer(self, conn, addr, agre):
        logger = logging.getLogger('%s:%d' % (agre, conn.fileno()))
        logger.debug('New Client to: %s:%d' % (addr[0], addr[1]))
        tosock = None
        while True:
            try:
                if tosock is None:
                    rport = conn.getsockname()[1]
                    url = agre + '://' + self.cfg.DOMAIN + ':' + str(rport)
                    if url in self.TCPS:
                        info = self.TCPS[url]

                        reginfo = dict()
                        reginfo['url'] = url
                        reginfo['rsock'] = conn
                        reginfo['queue'] = Queue()

                        self.reglist[info['clientid']].put(reginfo)

                        tosock = reginfo['queue'].get() # 等待队列完成

                        sendpack(info['sock'], ReqProxy())
                    else:
                        pass

                recvbut = conn.recv(self.cfg.bufsize)
                if not recvbut: break

                if tosock is not None:
                    sendbuf(tosock, recvbut) # 数据转发给客户端
                    continue # 长链接

            except Exception:
                break

        if tosock is not None:
            tosock.close() # 关闭RegProxy链接

        logger.debug('Closing')
        conn.close()

    # 服务端程序处理过程
    def HHServer(self, conn, addr, agre):
        tosock = None
        logger = logging.getLogger('%s:%d' % (agre, conn.fileno()))
        logger.debug('New Client to: %s:%d' % (addr[0], addr[1]))
        while True:
            try:
                recvbut = conn.recv(self.cfg.bufsize)
                if not recvbut: break

                if tosock is None:
                    heads = httphead(recvbut.decode('utf-8'))
                    if 'Host' in heads:
                        url = agre + '://' + heads['Host']
                        if url in self.HOSTS:
                            info = self.HOSTS[url]

                            reginfo = dict()
                            reginfo['url'] = url
                            reginfo['rsock'] = conn
                            reginfo['queue'] = Queue()

                            self.reglist[info['clientid']].put(reginfo)

                            tosock = reginfo['queue'].get() # 等待队列完成

                            sendpack(info['sock'], ReqProxy())
                        else:
                            html = 'Tunnel %s not found' % heads['Host']
                            header = "HTTP/1.0 404 Not Foun" + "\r\n"
                            header += "Content-Length: %d" + "\r\n"
                            header += "\r\n" + "%s"
                            buf = header % (len(html.encode('utf-8')), html)
                            sendbuf(conn, buf.encode('utf-8'))

                if tosock is not None:
                    sendbuf(tosock, recvbut) # 数据转发给客户端
                    continue # 长链接

            except Exception:
                break

        if tosock is not None:
            tosock.close() # 关闭RegProxy链接

        logger.debug('Closing')
        conn.close()

    # 服务端程序处理过程
    def HKServer(self, conn, addr, agre):
        recvbuf = bytes()
        ClientId = ''
        pingtime = 0
        tosock = None
        logger = logging.getLogger('%s:%d' % (agre, conn.fileno()))
        logger.debug('New Client to: %s:%d' % (addr[0], addr[1]))
        while True:
            try:
                recvbut = conn.recv(self.cfg.bufsize)
                if not recvbut: break

                if len(recvbut) > 0:
                    if not recvbuf:
                        recvbuf = recvbut
                    else:
                        recvbuf += recvbut

                lenbyte = tolen(recvbuf[0:8])
                if len(recvbuf) >= (8 + lenbyte):
                    buf = recvbuf[8:lenbyte + 8].decode('utf-8')
                    logger.debug('message with length: %d' % len(buf))
                    logger.debug('message: %s' % buf)
                    js = json.loads(buf)
                    if js['Type'] == 'Auth':
                        pingtime = time.time()
                        ClientId = md5(str(pingtime))
                        self.Tunnels[ClientId] = [] # 创建渠道队列
                        self.reglist[ClientId] = Queue() # 创建消息队列
                        sendpack(conn, AuthResp(ClientId=ClientId))
                        sendpack(conn, ReqProxy())

                    if js['Type'] == 'RegProxy':
                        TEMP_ClientId = js['Payload']['ClientId']
                        if not (TEMP_ClientId in self.reglist): break
                        linkinfo = self.reglist[TEMP_ClientId].get()
                        if linkinfo == 'Closing': # 等待消息队列退出
                            del self.reglist[TEMP_ClientId]
                            break

                        tosock = linkinfo['rsock']

                        url = linkinfo['url']
                        sockinfo = tosock.getpeername()
                        clientaddr = sockinfo[0] + ':' + str(sockinfo[1])
                        sendpack(conn, StartProxy(url, clientaddr))

                        linkinfo['queue'].put(conn) # 许可队列直接转发客户端

                    if js['Type'] == 'ReqTunnel':
                        if js['Payload']['Protocol'] == 'http' or js['Payload']['Protocol'] == 'https':
                            if 'Hostname' in js['Payload'] and len(js['Payload']['Hostname']) > 0:
                                domain_name = js['Payload']['Hostname']
                            else:
                                if len(js['Payload']['Subdomain']) == 0:
                                    js['Payload']['Subdomain'] = getRandChar(5)
                                domain_name = js['Payload']['Subdomain'] + '.' + self.cfg.DOMAIN

                            if js['Payload']['Protocol'] == 'http' and self.cfg.HTTP != 80:
                                url = js['Payload']['Protocol'] + '://' + domain_name + ':' + str(self.cfg.HTTP)
                            elif js['Payload']['Protocol'] == 'https' and self.cfg.HTTPS != 443:
                                url = js['Payload']['Protocol'] + '://' + domain_name + ':' + str(self.cfg.HTTPS)
                            else:
                                url = js['Payload']['Protocol'] + '://' + domain_name

                            if url in self.HOSTS:
                                Error = 'The tunnel %s is already registered.' % url
                                sendpack(conn, NewTunnel(Error=Error))
                                conn.shutdown(socket.SHUT_WR)
                                break
                            else:
                                HOSTINFO = dict()
                                HOSTINFO['sock'] = conn
                                HOSTINFO['clientid'] = ClientId
                                self.HOSTS[url] = HOSTINFO
                                self.Tunnels[ClientId].append(url)

                                sendpack(conn, NewTunnel(js['Payload']['ReqId'], url, js['Payload']['Protocol']))

                        if js['Payload']['Protocol'] == 'tcp':
                            rport = js['Payload']['RemotePort']
                            url = js['Payload']['Protocol'] + '://' + self.cfg.DOMAIN + ':' + str(rport)
                            if url in self.TCPS:
                                Error = 'The tunnel %s is already registered.' % url
                                sendpack(conn, NewTunnel(Error=Error))
                                conn.shutdown(socket.SHUT_WR)
                                break
                            else:
                                try:
                                    ListenFX = NgrokListenFX(self.cfg.HOST, rport)
                                    ListenFX.run(self.HTServer, 'tcp')
                                except Exception:
                                    Error = 'The tunnel %s is already registered.' % url
                                    sendpack(conn, NewTunnel(Error=Error))
                                    conn.shutdown(socket.SHUT_WR)
                                    break

                                TCPINFO = dict()
                                TCPINFO['sock'] = conn
                                TCPINFO['clientid'] = ClientId
                                TCPINFO['port'] = rport
                                TCPINFO['listen_port'] = ListenFX.server
                                self.TCPS[url] = TCPINFO
                                self.Tunnels[ClientId].append(url)

                                sendpack(conn, NewTunnel(js['Payload']['ReqId'], url, js['Payload']['Protocol']))

                    if js['Type'] == 'Ping':
                        pingtime = time.time()
                        sendpack(conn, Pong())

                    if len(recvbuf) == (8 + lenbyte):
                        recvbuf = bytes()
                    else:
                        recvbuf = recvbuf[8 + lenbyte:]

                if tosock is not None:
                    sendbuf(tosock, recvbuf) # 数据转发给网页端
                    recvbuf = bytes()

            except Exception:
                break

        if tosock is not None:
            tosock.close() # 关闭访问端链接

        if ClientId in self.reglist:
            self.reglist[ClientId].put('Closing')

        if ClientId in self.Tunnels:
            for Tunnel in self.Tunnels[ClientId]:
                if Tunnel in self.HOSTS:
                    del self.HOSTS[Tunnel]
                if Tunnel in self.TCPS:
                    rport = self.TCPS[Tunnel]['port']
                    try:
                        try:
                            self.TCPS[Tunnel]['listen_port'].shutdown(socket.SHUT_RDWR)
                        except Exception:
                            pass

                        try:
                            self.TCPS[Tunnel]['listen_port'].close()
                        except Exception:
                            pass

                        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        client.connect(('', rport))
                    except Exception:
                        pass

                    del self.TCPS[Tunnel]
                logger.debug('Remove Tunnel :%s' % str(Tunnel))
            del self.Tunnels[ClientId]
            logger.debug('Remove ClientId :%s' % ClientId)

        logger.debug('Closing')
        conn.close()

# 服务端程序初始化
if __name__ == '__main__':
    ngrokd = NgrokServiceFX()
    ngrokd.Http()
    ngrokd.Https()
    ngrokd.Service()

    ngrokd.run()
