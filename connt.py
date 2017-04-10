from ngrokd import *
from msg import *

# 判断解释器版本
if not sys.version_info >= (3, 0):
    from Queue import Queue
else:
    from queue import Queue

HOSTS = dict()
TCPS = dict()
Tunnels = dict()

reglist = dict()

# 服务端程序处理过程
def HTServer(conn, addr, agre):
    global TCPS
    global reglist
    tosock = None
    while True:
        try:
            if tosock is None:
                rport = conn.getsockname()[1]
                url = agre + '://' + SERVERDOMAIN + ':' + str(rport)
                if url in TCPS:
                    info = TCPS[url]

                    reginfo = dict()
                    reginfo['url'] = url
                    reginfo['sock'] = info['sock']
                    reginfo['rsock'] = conn
                    reginfo['queue'] = Queue()

                    reglist[info['clientid']].put(reginfo)

                    tosock = reginfo['queue'].get() # 等待队列完成

            data = conn.recv(bufsize)
            if not data: break

            if tosock is not None:
                sendbuf(tosock, data) # 数据转发给客户端
                continue # 长链接

        except Exception:
            break

    if tosock is not None:
        tosock.close() # 关闭RegProxy链接

    conn.close()

# 服务端程序处理过程
def HHServer(conn, addr, agre):
    global HOSTS
    global reglist
    tosock = None
    logger = logging.getLogger('%s:%d' % (agre, conn.fileno()))
    while True:
        try:
            data = conn.recv(bufsize)
            if not data: break

            if tosock is None:
                heads = httphead(data.decode('utf-8'))
                if 'Host' in heads:
                    url = agre + '://' + heads['Host']
                    if url in HOSTS:
                        info = HOSTS[url]

                        reginfo = dict()
                        reginfo['url'] = url
                        reginfo['sock'] = info['sock']
                        reginfo['rsock'] = conn
                        reginfo['queue'] = Queue()

                        reglist[info['clientid']].put(reginfo)

                        tosock = reginfo['queue'].get() # 等待队列完成
                    else:
                        html = 'Tunnel %s not found' % heads['Host']
                        header = "HTTP/1.0 404 Not Foun" + "\r\n"
                        header += "Content-Length: %d" + "\r\n"
                        header += "\r\n" + "%s"
                        buf = header % (len(html.encode('utf-8')), html)
                        sendbuf(conn, buf.encode('utf-8'))

            if tosock is not None:
                sendbuf(tosock, data) # 数据转发给客户端
                continue # 长链接
                # break # 短链接

        except Exception:
            break

    if tosock is not None:
        tosock.close() # 关闭RegProxy链接

    logger.debug('Closing')
    conn.close()

# 服务端程序处理过程
def HKServer(conn, addr, agre):
    global HOSTS
    global TCPS
    global Tunnels
    global reglist
    recvbuf = bytes()
    ClientId = ''
    pingtime = 0
    tosock = None
    logger = logging.getLogger('%s:%d' % (agre, conn.fileno()))
    while True:
        try:
            recvbut = conn.recv(bufsize)
            if not recvbut: break

            if len(recvbut) > 0:
                if not recvbuf:
                    recvbuf = recvbut
                else:
                    recvbuf += recvbut

            lenbyte = tolen(recvbuf[0:8])
            if len(recvbuf) >= (8 + lenbyte):
                buf = recvbuf[8:lenbyte + 8].decode('utf-8')
                logger.debug('message: %s' % buf)
                logger.debug('message with length: %d' % len(buf))
                js = json.loads(buf)
                if js['Type'] == 'Auth':
                    pingtime = time.time()
                    ClientId = md5(str(pingtime))
                    reglist[ClientId] = Queue() # 创建消息队列
                    sendpack(conn, AuthResp(ClientId=ClientId))
                    sendpack(conn, ReqProxy())

                if js['Type'] == 'RegProxy':
                    TEMP_ClientId = js['Payload']['ClientId']
                    if not (TEMP_ClientId in reglist): break
                    linkinfo = reglist[TEMP_ClientId].get()

                    if linkinfo == 'delete': # 等待消息队列退出
                        del reglist[TEMP_ClientId]
                        break

                    tosock = linkinfo['rsock']

                    url = linkinfo['url']
                    sockinfo = tosock.getpeername()
                    clientaddr = sockinfo[0] + ':' + str(sockinfo[1])
                    sendpack(conn, StartProxy(url, clientaddr))

                    linkinfo['queue'].put(conn) # 许可队列直接转发客户端

                    sendpack(linkinfo['sock'], ReqProxy())

                if js['Type'] == 'ReqTunnel':
                    if js['Payload']['Protocol'] == 'http' or js['Payload']['Protocol'] == 'https':
                        if 'Hostname' in js['Payload'] and len(js['Payload']['Hostname']) > 0:
                            domain_name = js['Payload']['Hostname']
                        else:
                            if len(js['Payload']['Subdomain']) == 0:
                                js['Payload']['Subdomain'] = getRandChar(5)
                            domain_name = js['Payload']['Subdomain'] + '.' + SERVERDOMAIN

                        if js['Payload']['Protocol'] == 'http' and SERVERHTTP != 80:
                            url = js['Payload']['Protocol'] + '://' + domain_name + ':' + str(SERVERHTTP)
                        elif js['Payload']['Protocol'] == 'https' and SERVERHTTPS != 443:
                            url = js['Payload']['Protocol'] + '://' + domain_name + ':' + str(SERVERHTTPS)
                        else:
                            url = js['Payload']['Protocol'] + '://' + domain_name

                        if domain_name in HOSTS:
                            Error = 'The tunnel %s is already registered.' % url
                            sendpack(conn, NewTunnel(Error=Error))
                            break
                        else:
                            HOSTINFO = dict()
                            HOSTINFO['sock'] = conn
                            HOSTINFO['clientid'] = ClientId
                            HOSTS[url] = HOSTINFO
                            if ClientId in Tunnels:
                                Tunnels[ClientId] += [url]
                            else:
                                Tunnels[ClientId] = [url]

                            sendpack(conn, NewTunnel(js['Payload']['ReqId'], url, js['Payload']['Protocol']))

                    if js['Payload']['Protocol'] == 'tcp':
                        rport = js['Payload']['RemotePort']
                        url = js['Payload']['Protocol'] + '://' + SERVERDOMAIN + ':' + str(rport)
                        if rport in TCPS:
                            Error = 'The tunnel %s is already registered.' % url
                            sendpack(conn, NewTunnel(Error=Error))
                            break
                        else:
                            try:
                                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                server.bind((SERVERHOST, rport))
                                server.listen(5)
                                server.setblocking(1)
                            except Exception:
                                Error = 'The tunnel %s is already registered.' % url
                                sendpack(conn, NewTunnel(Error=Error))
                                break

                            threading.Thread(daemon=True, target = tcp_service, args = (server, rport)).start() # 服务启用,TCP_SERVICE

                            TCPINFO = dict()
                            TCPINFO['sock'] = conn
                            TCPINFO['clientid'] = ClientId
                            TCPINFO['tcp_server'] = server
                            TCPS[rport] = url
                            if ClientId in Tunnels:
                                Tunnels[ClientId] += [url]
                            else:
                                Tunnels[ClientId] = [url]

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

    if ClientId in reglist:
        reglist[ClientId].put('delete')

    if ClientId in Tunnels:
        for Tunnel in Tunnels[ClientId]:
            if Tunnel in HOSTS:
                del HOSTS[Tunnel]
            if Tunnel in TCPS:
                TCPS[Tunnel]['tcp_server'].close()
                del TCPS[Tunnel]
            logger.debug('Remove Tunnel :%s' % str(Tunnel))
        del Tunnels[ClientId]
        logger.debug('Remove ClientId :%s' % ClientId)

    logger.debug('Closing')
    conn.close()
