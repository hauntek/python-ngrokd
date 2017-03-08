from ngrokd import *
from msg import *

HOSTS = dict()
TCPS = dict()
Tunnels = dict()
reglist = dict()

tosocklist = dict()
proxylist = dict()
tcplist = dict()

# 服务端程序处理日记
def Server_list():
    client_num = 0
    tunnels_num = 0
    messages_num = 0
    for ClientId in Tunnels:
        client_num += 1
        if ClientId in reglist:
            messages_num += len(reglist[ClientId])
        if ClientId in Tunnels:
            tunnels_num += len(Tunnels[ClientId])
    log_str = 'client:%d, reg_tunnels:%d, stay_messages:%d, tosocklist:%d, proxylist:%d, tcplist:%d' % (client_num,
            tunnels_num, messages_num, len(tosocklist), len(proxylist), len(tcplist))
    logging.debug(log_str)

# 服务端程序处理过程
def HTServer(conn, rport):
    global reglist
    global tcplist
    while True:
        try:
            data = conn.recv(1024*8)
            if not data: break

            if conn in tcplist:
                sendbuf(tcplist[conn], data) # 数据转发给客户端
                continue # 长链接

            if rport in TCPS:
                tcp = TCPS[rport]
                sendpack(tcp['sock'], ReqProxy())
                if tcp['clientid'] in reglist:
                    regitem = reglist[tcp['clientid']]
                else:
                    regitem = list()
                reginfo = dict()
                reginfo['Protocol'] = 'tcp'
                reginfo['rport'] = rport
                reginfo['rsock'] = conn
                reginfo['buf'] = data
                regitem.append(reginfo)
                reglist[tcp['clientid']] = regitem

        except socket.error:
            break

    if conn in tcplist:
        tcplist[conn].close() # 关闭RegProxy链接
        del tcplist[conn]

    conn.close()

# 服务端程序处理过程
def HHServer(conn, addr, agre):
    global reglist
    global proxylist
    logger = logging.getLogger('%s:%d' % (agre, conn.fileno()))
    while True:
        try:
            data = conn.recv(1024*8)
            if not data: break

            if conn in proxylist:
                sendbuf(proxylist[conn], data) # 数据转发给客户端
                break # 短链接

            heads = httphead(data.decode('utf-8'))
            if 'Host' in heads:
                if heads['Host'] in HOSTS:
                    Host = HOSTS[heads['Host']]
                    sendpack(Host['sock'], ReqProxy())
                    if Host['clientid'] in reglist:
                        regitem = reglist[Host['clientid']]
                    else:
                        regitem = list()
                    reginfo = dict()
                    reginfo['Protocol'] = agre
                    reginfo['Host'] = heads['Host']
                    reginfo['rsock'] = conn
                    reginfo['buf'] = data
                    regitem.append(reginfo)
                    reglist[Host['clientid']] = regitem
                else:
                    html = 'Tunnel %s not found' % heads['Host']
                    header = "HTTP/1.0 404 Not Foun" + "\r\n"
                    header += "Content-Length: %d" + "\r\n"
                    header += "\r\n" + "%s"
                    buf = header % (len(html), html)
                    sendbuf(conn, buf.encode('utf-8'))

        except socket.error:
            break

    if conn in proxylist:
        proxylist[conn].close() # 关闭RegProxy链接
        del proxylist[conn]

    logger.debug('Closing')
    conn.close()

# 服务端程序处理过程
def HKServer(conn, addr, agre):
    global HOSTS
    global TCPS
    global Tunnels
    global reglist
    global tosocklist
    global proxylist
    global tcplist
    logger = logging.getLogger('%s:%d' % (agre, conn.fileno()))
    recvbuf = bytes()
    ClientId = ''
    pingtime = 0
    while True:
        try:
            if pingtime + 30 < time.time() and pingtime != 0: # 心跳超时
                logger.debug('Ping Timeout')
                break

            recvbut = conn.recv(1024*8)
            if not recvbut: break
            if len(recvbut) > 0:
                if not recvbuf:
                    recvbuf = recvbut
                else:
                    recvbuf += recvbut

            lenbyte = tolen(recvbuf[0:4])
            if len(recvbuf) >= (8 + lenbyte):
                buf = recvbuf[8:lenbyte + 8].decode('utf-8')
                logger.debug('message: %s' % buf)
                logger.debug('message with length: %d' % len(buf))
                js = json.loads(buf)
                if js['Type'] == 'Auth':
                    pingtime = time.time()
                    ClientId = md5(str(pingtime))
                    sendpack(conn, AuthResp(ClientId=ClientId))

                if js['Type'] == 'RegProxy':
                    ClientId = js['Payload']['ClientId']
                    if ClientId in reglist:
                        linkinfo = reglist[ClientId].pop() # 取出最后一个数据并删除
                        if linkinfo['Protocol'] == 'http' or linkinfo['Protocol'] == 'https':
                            tosock = linkinfo['rsock']
                            tosocklist[conn] = tosock
                            sockinfo = tosock.getpeername()
                            url = linkinfo['Protocol'] + '://' + linkinfo['Host']
                            clientaddr = sockinfo[0] + ':' + str(sockinfo[1])
                            sendpack(conn, StartProxy(url, clientaddr))
                            sendbuf(conn, linkinfo['buf']) # 请求头转发给客户端
                            proxylist[tosock] = conn # 许可HHServer直接转发客户端

                        if linkinfo['Protocol'] == 'tcp':
                            tosock = linkinfo['rsock']
                            tosocklist[conn] = tosock
                            sockinfo = tosock.getpeername()
                            url = linkinfo['Protocol'] + '://' + SERVERDOMAIN + ':' + str(linkinfo['rport'])
                            clientaddr = sockinfo[0] + ':' + str(sockinfo[1])
                            sendpack(conn, StartProxy(url, clientaddr))
                            sendbuf(conn, linkinfo['buf']) # 转发请求头给客户端
                            tcplist[tosock] = conn # 许可HTServer直接转发客户端

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
                            HOSTS[domain_name] = HOSTINFO
                            if ClientId in Tunnels:
                                Tunnels[ClientId] += [domain_name]
                            else:
                                Tunnels[ClientId] = [domain_name]

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
                            except socket.error:
                                Error = 'The tunnel %s is already registered.' % url
                                sendpack(conn, NewTunnel(Error=Error))
                                break

                            threading.Thread(target = tcp_service, args = (server, rport)).start() # 服务启用,TCP_SERVICE

                            TCPINFO = dict()
                            TCPINFO['sock'] = conn
                            TCPINFO['clientid'] = ClientId
                            TCPINFO['server'] = server
                            TCPS[rport] = TCPINFO
                            if ClientId in Tunnels:
                                Tunnels[ClientId] += [rport]
                            else:
                                Tunnels[ClientId] = [rport]

                            sendpack(conn, NewTunnel(js['Payload']['ReqId'], url, js['Payload']['Protocol']))

                if js['Type'] == 'Ping':
                    pingtime = time.time()
                    sendpack(conn, Pong())

                if len(recvbuf) == (8 + lenbyte):
                    recvbuf = bytes()
                else:
                    recvbuf = recvbuf[8 + lenbyte:]

            if conn in tosocklist:
                sendbuf(tosocklist[conn], recvbuf) # 数据转发给网页端
                recvbuf = bytes()

        except socket.error:
            break

    if conn in tosocklist:
        tosocklist[conn].close() # 关闭网页端链接
        del tosocklist[conn]

    if pingtime != 0:
        if ClientId in Tunnels:
            for Tunnel in Tunnels[ClientId]:
                if Tunnel in HOSTS:
                    del HOSTS[Tunnel]
                if Tunnel in TCPS:
                    TCPS[Tunnel]['server'].close()
                    del TCPS[Tunnel]
                logger.debug('Remove Tunnel :%s' % str(Tunnel))
            del Tunnels[ClientId]
            logger.debug('Remove ClientId :%s' % ClientId)

    logger.debug('Closing')
    conn.close()
