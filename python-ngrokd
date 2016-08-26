import socket
import ssl
import json
import struct
import uuid
import time
import threading

SERVERDOMAIN = 'tunnel.crysadmapp.cn'
SERVERHOST = '0.0.0.0'
SERVERHTTP = 80
SERVERHTTPS = 443
SERVERPORT = 4443

token = 'N53NhAfc-IHUT-ljmW-qS7Z-4je88zBTY3VZ'

pemfile = 'snakeoil.crt'
keyfile = 'snakeoil.key'

HOSTS = dict() # 链接全局储存
TCPS = dict() # 链接全局储存
reglist = dict() # 链接全局储存

tosocklist = dict()
proxylist = dict()
tcplist = dict()

def AuthResp(ClientId = '', Error = ''):
    Payload = dict()
    Payload['ClientId'] = ClientId
    Payload['Version'] = '2'
    Payload['MmVersion'] = '1.7'
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
    xx = struct.pack('I', len)
    xx1 = struct.pack('I', 0)
    return xx + xx1

def sendbuf(sock, buf, isblock = True):
    if isblock:
        sock.setblocking(0)
    sock.send(buf)
    if isblock:
        sock.setblocking(1)

def sendpack(sock, msg, isblock = True):
    if isblock:
        sock.setblocking(0)
    sock.send(lentobyte(len(msg)) + msg.encode('utf-8'))
    if isblock:
        sock.setblocking(1)

def tolen(v):
    return struct.unpack('I', v)[0]

def getRandChar(length):
    _chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
    return ''.join(random.sample(_chars, length))

def md5(s):
    import hashlib
    return hashlib.md5(s.encode('utf-8')).hexdigest().lower()

# 输出日记到命令行
def ConsoleOut(text):
    import sys
    from datetime import datetime
    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    tmp_str = '[%s] %s' % (date, str(text) + "\n")
    sys.stdout.write(tmp_str)
    sys.stdout.flush()

def httphead(request):
    http = request.split("\n")
    REQUEST_METHOD = http[0][0:http[0].find(' ')]
    back = dict()
    for line in http:
        pos = line.find(':')
        if pos != -1:
            key = line[0:pos]
            value = line[int(pos) + 1:]
            back[key] = value.strip()
            back['REQUEST_METHOD'] = REQUEST_METHOD
    if 'Host' in back:
        if back['Host'].find(':') != -1:
            back['Host'] = back['Host'][:back['Host'].find(':')]
    return back

def show404(sock, host):
    body = 'Tunnel %s not found'
    html = body % host
    header = "HTTP/1.0 404 Not Foun" + "\r\n"
    header += "Content-Length: %d" + "\r\n"
    header += "\r\n" + "%s"
    buf = header % (len(html), html)
    sendbuf(sock, buf.encode('utf-8'))

# 服务端程序处理过程[HTTP,HTTPS]协议
def HHServer(conn, addr, agre):
    global reglist
    while True:
        try:
            data = conn.recv(1024)
            if not data: break
            if conn in proxylist:
                sendbuf(proxylist[conn], data) # 转发
                proxylist.pop(conn)
                break
            heads = httphead(data.decode('utf-8')) # 请求头
            # print(heads)
            if heads['Host'] in HOSTS:
                Host = HOSTS[heads['Host']]
                sendpack(Host['sock'], ReqProxy()) # 发送给客户端建立新渠道
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
                show404(conn, heads['Host'])

        except socket.error:
            break

    ConsoleOut('[%s] [file:%s] Closing' % (agre, conn.fileno()))
    conn.close()

# 服务端程序处理过程[TCP]协议
def HTServer(conn, addr):
    global reglist
    while True:
        try:
            data = conn.recv(1024)
            if conn in tcplist:
                sendbuf(tcplist[conn], data) # 转发
                continue
            if not data:
                tcplist.pop(conn)
                break
            sockinfo = conn.getsockname()
            if sockinfo[1] in TCPS:
                tcp = TCPS[sockinfo[1]]
                sendpack(tcp['sock'], ReqProxy()) # 发送给客户端新建立渠道
                if tcp['clientid'] in reglist:
                    regitem = reglist[clientid]
                else:
                    regitem = list()
                reginfo = dict()
                reginfo['Protocol'] = 'tcp'
                reginfo['rport'] = sockinfo[1]
                reginfo['rsock'] = conn
                reginfo['buf'] = data
                regitem.append(reginfo)
                reglist[Host['clientid']] = regitem

        except socket.error:
            break

    ConsoleOut('[tcp] [file:%s] Closing' % conn.fileno())
    conn.close()

# 注销处理
def server_close(ClientId, Tunnels):
    global HOSTS
    global TCPS
    global reglist
    if ClientId in reglist and len(Tunnels):
        del reglist[ClientId]
        ConsoleOut('del:%s' % ClientId)
    for Tunnel in Tunnels:
        if Tunnel in HOSTS:
            del HOSTS[Tunnel]
            ConsoleOut('del:%s' % Tunnel)
        if Tunnel in TCPS:
            TCP = TCPS[Tunnel]
            TCP['csock'].close()
            del TCPS[Tunnel]
            ConsoleOut('del:%s' % Tunnel)

# 服务端程序处理过程
def HKServer(conn, addr):
    global HOSTS
    global TCPS
    global reglist
    global tosocklist
    global proxylist
    global tcplist
    ClientId = ''
    Tunnels = []
    pingtime = 0
    while True:
        if pingtime + 30 < time.time() and pingtime != 0: # 心跳超时
            ConsoleOut('[server] [file:%s] Ping Timeout' % conn.fileno())
            break
        try:
            data = conn.recv(1024)
            if conn in tosocklist and len(data) > 0:
                sendbuf(tosocklist[conn], data) # 转发
                continue

            if not data:
                tosocklist[conn].shutdown(socket.SHUT_RDWR) # 关闭http读写
                tosocklist.pop(conn)
                break
            lenbyte = tolen(data[0:4])
            if len(data) >= (8 + lenbyte):
                buf = data[8:].decode('utf-8')
                ConsoleOut('[server] [file:%s] message: %s' % (conn.fileno(), buf))
                ConsoleOut('[server] [file:%s] message with length: %s' % (conn.fileno(), len(buf)))
                if buf == 'close':
                    server_close(ClientId, Tunnels)
                    break
                js = json.loads(buf)
                if js['Type'] == 'Auth':
                    ClientId = md5(str(time.time())) # 赋值线程变量
                    sendpack(conn, AuthResp(ClientId=ClientId))

                if js['Type'] == 'RegProxy':
                    ClientId = js['Payload']['ClientId'] # 赋值线程变量
                    linklist = reglist[ClientId]
                    for k, linkinfo in enumerate(linklist):
                        if linkinfo['Protocol'] == 'http' or linkinfo['Protocol'] == 'https':
                            tosock = linkinfo['rsock']
                            tosocklist[conn] = tosock
                            sockinfo = tosock.getpeername()
                            url = linkinfo['Protocol'] + '://' + linkinfo['Host']
                            clientaddr = sockinfo[0] + ':' + str(sockinfo[1])
                            sendpack(conn, StartProxy(url, clientaddr))
                            sendbuf(conn, linkinfo['buf']) # 转发请求头
                            proxylist[tosock] = conn # 许可转发

                        if linkinfo['Protocol'] == 'tcp':
                            tosock = linkinfo['rsock']
                            tosocklist[conn] = tosock
                            sockinfo = tosock.getpeername()
                            url = linkinfo['Protocol'] + '://' + SERVERDOMAIN + ':' + str(linkinfo['rport'])
                            clientaddr = sockinfo[0] + ':' + str(sockinfo[1])
                            sendpack(conn, StartProxy(url, clientaddr))
                            sendbuf(conn, linkinfo['buf']) # 转发请求头
                            tcplist[tosock] = conn # 许可转发
                        reglist[ClientId].pop(k)
                    #reglist.pop(ClientId)

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
                        else:
                            HOSTINFO = dict()
                            HOSTINFO['sock'] = conn # 取值线程参数
                            HOSTINFO['clientid'] = ClientId # 取值线程变量
                            HOSTS[domain_name] = HOSTINFO # 赋值全局变量
                            Tunnels.append(domain_name)
                            sendpack(conn, NewTunnel(js['Payload']['ReqId'], url, js['Payload']['Protocol']))

                    if js['Payload']['Protocol'] == 'tcp':
                        rport = js['Payload']['RemotePort']
                        url = js['Payload']['Protocol'] + '://' + SERVERDOMAIN + ':' + str(rport)
                        if rport in TCPS:
                            Error = 'The tunnel %s is already registered.' % url
                            sendpack(conn, NewTunnel(Error=Error))
                        else:
                            try:
                                tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                tcp_server.bind(('0.0.0.0', rport))
                                tcp_server.listen(5)
                                tcp_server.setblocking(1)
                                thread = threading.Thread(target = c_tcp, args = (tcp_server, rport))
                                thread.start()
                            except socket.error:
                                # print('tcp:error') # 端口被其他程序占用
                                Error = 'The tunnel %s is already registered.' % url
                                sendpack(conn, NewTunnel(Error=Error))
                            else:
                                TCPINFO = dict()
                                TCPINFO['sock'] = conn # 取值线程参数
                                TCPINFO['csock'] = tcp_server
                                TCPINFO['clientid'] = ClientId # 取值线程变量
                                TCPS[rport] = TCPINFO # 赋值全局变量
                                Tunnels.append(rport)
                                sendpack(conn, NewTunnel(js['Payload']['ReqId'], url, js['Payload']['Protocol']))

                if js['Type'] == 'Ping':
                    pingtime = time.time()
                    sendpack(conn, Pong())

        except socket.error:
            server_close(ClientId, Tunnels)
            break

    ConsoleOut('[server] [file:%s] Closing' % conn.fileno())
    conn.close()

def h_http():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((SERVERHOST, SERVERHTTP))
        server.listen(5)
        server.setblocking(1)
        ConsoleOut('[http] [file:%s] [%s:%s] Service establishment success' % (server.fileno(), SERVERHOST, SERVERHTTP))
        while True:
            conn, addr = server.accept()
            ConsoleOut('[%s] [file:%s] New Client to: %s:%s' % ('http', server.fileno(), addr[0], addr[1]))
            thread = threading.Thread(target = HHServer, args = (conn, addr, 'http'))
            thread.start()
    except socket.error:
        ConsoleOut('[http] [%s] Service failed to build, port is occupied by other applications' % SERVERHTTP)
        time.sleep(10)
    server.close()

def h_https():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_server = ssl.wrap_socket(server, certfile=pemfile, keyfile=keyfile, server_side=True)
        ssl_server.bind((SERVERHOST, SERVERHTTPS))
        ssl_server.listen(5)
        ssl_server.setblocking(1)
        ConsoleOut('[https] [file:%s] [%s:%s] Service establishment success' % (ssl_server.fileno(), SERVERHOST, SERVERHTTPS))
        while True:
            conn, addr = ssl_server.accept()
            ConsoleOut('[%s] [file:%s] New Client to: %s:%s' % ('https', ssl_server.fileno(), addr[0], addr[1]))
            thread = threading.Thread(target = HHServer, args = (conn, addr, 'https'))
            thread.start()
    except socket.error:
        ConsoleOut('[https] [%s] Service failed to build, port is occupied by other applications' % SERVERHTTPS)
        time.sleep(10)
    ssl_server.close()

def s_tcp():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_server = ssl.wrap_socket(server, certfile=pemfile, keyfile=keyfile)
        ssl_server.bind((SERVERHOST, SERVERPORT))
        ssl_server.listen(5)
        ssl_server.setblocking(1)
        ConsoleOut('[server] [file:%s] [%s:%s] Service establishment success' % (ssl_server.fileno(), SERVERHOST, SERVERPORT))
        while True:
            conn, addr = ssl_server.accept()
            ConsoleOut('[server] [file:%s] New Client to: %s:%s' % (ssl_server.fileno(), addr[0], addr[1]))
            thread = threading.Thread(target = HKServer, args = (conn, addr))
            thread.start()
    except socket.error:
        ConsoleOut('[server] [%s] Service failed to build, port is occupied by other applications' % SERVERPORT)
        time.sleep(10)
    ssl_server.close()

def c_tcp(server, sd):
    while True:
        try:
            conn, addr = server.accept()
            ConsoleOut('[tcp] [file:%s] New Client to: %s:%s' % (server.fileno(), addr[0], addr[1]))
            thread = threading.Thread(target = HTServer, args = (conn, addr))
            thread.start()
        except socket.error:
            break
    server.close()

# 服务端程序初始化
if __name__ == '__main__':
    ConsoleOut('python-ngrokd v1.0')
    threading.Thread(target = h_http, args = ()).start()
    threading.Thread(target = h_https, args = ()).start()
    threading.Thread(target = s_tcp, args = ()).start()
