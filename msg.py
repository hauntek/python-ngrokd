import json

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
    import struct
    xx = struct.pack('I', len)
    xx1 = struct.pack('I', 0)
    return xx + xx1

def sendbuf(sock, buf, isblock = False):
    if isblock:
        sock.setblocking(1)
    sock.sendall(buf)
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
    import struct
    return struct.unpack('I', v)[0]

def getRandChar(length):
    import random
    _chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
    return ''.join(random.sample(_chars, length))

def md5(s):
    import hashlib
    return hashlib.md5(s.encode('utf-8')).hexdigest().lower()

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
