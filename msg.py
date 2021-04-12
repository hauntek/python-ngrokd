import json
import struct

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
