#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 2.7.9 或 Python 3.4.2 以上运行
# 项目地址: https://github.com/hauntek/python-ngrokd
# Version: v1.46
import socket
import ssl
import sys
import time
import logging
import threading

SERVERDOMAIN = 'ngrok.com' # 服务域名
SERVERHOST = ''
SERVERHTTP = 80
SERVERHTTPS = 443
SERVERPORT = 4443

pemfile = 'snakeoil.crt' # 服务证书公钥
keyfile = 'snakeoil.key' # 服务证书密钥

bufsize = 1024*8 # 吞吐量

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s', datefmt='%Y/%m/%d %H:%M:%S')

def tcp_service(server, post):
    from connt import HTServer
    try:
        while True:
            conn, addr = server.accept()
            try:
                thread = threading.Thread(target = HTServer, args = (conn, addr, 'tcp'))
                thread.setDaemon(True)
                thread.start()
            except Exception:
                pass

    except Exception:
        pass

    server.close()

def https_service(host, post, certfile=pemfile, keyfile=keyfile):
    from connt import HHServer
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, post))
        server.listen(5)
        server.setblocking(1)
        logging.debug('[%s:%d] Service establishment success' % (host, post))
        while True:
            news, addr = server.accept()
            try:
                conn = context.wrap_socket(news, server_side=True)
                logger = logging.getLogger('%s:%d' % ('https', conn.fileno()))
                logger.debug('New Client to: %s:%d' % (addr[0], addr[1]))
                thread = threading.Thread(target = HHServer, args = (conn, addr, 'https'))
                thread.setDaemon(True)
                thread.start()
            except Exception:
                pass

    except Exception as ex:
        logging.error('[%s:%d] %s' % (host, post, str(ex)))

    server.close()

def http_service(host, post):
    from connt import HHServer
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, post))
        server.listen(5)
        server.setblocking(1)
        logging.debug('[%s:%d] Service establishment success' % (host, post))
        while True:
            conn, addr = server.accept()
            try:
                logger = logging.getLogger('%s:%d' % ('http', conn.fileno()))
                logger.debug('New Client to: %s:%d' % (addr[0], addr[1]))
                thread = threading.Thread(target = HHServer, args = (conn, addr, 'http'))
                thread.setDaemon(True)
                thread.start()
            except Exception:
                pass

    except Exception as ex:
        logging.error('[%s:%d] %s' % (host, post, str(ex)))

    server.close()

def service(host, post, certfile=pemfile, keyfile=keyfile):
    from connt import HKServer
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, post))
        server.listen(5)
        server.setblocking(1)
        logging.debug('[%s:%d] Service establishment success' % (host, post))
        while True:
            news, addr = server.accept()
            try:
                conn = context.wrap_socket(news, server_side=True)
                logger = logging.getLogger('%s:%d' % ('service', conn.fileno()))
                logger.debug('New Client to: %s:%d' % (addr[0], addr[1]))
                thread = threading.Thread(target = HKServer, args = (conn, addr, 'service'))
                thread.setDaemon(True)
                thread.start()
            except Exception:
                pass

    except Exception as ex:
        logging.error('[%s:%d] %s' % (host, post, str(ex)))

    server.close()

# 服务端程序初始化
if __name__ == '__main__':
    thread = threading.Thread(target = service, args = (SERVERHOST, SERVERPORT)) # 服务启用,SERVICE
    thread.setDaemon(True)
    thread.start()
    thread = threading.Thread(target = http_service, args = (SERVERHOST, SERVERHTTP)) # 服务启用,HTTP_SERVICE
    thread.setDaemon(True)
    thread.start()
    thread = threading.Thread(target = https_service, args = (SERVERHOST, SERVERHTTPS)) # 服务启用,HTTPS_SERVICE
    thread.setDaemon(True)
    thread.start()
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()
