#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 2.7.12 或 Python 3.1 以上运行
# 项目地址: https://github.com/hauntek/python-ngrokd
# Version: v1.42
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

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s:%(lineno)d] [%(name)s] %(message)s', datefmt='%Y/%m/%d %H:%M:%S')

def tcp_service(tcp_server, post):
    from connt import HTServer
    try:
        while True:
            conn, addr = tcp_server.accept()
            thread = threading.Thread(target = HTServer, args = (conn, addr, 'tcp'))
            thread.setDaemon(True)
            thread.start()
    except Exception:
        pass

    tcp_server.close()

def https_service(host, post, certfile=pemfile, keyfile=keyfile):
    from connt import HHServer
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_server = ssl.wrap_socket(server, certfile=certfile, keyfile=keyfile, server_side=True)
        ssl_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ssl_server.bind((host, post))
        ssl_server.listen(5)
        ssl_server.setblocking(1)
        logging.debug('[%s:%s] Service establishment success' % (host, post))
        while True:
            try:
                conn, addr = ssl_server.accept()
                logger = logging.getLogger('%s:%d' % ('https', conn.fileno()))
                logger.debug('New Client to: %s:%s' % (addr[0], addr[1]))
                thread = threading.Thread(target = HHServer, args = (conn, addr, 'https'))
                thread.setDaemon(True)
                thread.start()
            except Exception:
                pass

    except Exception:
        logging.error('[%s:%s] Service failed to build, port is occupied by other applications' % (host, post))

    ssl_server.close()

def http_service(host, post):
    from connt import HHServer
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, post))
        server.listen(5)
        server.setblocking(1)
        logging.debug('[%s:%s] Service establishment success' % (host, post))
        while True:
            try:
                conn, addr = server.accept()
                logger = logging.getLogger('%s:%d' % ('http', conn.fileno()))
                logger.debug('New Client to: %s:%s' % (addr[0], addr[1]))
                thread = threading.Thread(target = HHServer, args = (conn, addr, 'http'))
                thread.setDaemon(True)
                thread.start()
            except Exception:
                pass

    except Exception:
        logging.error('[%s:%s] Service failed to build, port is occupied by other applications' % (host, post))

    server.close()

def service(host, post, certfile=pemfile, keyfile=keyfile):
    from connt import HKServer
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_server = ssl.wrap_socket(server, certfile=certfile, keyfile=keyfile)
        ssl_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ssl_server.bind((host, post))
        ssl_server.listen(5)
        ssl_server.setblocking(1)
        logging.debug('[%s:%s] Service establishment success' % (host, post))
        while True:
            try:
                conn, addr = ssl_server.accept()
                logger = logging.getLogger('%s:%d' % ('service', conn.fileno()))
                logger.debug('New Client to: %s:%s' % (addr[0], addr[1]))
                thread = threading.Thread(target = HKServer, args = (conn, addr, 'service'))
                thread.setDaemon(True)
                thread.start()
            except Exception:
                pass

    except Exception:
        logging.error('[%s:%s] Service failed to build, port is occupied by other applications' % (host, post))

    ssl_server.close()

# 服务端程序初始化
if __name__ == '__main__':
    threading.Thread(daemon=True, target = service, args = (SERVERHOST, SERVERPORT)).start() # 服务启用,SERVICE
    threading.Thread(daemon=True, target = http_service, args = (SERVERHOST, SERVERHTTP)).start() # 服务启用,HTTP_SERVICE
    threading.Thread(daemon=True, target = https_service, args = (SERVERHOST, SERVERHTTPS)).start() # 服务启用,HTTPS_SERVICE
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()
