#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 2.7.13 或 Python 3.1 以上运行
# 项目地址: https://github.com/hauntek/python-ngrokd
# Version: v1.38
import socket
import ssl
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

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s:%(lineno)d] [%(name)s] %(message)s', datefmt='%Y/%m/%d %H:%M:%S')

def log_service(times):
    from connt import Server_list
    while True:
        time.sleep(times)
        Server_list()

def tcp_service(server, post):
    from connt import HTServer
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target = HTServer, args = (conn, post))
            thread.start()

    except socket.error:
        pass

    server.close()

def https_service(host, post, certfile=pemfile, keyfile=keyfile):
    from connt import HHServer
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_server = ssl.wrap_socket(server, certfile=certfile, keyfile=keyfile, server_side=True)
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
                thread.start()
            except ssl.SSLError:
                pass

    except socket.error:
        logging.error('Service failed to build, port is occupied by other applications' % post)
        time.sleep(10)

    ssl_server.close()

def http_service(host, post):
    from connt import HHServer
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, post))
        server.listen(5)
        server.setblocking(1)
        logging.debug('[%s:%s] Service establishment success' % (host, post))
        while True:
            conn, addr = server.accept()
            logger = logging.getLogger('%s:%d' % ('http', conn.fileno()))
            logger.debug('New Client to: %s:%s' % (addr[0], addr[1]))
            thread = threading.Thread(target = HHServer, args = (conn, addr, 'http'))
            thread.start()

    except socket.error:
        logging.error('Service failed to build, port is occupied by other applications' % post)
        time.sleep(10)

    server.close()

def service(host, post, certfile=pemfile, keyfile=keyfile):
    from connt import HKServer
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_server = ssl.wrap_socket(server, certfile=certfile, keyfile=keyfile)
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
                thread.start()
            except ssl.SSLError:
                pass

    except socket.error:
        logging.error('Service failed to build, port is occupied by other applications' % post)
        time.sleep(10)

    ssl_server.close()

# 服务端程序初始化
if __name__ == '__main__':
    threading.Thread(target = service, args = (SERVERHOST, SERVERPORT)).start() # 服务启用,SERVICE
    threading.Thread(target = http_service, args = (SERVERHOST, SERVERHTTP)).start() # 服务启用,HTTP_SERVICE
    threading.Thread(target = https_service, args = (SERVERHOST, SERVERHTTPS)).start() # 服务启用,HTTPS_SERVICE
    threading.Thread(target = log_service, args = (20, )).start() # 服务启用,LOG_SERVICE
