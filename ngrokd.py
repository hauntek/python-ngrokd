#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 2.7.13 或 Python 3.1 以上运行
# 项目地址: https://github.com/hauntek/python-ngrokd
# Version: v1.41
import socket
import ssl
import sys
import time
import logging
import threading

# 服务域名
server_domain = 'ngrok.com'

server_host = '127.0.0.1'
server_http = 8080
server_https = 4439
server_port = 4443

# 服务证书公钥
pemfile = 'key/snakeoil.crt'
# 服务证书密钥
keyfile = 'key/snakeoil.key'
# 吞吐量
bufsize = 1024*8

logging.basicConfig(
    level=logging.NOTSET,
    format='[%(asctime)s] [%(levelname)s:%(lineno)d] [%(filename)s(thread name: %(threadName)s thread number: %(thread)d)] %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S',
    stream=sys.stdout
)

def log_service(times):
    from module import connt
    while True:
        time.sleep(times)
        connt.Server_list()

def tcp_service(server, post):
    from module import connt
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=connt.HTServer, args=(conn, addr, 'tcp'))
            thread.setDaemon(True)
            thread.start()

    except socket.error:
        pass

    server.close()

def https_service(host, post, certfile=pemfile, keyfile=keyfile):
    from module import connt
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
                thread = threading.Thread(target = connt.HHServer, args = (conn, addr, 'https'))
                thread.setDaemon(True)
                thread.start()
            except ssl.SSLError:
                pass

    except Exception:
        logging.error('[%s:%s] Service failed to build, port is occupied by other applications' % (host, post))

    ssl_server.close()

def http_service(host, post):
    from module import connt
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((host, post))
        server_sock.listen(5)
        server_sock.setblocking(1)
        logging.debug('[%s:%s] Service establishment success' % (host, post))
        while True:
            conn, addr = server_sock.accept()
            logging.debug('New Client to: %s:%s' % (addr[0], addr[1]))
            thread = threading.Thread(target = connt.HHServer, args = (conn, addr, 'http'))
            thread.setDaemon(True)
            thread.start()

    except Exception:
        logging.error('[%s:%s] Service failed to build, port is occupied by other applications' % (host, post))

    server_sock.close()

def service(host, post, certfile=pemfile, keyfile=keyfile):
    from module import connt
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_server = ssl.wrap_socket(server_sock, certfile=certfile, keyfile=keyfile)
        ssl_server.bind((host, post))
        ssl_server.listen(5)
        # 阻塞式的套接字
        ssl_server.setblocking(1)
        # 这里用info比较好吧
        logging.info('[%s:%s] Service start success' % (host, post))
        while True:
            try:
                conn, addr = ssl_server.accept()
                logging.debug('New Client to: %s:%s' % (addr[0], addr[1]))
                thread = threading.Thread(target=connt.HKServer, args=(conn, addr, 'service'))
                thread.setDaemon(True)
                thread.start()
            except ssl.SSLError:
                pass

    except Exception:
        logging.error('[%s:%s] Service failed to build, port is occupied by other applications' % (host, post))

    ssl_server.close()

def main():
    # 服务启用,SERVICE
    service_thread = threading.Thread(
        target=service,
        args=(server_host, server_port)
        )
    service_thread.setDaemon(True)
    service_thread.start()
    logging.info('Service start')

    # 服务启用,HTTP_SERVICE
    http_service_thread = threading.Thread(
        target=http_service,
        args=(server_host, server_http)
        )
    http_service_thread.setDaemon(True)
    http_service_thread.start()
    logging.info('http service start')
    # 服务启用,HTTPS_SERVICE
    https_service_thread = threading.Thread(
        target=https_service,
        args=(server_host, server_https)
        )
    https_service_thread.setDaemon(True)
    https_service_thread.start()
    logging.info('https service start')
    # 服务启用,LOG_SERVICE
    log_service_thread = threading.Thread(
        target=log_service,
        args=(30, )
        )
    log_service_thread.setDaemon(True)
    log_service_thread.start()
    logging.info('log service start')

    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit(0)

# 服务端程序初始化
if __name__ == '__main__':
    main()
