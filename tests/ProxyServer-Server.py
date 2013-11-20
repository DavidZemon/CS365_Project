#/usr/bin/python
# File:     'ProxyServer-Server'.py
# Date:     '11/19/13'
# Author    'Ethan Wells'

from src.ProxyServer import ReqHandler
from http.server import HTTPServer
import logging

logging.basicConfig(level='DEBUG')

try:
    server = HTTPServer(('', 12002), ReqHandler)
    print('Started HTTP Server')
    server.serve_forever()
except KeyboardInterrupt:
    server.socket.close()

