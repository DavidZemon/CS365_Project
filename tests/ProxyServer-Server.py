#/usr/bin/python
# File:     'ProxyServer-Server'.py
# Date:     '11/19/13'
# Author    'Ethan Wells'

from http.server import HTTPServer
import logging
from signal import signal, SIGINT
import sys

from src.ProxyServer import ReqHandler


#noinspection PyUnusedLocal
def signal_handler(sig, frame):
    if SIGINT == sig:
        print("Exiting!")
        server.socket.close()
        sys.exit(0)
    else:
        raise Exception("Whoops... shouldn't have caught that signal!")


logging.basicConfig(level='DEBUG')

signal(SIGINT, signal_handler)
server = HTTPServer(('', 12002), ReqHandler)
print('Started HTTP Server')
server.serve_forever()
