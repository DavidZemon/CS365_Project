#/usr/bin/python
# File:    HttpServer.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""

from signal import signal, SIGINT
import sys

from src.HTTP import HttpServer


#noinspection PyUnusedLocal
def signal_handler(sig, frame):
    if SIGINT == sig:
        server.transportLayer.close()
        sys.exit(0)
    else:
        raise Exception("Whoops... shouldn't have caught that signal!")


signal(SIGINT, signal_handler)
#logging.basicConfig(level="DEBUG")

server = HttpServer("127.0.0.1")
while 1:
    server.recv()
