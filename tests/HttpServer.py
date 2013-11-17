#/usr/bin/python
# File:    HttpServer.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""

import logging
from src.HTTP import HttpServer

#logging.basicConfig(level="DEBUG")

server = HttpServer("127.0.0.1")
server.recv()
