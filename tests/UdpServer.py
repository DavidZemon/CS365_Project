#/usr/bin/python
# File:    UdpServer.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
__author__ = 'david'

import logging
from src.UDP import UDPServer

logging.basicConfig(level="DEBUG")

print("The server is ready to receive")

server = UDPServer(12000)
while True:
    message, clientAddress = server.recvfrom(2048)
    message = message.decode('utf-8')
    modifiedMessage = message.upper()
    server.sendto(modifiedMessage.encode('utf-8'), clientAddress)
