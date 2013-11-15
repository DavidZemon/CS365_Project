#/usr/bin/python
# File:    UdpClient.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
__author__ = 'david'

import logging
from src.UDP import UDPClient

logging.basicConfig(level="DEBUG")

serverName = '127.0.0.1'
serverPort = 12000

client = UDPClient()

message = input("Input lowercase sentence: ")
client.sendto(message.encode('utf-8'), (serverName, serverPort))

modifiedMessage, serverAddress = client.recvfrom(2048)
print(modifiedMessage.decode('utf-8'))
client.close()
