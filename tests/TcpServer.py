#/usr/bin/python
# File:    TcpServer.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
__author__ = 'david'

from src.TCP import TcpServer

server = TcpServer(12000)
server.recvConnection()

print("Server: I'm connected!")
