#/usr/bin/python
# File:    TcpClient.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
__author__ = 'david'

from src.TCP import TcpClient

client = TcpClient(12000)
client.connect('127.0.0.1', 12000)

print("Client: I'm connected!")
