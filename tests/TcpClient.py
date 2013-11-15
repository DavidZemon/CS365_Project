#/usr/bin/python
# File:    TcpClient.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
import logging

__author__ = 'david'

from src.TCP import TcpClient

logging.basicConfig(level="DEBUG")
client = TcpClient(12000)
client.connect('127.0.0.1', 12000)

print("Client: I'm connected!")
