#/usr/bin/python
# File:    TcpGram.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
__author__ = 'david'

import logging
from src.TCP import TcpGram

logging.basicConfig(level="DEBUG")

tcpGram1 = TcpGram()
tcpGram1.create(12000, 12000, 0, 0)

tcpGram2 = TcpGram.decode(tcpGram1.encode())

print("TcpGram equality: " + str(tcpGram1 == tcpGram2))
