#/usr/bin/python
# File:    TcpPacket.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
__author__ = 'david'

import logging
from src.TCP import TCP

logging.basicConfig(level="DEBUG")

packet1 = TCP.Packet()
packet1.create(12000, 12000, 0, 0)

packet2 = TCP.Packet.decode(packet1.encode())

print("Packet equality: " + str(packet1 == packet2))
