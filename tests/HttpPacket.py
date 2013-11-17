#/usr/bin/python
# File:    HttpPacket.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""

from src.HTTP import HTTP

packet1 = HTTP.RequestPacket()
packet1.hostStr = "host"
packet1.verb = "GET"
packet1.arg = "poop.txt"

assembly = packet1.assemble()

packet2 = HTTP.RequestPacket.parse(assembly)

print(packet1)
print(packet1 == packet2)
