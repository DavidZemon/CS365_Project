#/usr/bin/python3
# File:    UDP.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description: Implement the client side of http to interact with the server you have developed in the previous
assignment. You do not need to implement the function to display the received object, just save it as a local file.
"""

import logging
from socket import socket, AF_INET, SOCK_DGRAM


class UDPServer(object):
    def __init__(self, port):
        logging.getLogger(__name__).debug("Starting UDPServer")
        self.port = port
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind(('', self.port))

    def recvfrom(self, bufferSize):
        assert (isinstance(bufferSize, int))
        return self.socket.recvfrom(bufferSize)

    def sendto(self, data, address):
        assert (isinstance(data, bytes))
        assert (isinstance(address, tuple))
        assert (isinstance(address[0], str))
        assert (isinstance(address[1], int))

        self.socket.sendto(data, address)


class UDPClient(object):
    def __init__(self):
        logging.getLogger(__name__).debug("Starting UDPClient")
        self.socket = socket(AF_INET, SOCK_DGRAM)

    def sendto(self, data, address):
        assert (isinstance(data, bytes))
        assert (isinstance(address, tuple))
        assert (isinstance(address[0], str))
        assert (isinstance(address[1], int))

        logging.getLogger(__name__).debug("Sending data to " + str(address))
        self.socket.sendto(data, address)

    def recvfrom(self, bufferSize):
        assert (isinstance(bufferSize, int))

        return self.socket.recvfrom(bufferSize)

    def close(self):
        self.socket.close()


if "__main__" == __name__:
    raise Exception("File not executable! Try calling tests.UdpClient and tests.UdpServer instead")
