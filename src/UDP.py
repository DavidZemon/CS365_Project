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

from socket import socket, AF_INET, SOCK_DGRAM


class UDPServer(object):
    def __init__(self, port):
        self.port = port
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind('', self.port)

    def recvfrom(self, bufferSize):
        assert (isinstance(bufferSize, int))
        return self.socket.recvfrom(bufferSize)

    def sendto(self, data, address):
        self.socket.sendto(data, address)


class UDPClient(object):
    def __init__(self):
        self.socket = socket(AF_INET, SOCK_DGRAM)

    def sendto(self, address, data):
        assert (isinstance(address, tuple))
        assert (isinstance(address[0], str))
        assert (isinstance(address[1], int))

        self.socket.sendto(data, address)

    def recvfrom(self, bufferSize):
        assert (isinstance(bufferSize, int))

        return self.socket.recvfrom(bufferSize)


if "__main__" == __name__:
    print("The server is ready to receive")

    while True:
        server = UDPServer(12000)
        message, clientAddress = server.recvfrom(2048)
        message = message.decode('utf-8')
        modifiedMessage = message.upper()
        server.sendto(modifiedMessage.encode('utf-8'), clientAddress)
