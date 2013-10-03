#/usr/bin/python3
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description: Implement the client side of http to interact with the server you have developed in the previous
assignment. You do not need to implement the function to display the received object, just save it as a local file.
"""

from socket import socket, AF_INET, SOCK_DGRAM

serverPort = 12000

serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('', serverPort))

print("The server is ready to receive")

while True:
    message, clientAddress = serverSocket.recvfrom(2048)
    message = message.decode('utf-8')
    modifiedMessage = message.upper()
    serverSocket.sendto(modifiedMessage.encode('utf-8'), clientAddress)
