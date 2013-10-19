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

serverName = '127.0.0.1'
serverPort = 12000

address = (serverName, serverPort)

clientSocket = socket(AF_INET, SOCK_DGRAM)

message = input("Input lowercase sentence: ")

clientSocket.sendto(message.encode('utf-8'), address)

modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
print(modifiedMessage.decode('utf-8'))
clientSocket.close()
