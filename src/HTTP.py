#/usr/bin/python
# File:    HTTP.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
__author__ = 'david'

from src.TCP import TcpServer, TcpClient


class HTTP(object):
    """

    """

    HTTP_VERSION = "HTTP/1.1"
    SERV_STR = "Super HTTP Server!!!"
    NEW_LINE = "\x0D\n"  # Carriage return followed by line feed
    verbs = ["GET", "POST", "HEAD", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]
    RESPONSE_CODE = {"success": 200, "Payment required": 202, "No response": 204, "Bad request": 400,
                     "Resource not found": 404}
    CONTENT_TYPE = ["text/html", "porn", "cars"]

    def __init__(self):
        pass
