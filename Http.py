#/usr/bin/python
# File:    Http.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
__author__ = 'david'


class Http(object):
    """

    """

    def __init__(self):
        self.HTTP_VERSION = "HTTP/1.1"
        self.SERV_STR = "Super HTTP Server!!!"
        # Likely going to delete a bunch of these
        self.verbs = ["GET", "POST", "HEAD", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]
        self.responseCodes = {"success": 200, "Payment required": 202, "No response": 204, "Bad request": 400,
                              "Resource not found": 404}
        self.contentType = ["text/html", "porn", "cars"]
        self.NEW_LINE = "\x0D\n"  # Carriage return followed by line feed

