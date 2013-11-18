#/usr/bin/python
# File:    HttpClient.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""

import logging
from src.HTTP import HttpClient

logging.basicConfig(level="INFO")

fileName = "testfile.jpg"
dstDir = "received/"

client = HttpClient("www.swaggestofdudes.com")
rawContent, t = client.getFile("127.0.0.1", fileName)

f = open(dstDir + fileName, 'wb')
f.write(rawContent)
f.close()
