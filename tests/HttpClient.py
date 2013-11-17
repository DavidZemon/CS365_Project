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

#logging.basicConfig(level="DEBUG")

client = HttpClient("www.swaggestofdudes.com")
rawContent, t = client.getFile("127.0.0.1", "test.txt")

f = open("test.txt", 'w')

for line in rawContent:
    f.write(line)
    print(line)
