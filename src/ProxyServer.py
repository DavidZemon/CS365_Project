#/usr/bin/python3
# File:    ProxyServer.py
# Author:  Ethan Wells
# Project: Project1

from os import curdir, path
from http.server import BaseHTTPRequestHandler
import logging

from src.HTTP import HttpClient, HTTPError, HTTP, HTTP404


class ReqHandler(BaseHTTPRequestHandler):
    CONTENT_TYPE = {'pdf': 'application/pdf', 'txt': 'text/plain', 'html': 'text/html',
                    'exe': 'application/octet-stream', 'zip': 'application/zip', 'doc': 'application/msword',
                    'xls': 'application/vnd.ms-excel', 'ppt': 'application/vnd.ms-powerpoint', 'gif': 'image/gif',
                    'png': 'image/png', 'jpeg': 'image/jpg', 'jpg': 'image/jpg', 'php': 'text/plain'}
    UNKNOWN_CONTENT = 'application/octet-stream'
    hostStr = "www.swaggestofdudes.com"
    originServerIP = '127.0.0.1'
    originServerPort = 12001

    def do_GET(self):
        logging.getLogger(__name__).debug("ProxyServer: Got GET Request!!!!!!")
        try:
            contentType = self.path.split('.')[1]
            # try to open the file. if it can't, it doesn't exist
            logging.getLogger(__name__).debug("ProxyServer: Name of file: " + self.path[1:])
            f = open(curdir + self.path, 'rb')
            readFile = f.read()
            self.send_response(200)
            try:
                self.send_header('Content-Type', self.CONTENT_TYPE[contentType])
            except KeyError:
                self.send_header('Content-Type', self.UNKNOWN_CONTENT)
            self.send_header('Content-Length', len(readFile))
            self.send_header('Last-Modified', path.getmtime(curdir + self.path))
            self.end_headers()
            self.wfile.write(readFile)
            f.close()
        except IOError:
            logging.getLogger(__name__).debug("ProxyServer: File not found, requesting it from origin server.")
            # file not found, so need to request it from the origin server
            file, contentTypeStr = self.getFileFromOrigin(self.path[1:], self.hostStr)
            if None == file and None == contentTypeStr:
                self.send_response(404, HTTP.RESPONSE_CODE[404])
                return
            else:
                # Got file, now send it to the client
                self.send_response(200)
                self.send_header('Content-type', contentTypeStr)
                self.send_header('Content-Length', len(file))
                self.end_headers()
                self.wfile.write(file)

    def getFileFromOrigin(self, filename, hostStr):
        client = HttpClient(hostStr)
        try:
            rawContent, t = client.getFile(self.originServerIP, filename)
            with open(filename, 'wb') as f:
                f.write(rawContent)
        except HTTPError as e:
            if isinstance(e, HTTP404):
                return None, None
            else:
                raise e

        return rawContent, t


if __name__ == '__main__':
    print("Run me as a test!")
