#/usr/bin/python3
# File:    ProcyServer.py
# Author:  Ethan Wells
# Project: Project1

import http.server


class ReqHandler(http.BaseHTTPRequestHandler):

    CONTENT_TYPE = {'pdf': 'application/pdf', 'txt': 'text/plain', 'html': 'text/html',
                    'exe': 'application/octet-stream', 'zip': 'application/zip', 'doc': 'application/msword',
                    'xls': 'application/vnd.ms-excel', 'ppt': 'application/vnd.ms-powerpoint', 'gif': 'image/gif',
                    'png': 'image/png', 'jpeg': 'image/jpg', 'jpg': 'image/jpg', 'php': 'text/plain'}
    UNKNOWN_CONTENT = 'application/octet-stream'

    # TODO: Implement me!
    def do_GET(self):
        try:
            if self.path.splitext()[1] in self.CONTENT_TYPE.keys:
                contentType = self.CONTENT_TYPE[self.path.splitext()[1]]
                self.addHeader(200)
                self.send_header('Content-type', contentType)

        except IOError:
            pass    # TODO: Send request using MyTCP to the origin server


if __name__ == '__main__':
    print("Run me as a test!")