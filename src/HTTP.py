#/usr/bin/python
# File:    HTTP.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
from time import time
from src.TCP import TcpClient, TCP


class HTTP(object):
    """

    """

    PORT = 80
    RESPONSE_CODE = {"OK": 200, "Payment required": 202, "No response": 204, "Moved permanently": 301, "Found": 302,
                     "Bad request": 400, "Resource not found": 404}
    NEW_LINE = "\x0D\n"  # Carriage return followed by line feed
    DEFAULT_TIMEOUT = 20  # Timeout for blocking TCP calls (in seconds)

    class Packet(object):
        VERBS = ["GET"]
        HTTP_VERSION = "HTTP/1.1"
        CONTENT_TYPE = {'pdf': 'application/pdf', 'txt': 'text/plain', 'html': 'text/html',
                        'exe': 'application/octet-stream', 'zip': 'application/zip', 'doc': 'application/msword',
                        'xls': 'application/vnd.ms-excel', 'ppt': 'application/vnd.ms-powerpoint', 'gif': 'image/gif',
                        'png': 'image/png', 'jpeg': 'image/jpg', 'jpg': 'image/jpg', 'php': 'text/plain'}

        def __init__(self):
            assert ("<class 'src.HTTP.HTTP.Packet'>" != str(self.__class__))

            self.hostStr = ''

        @staticmethod
        def parse(packet):
            assert (isinstance(packet, str))

            temp = packet.split(2 * HTTP.NEW_LINE)
            header = temp[0]
            try:
                data = temp[1:]
            except IndexError:
                data = None

            # Split the header lines into words
            temp = header.split(HTTP.NEW_LINE)
            header = []
            for line in temp:
                header.append(line.split())

            return header, data

        def __eq__(self, other):
            if type(self) != type(other) or self.hostStr != other.hostStr:
                return False

            return True

    class RequestPacket(Packet):
        def __init__(self):
            super().__init__()
            self.verb = ""
            self.arg = ""
            self.options = {}

        def assemble(self):
            s = self.verb
            s += ' ' + self.arg
            s += ' ' + HTTP.Packet.HTTP_VERSION
            s += HTTP.NEW_LINE
            s += "Host: " + self.hostStr
            s += HTTP.NEW_LINE
            s += HTTP.NEW_LINE

            return s

        @staticmethod
        def parse(packet):
            header, trash = super().parse(packet)

            newPacket = HTTP.RequestPacket()

            # Ensure that we can handle this type of request
            if header[0] not in HTTP.Packet.VERBS:
                raise Exception("Well shit... I guess " + header[0] + " needs to be implemented")

            newPacket.verb = header[0][0]
            newPacket.arg = header[0][1]
            newPacket.hostStr = header[1][1]

            return newPacket

        def __eq__(self, other):
            if not super().__eq__(other):
                return False

            if self.verb != other.verb:
                return False

            if self.arg != other.arg:
                return False

            if self.options != other.options:
                return False

    class ResponsePacket(Packet):
        def __init__(self):
            super().__init__()
            self.data = None
            self.code = ''
            self.codeStr = ''
            self.options = {}

        def assembleResponse(self):
            pass

        @staticmethod
        def parse(packet):
            header, data = super().parse(packet)

            newPacket = HTTP.ResponsePacket()

            try:
                assert (isinstance(data, []))
                newPacket.data = ''
                for piece in data:
                    newPacket.data += piece + 2 * HTTP.NEW_LINE
            except AssertionError:
                newPacket.data = None

            newPacket.code = int(header[0][1])
            newPacket.codeStr = header[0][2]
            header.pop(0)

            for line in header:
                newPacket.options[line[0]] = line[1:]

            return newPacket

    def __init__(self):
        self.tcp = None

    def recvPacket(self, ipAddress, timeout=DEFAULT_TIMEOUT):
        """
        """
        assert (isinstance(self.tcp, TCP))

        respPacket = None
        httpPacket = bytes()

        # Continue receiving packets until the FIN flag is set, signaling the complete HTTP packet has been sent
        while {} == respPacket.header or "fin" not in respPacket.getFlags():
            respPacket = self.tcp.recv((ipAddress, HTTP.PORT), timeout + time())  # TODO: Catch the Timeout exception
            httpPacket += respPacket.getData()

        # Decode the HTTP packet
        httpPacket = httpPacket.decode('utf-8')
        httpPacket = HTTP.ResponsePacket.parse(httpPacket)

        return httpPacket, httpPacket.code


class HttpClient(HTTP):
    """

    """

    def __init__(self, host_str):
        assert (isinstance(host_str, str))

        super(HTTP, self).__init__()
        self.tcp = TcpClient(HTTP.PORT)
        self.host_str = host_str

    def getFile(self, ipAddress, path):
        self.tcp.connect(ipAddress, HTTP.PORT)

        packet = HTTP.RequestPacket()
        packet.verb = "GET"
        packet.arg = path
        packet.hostStr = self.host_str

        # Send the request packet and get a response
        self.tcp.sendData(packet.assemble().encode('utf-8'))
        response, code = self.recvPacket(ipAddress)

        # Ensure the response was positive (contains file)
        if HTTP.RESPONSE_CODE["OK"] != code:
            # TODO: Handle me properly!
            raise Exception("HTTP response error " + str(code) + ": " + response.codeStr)
        else:
            return response.data, response.options["Content-Type:"]


class HttpServer(HTTP):
    pass


if "__main__" == __name__:
    client = HttpClient("www.swaggestofdudes.com")
    client.getFile("127.0.0.1", "test.txt")
