#/usr/bin/python
# File:    HTTP.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
import logging
from os import path
from time import time
from src.TCP import TcpClient, TCP, TcpServer


class HTTP(object):
    """

    """

    PORT = 12001
    RESPONSE_CODE = {200: "OK", 202: "Payment required", 204: "No response", 301: "Moved permanently", 302: "Found",
                     400: "Bad request", 404: "Resource not found"}
    NEW_LINE = "\x0D\n"  # Carriage return followed by line feed
    DEFAULT_TIMEOUT = 20  # Timeout for blocking TCP calls (in seconds)

    def __init__(self):
        self.tcp = None

    def recvPacket(self, packetType, ipAddress, timeout=DEFAULT_TIMEOUT):
        """
        """
        assert (packetType in [HTTP.RequestPacket, HTTP.ResponsePacket])
        assert (isinstance(self.tcp, TCP))

        respPacket = None
        httpPacket = bytes()

        # Continue receiving packets until the FIN flag is set, signaling the complete HTTP packet has been sent
        logging.getLogger(__name__).debug("HTTP.recvPacket(): Waiting on first TCP packet...")
        while None == respPacket or "fin" not in respPacket.getFlags():
            if None == ipAddress:
                respPacket = self.tcp.recv(None)  # TODO: Catch the Timeout exception
                if HTTP.PORT != respPacket.header["srcPort"]:
                    logging.getLogger(__name__).debug("HTTP.recvPacket(): Received wrong TCP packet :(")
                    self.recvPacket(packetType, None)
            else:
                respPacket = self.tcp.recv((ipAddress, HTTP.PORT),
                                           timeout + time())  # TODO: Catch the Timeout exception
            logging.getLogger(__name__).debug("HTTP.recvPacket(): Received good TCP packet! :)")
            httpPacket += respPacket.getData()

        logging.getLogger(__name__).debug("HTTP.recvPacket(): Received complete HTTP packet! :D")

        # Decode the HTTP packet
        httpPacket = httpPacket.decode('utf-8')
        httpPacket = packetType.parse(httpPacket)

        print("Printing packet from HTTP.recvPacket():\n---------------------------\n" + str(
            httpPacket) + "\n---------------------------")

        if HTTP.RequestPacket == packetType:
            return httpPacket, httpPacket.verb
        elif HTTP.ResponsePacket == packetType:
            return httpPacket, httpPacket.code
        else:
            raise Exception("RAWR!!! No, but seriously, how did this happen?")

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
            print(temp)
            header = temp[0]
            try:
                data = temp[1:]
            except IndexError:
                data = None

            # Split the header lines into words
            temp = header.split(HTTP.NEW_LINE)
            print(temp)
            header = []
            for line in temp:
                header.append(line.split())
                print("New: " + str(header))

            return header, data

        def __eq__(self, other):
            if type(self) != type(other):
                return False

            if self.hostStr != other.hostStr:
                return False

            return True

        def __str__(self):
            assert (isinstance(self, (HTTP.RequestPacket, HTTP.ResponsePacket)))

            return self.assemble()

    class RequestPacket(Packet):
        def __init__(self):
            super().__init__()
            self.verb = ""
            self.arg = ""

        def assemble(self):
            assert ('' != self.hostStr)

            s = ''

            s += self.verb + ' ' + self.arg + ' ' + HTTP.Packet.HTTP_VERSION + HTTP.NEW_LINE
            s += "Host: " + self.hostStr + HTTP.NEW_LINE
            s += HTTP.NEW_LINE

            return s

        @staticmethod
        def parse(packet):
            header, trash = HTTP.Packet.parse(packet)

            newPacket = HTTP.RequestPacket()

            # Ensure that we can handle this type of request
            if header[0][0] not in HTTP.Packet.VERBS:
                raise Exception("Well shit... I guess " + str(header[0]) + " needs to be implemented")

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

            return True

    class ResponsePacket(Packet):
        def __init__(self):
            super().__init__()
            self.data = None
            self.code = ''
            self.codeStr = ''
            self.options = {}

        def create(self, code, options):
            assert (isinstance(code, int))
            assert (code in HTTP.RESPONSE_CODE.keys())
            if None != options:
                assert (isinstance(options, dict))

            self.code = code
            self.codeStr = HTTP.RESPONSE_CODE[code]
            self.options = options

        def addData(self, data):
            assert (isinstance(data, str))

            self.data += data

        def assemble(self):
            assert ('' != self.hostStr)

            s = ''

            s += HTTP.Packet.HTTP_VERSION + ' ' + str(self.code) + ' ' + HTTP.RESPONSE_CODE[self.code] + HTTP.NEW_LINE

            if None != self.options:
                for option in self.options:
                    s += option + ' ' + self.options[option] + HTTP.NEW_LINE

            return s

        @staticmethod
        def parse(packet):
            header, data = HTTP.Packet.parse(packet)
            print(header)

            if header[0][0] not in [HTTP.Packet.HTTP_VERSION, "HTTP/1.0"]:
                raise AssertionError("Packet is not an HTTP response")

            newPacket = HTTP.ResponsePacket()

            try:
                assert (isinstance(data, list))
                newPacket.data = ''
                for piece in data:
                    newPacket.data += piece + 2 * HTTP.NEW_LINE
            except AssertionError:
                newPacket.data = None

            newPacket.code = int(header[0][1])
            newPacket.codeStr = ' '.join(header[0][2:])
            header.pop(0)

            print("Remaining header: " + str(header))
            for line in header:
                newPacket.options[line[0]] = line[1:]

            return newPacket

        def __eq__(self, other):
            if not super().__eq__(other):
                return False

            if self.code != other.code:
                return False

            if self.codeStr != other.codeStr:
                return False

            if self.options != other.options:
                return False

            return True


class HttpClient(HTTP):
    """

    """

    def __init__(self, hostStr):
        assert (isinstance(hostStr, str))

        super().__init__()
        self.tcp = TcpClient(HTTP.PORT)
        self.hostStr = hostStr

    def getFile(self, ipAddress, path):
        self.tcp.connect(ipAddress, HTTP.PORT)

        packet = HTTP.RequestPacket()
        packet.verb = "GET"
        packet.arg = path
        packet.hostStr = self.hostStr

        # Send the request packet and get a response
        logging.getLogger(__name__).debug("HTTP.HTTPClient.getFile(): Sending request...")
        self.tcp.sendData(packet.assemble().encode('utf-8'))
        logging.getLogger(__name__).debug("HTTP.HTTPClient.getFile(): Request sent... waiting on response")
        response, code = self.recvPacket(HTTP.ResponsePacket, ipAddress)

        # Ensure the response was positive (contains file)
        if HTTP.RESPONSE_CODE[code] != "OK":
            # TODO: Handle me properly!
            raise Exception("HTTP response error " + str(code) + ": " + response.codeStr)
        else:
            return response.data, response.options["Content-Type:"]


class HttpServer(HTTP):
    def __init__(self, hostStr):
        assert (isinstance(hostStr, str))

        super().__init__()
        self.tcp = TcpServer(HTTP.PORT)
        self.hostStr = hostStr

    def recv(self):
        self.tcp.recvConnection(HTTP.PORT)

        packet, verb = self.recvPacket(HTTP.RequestPacket, None)

        # Create our response packet
        if "GET" == verb:
            # File was requested; check if it exists
            response = HTTP.ResponsePacket()
            response.hostStr = self.hostStr
            if path.exists(packet.arg):
                # File exists: Set the packet accordingly and add the file contents
                f = open(packet.arg, 'r')
                response.create("OK", None)  # TODO: Add options
            else:
                # File didn't exists: Set the packet with an error code
                response.create(404, None)
        else:
            raise Exception("Shouldn't this have been caught somewhere else already???")

        self.tcp.sendData(response.assemble().encode('utf-8'))

        self.tcp.close()


if "__main__" == __name__:
    raise Exception("You should probably stop being an idiot and run the tests instead")
