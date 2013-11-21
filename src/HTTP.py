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
from time import time, strftime, gmtime
from src.TCP import TCP, TcpClient, TcpServer, AddressFilterError


class HTTPError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class HTTP404(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class HTTP(object):
    """
    @description:
    Supports the following features:
        - TODO: Fill me in

    Does not support the following features:
        - Persistent connection
        - Almost everything else
    """
    PORT = 12001
    RESPONSE_CODE = {200: "OK", 202: "Payment required", 204: "No response", 301: "Moved permanently", 302: "Found",
                     400: "Bad request", 404: "Resource not found"}
    NEW_LINE = "\x0D\n"  # Carriage return followed by line feed
    DEFAULT_TIMEOUT = 20  # Timeout for blocking TCP calls (in seconds)
    MAX_SEND_ATTEMPTS = 5

    def __init__(self):
        self.transportLayer = None

    def recvPacket(self, packetType, ipAddress, timeout=DEFAULT_TIMEOUT):
        """
        """
        assert (packetType in [HTTP.RequestPacket, HTTP.ResponsePacket])
        assert (isinstance(self.transportLayer, TCP))

        respPacket = None
        httpPacket = bytes()

        # Receive the first TCP packet
        logging.getLogger(__name__).debug("HTTP.recvPacket(): Waiting on first TCP packet...")
        while None == respPacket:
            if None == ipAddress:
                try:
                    respPacket = self.transportLayer.recv(None)
                except AddressFilterError:
                    continue  # If we receive from the wrong address while accepting any address... that's a problem
            else:
                # TODO: Catch the timeout exception
                respPacket = self.transportLayer.recv((ipAddress, HTTP.PORT), timerOverride=timeout + time())
            logging.getLogger(__name__).debug("HTTP.recvPacket(): Received good TCP packet! :)")
            httpPacket += respPacket.getData()
            # TODO: Should we check some TCP flags and do things accordingly?

        # Decode the HTTP packet
        httpPacket = packetType.parse(httpPacket)

        if HTTP.RequestPacket == packetType:
            return httpPacket, httpPacket.verb
        elif HTTP.ResponsePacket == packetType:
            return httpPacket, httpPacket.code
        else:
            raise Exception("RAWR!!! No, but seriously, how did this happen?")

    def send(self, packet, attempts=0):
        assert (isinstance(packet, (HTTP.RequestPacket, HTTP.ResponsePacket)))

        if HTTP.MAX_SEND_ATTEMPTS <= attempts:
            raise TimeoutError

        try:
            self.transportLayer.sendData(packet.assemble())
        except TimeoutError:
            self.send(packet, attempts + 1)

    class Packet(object):
        VERBS = ["GET"]
        HTTP_VERSION = "HTTP/1.1"
        CONTENT_TYPE = {'pdf': 'application/pdf', 'txt': 'text/plain', 'html': 'text/html',
                        'exe': 'application/octet-stream', 'zip': 'application/zip', 'doc': 'application/msword',
                        'xls': 'application/vnd.ms-excel', 'ppt': 'application/vnd.ms-powerpoint', 'gif': 'image/gif',
                        'png': 'image/png', 'jpeg': 'image/jpg', 'jpg': 'image/jpg', 'php': 'text/plain'}
        UNKNOWN_CONTENT = 'application/octet-stream'

        def __init__(self):
            assert ("<class 'src.HTTP.HTTP.Packet'>" != str(self.__class__))

        @staticmethod
        def parse(packet):
            assert (isinstance(packet, bytes))

            temp = packet.split((2 * HTTP.NEW_LINE).encode('utf-8'))

            header = temp[0].decode('utf-8')
            try:
                data = bytes(0)
                for dat in temp[1:]:
                    data += dat
            except IndexError:
                data = bytes(0)

            # Split the header lines into words
            temp = header.split(HTTP.NEW_LINE)
            header = []
            for line in temp:
                header.append(line.split())

            return header, data

        def __eq__(self, other):
            if type(self) != type(other):
                return False

            return True

        def __str__(self):
            assert (isinstance(self, (HTTP.RequestPacket, HTTP.ResponsePacket)))

            return str(self.assemble())

    class RequestPacket(Packet):
        def __init__(self):
            super().__init__()
            self.verb = ""
            self.arg = ""
            self.hostStr = ''

        def assemble(self):
            assert ('' != self.hostStr)

            s = ''
            s += self.verb + ' ' + self.arg + ' ' + HTTP.Packet.HTTP_VERSION + HTTP.NEW_LINE
            s += "Host: " + self.hostStr + HTTP.NEW_LINE
            s += HTTP.NEW_LINE

            return s.encode('utf-8')

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

            if self.hostStr != other.hostStr:
                return False

            if self.verb != other.verb:
                return False

            if self.arg != other.arg:
                return False

            return True

    class ResponsePacket(Packet):
        def __init__(self):
            super().__init__()
            self.data = bytes(0)
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
            assert (isinstance(data, bytes))

            self.data += data

        def assemble(self):
            s = ''

            s += HTTP.Packet.HTTP_VERSION + ' ' + str(self.code) + ' ' + HTTP.RESPONSE_CODE[self.code] + HTTP.NEW_LINE

            if None != self.options:
                for option in self.options:
                    s += option + ' ' + self.options[option] + HTTP.NEW_LINE

            # End of header! Insert extra newline
            s += HTTP.NEW_LINE

            s = s.encode('utf-8')
            s += self.data

            return s

        @staticmethod
        def parse(packet):
            header, data = HTTP.Packet.parse(packet)

            if header[0][0] not in [HTTP.Packet.HTTP_VERSION, "HTTP/1.0"]:
                raise AssertionError("Packet is not an HTTP response")

            newPacket = HTTP.ResponsePacket()

            newPacket.data = data

            newPacket.code = int(header[0][1])
            newPacket.codeStr = ' '.join(header[0][2:])
            header.pop(0)

            for line in header:
                if line:
                    newPacket.options[line[0]] = ' '.join(line[1:])

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
        self.transportLayer = TcpClient(HTTP.PORT)
        self.hostStr = hostStr

    def getFile(self, ipAddress, filePath):
        assert (isinstance(ipAddress, str))
        assert (isinstance(filePath, str))

        self.transportLayer.connect(ipAddress, HTTP.PORT)

        packet = HTTP.RequestPacket()
        packet.verb = "GET"
        packet.arg = filePath
        packet.hostStr = self.hostStr

        # Send the request packet and get a response
        logging.getLogger(__name__).debug("HTTP.HTTPClient.getFile(): Sending request...")
        self.send(packet)
        logging.getLogger(__name__).debug("HTTP.HTTPClient.getFile(): Request sent... waiting on response")

        return self.getServerResponse(ipAddress)

    def getServerResponse(self, ipAddress, timeout=HTTP.DEFAULT_TIMEOUT, startTime=time()):
        assert (isinstance(ipAddress, str))

        # Receive the HTTP packet header and first bits of data (if applicable)
        response, code = self.recvPacket(HTTP.ResponsePacket, ipAddress)

        if HTTP.RESPONSE_CODE[code] != "OK":
            # TODO: Handle me properly!
            raise Exception("HTTP response error " + str(code) + ":\n" + response)

        logging.getLogger(__name__).info("Received first data packet...")
        packetNum = 1

        # Receive remaining HTTP packet data
        tcpPacket = None
        while None == tcpPacket or "fin" not in tcpPacket.getFlags():
            try:
                tcpPacket = self.transportLayer.recv((ipAddress, HTTP.PORT), timeout + time())
            except TimeoutError:
                if timeout > time():
                    return self.getServerResponse(ipAddress, timeout - (time() - startTime), time())
                else:
                    raise
            packetNum += 1
            if "fin" not in tcpPacket.getFlags():
                logging.getLogger(__name__).info("Received packet #" + str(packetNum))
            if tcpPacket.getData():
                response.addData(tcpPacket.getData())

        logging.getLogger(__name__).debug("HTTP.recvPacket(): Received complete HTTP packet! :D")

        # Ensure the response was positive (contains file)

        return response.data, response.options["Content-Type:"]


class HttpServer(HTTP):
    def __init__(self, hostStr):
        assert (isinstance(hostStr, str))

        super().__init__()
        self.transportLayer = TcpServer(HTTP.PORT)
        self.hostStr = hostStr

    def recv(self):
        self.transportLayer.recvConnection(HTTP.PORT)

        packet, verb = self.recvPacket(HTTP.RequestPacket, None)

        # Create our response packet
        if "GET" == verb:
            response = self.serviceGet(packet)
        else:
            raise Exception("Shouldn't this have been caught somewhere else already???")

        self.send(response)

        self.transportLayer.close()

    def serviceGet(self, packet):
        assert (isinstance(packet, HTTP.RequestPacket))

        # File was requested; check if it exists
        response = HTTP.ResponsePacket()
        response.hostStr = self.hostStr
        if path.exists(packet.arg):
            # File exists: Set the packet accordingly and add the file contents
            response.create(200, {})  # TODO: Add options
            f = open(packet.arg, 'rb')
            fileExt = packet.arg.split('.')[1]

            # Set file type
            try:
                response.options["Content-Type:"] = HTTP.Packet.CONTENT_TYPE[fileExt]
            except KeyError:
                response.options["Content-Type:"] = HTTP.Packet.UNKNOWN_CONTENT

            # Set the standard response options
            self.addBasicResponseOptions(response, 200)

            # Add the file contents
            response.addData(f.read())
            f.close()
        else:
            # File didn't exists: Set the packet with an error code
            response.create(404, None)

        return response

    def addBasicResponseOptions(self, response, code):
        response.options["date:"] = strftime("%a, %d %b %Y %H:%M:%S %Z", gmtime())
        response.options["status:"] = str(code) + ' ' + HTTP.RESPONSE_CODE[code]
        response.options["version:"] = HTTP.Packet.HTTP_VERSION
        response.options["server:"] = self.hostStr


if "__main__" == __name__:
    raise Exception("You should probably stop being an idiot and run the tests instead")
