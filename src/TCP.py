#/usr/bin/python
# File:    TCP.py
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""

import logging
from sys import stderr
from struct import unpack, pack
from time import time, sleep

from src.UDP import UDPClient, UDPServer


class TCP(object):
    """
    Optional section of TCP header NOT implemented!
    """

    MAX_PACKET_SIZE = 512  # Maximum packet size in bytes, including the header
    MINIMUM_HEADER_SIZE = 20  # Bytes required to receive a simple TCP packet (header only); Default = 20
    MAX_DATA_SIZE = MAX_PACKET_SIZE - MINIMUM_HEADER_SIZE
    MAX_PACKET_SEND_ATTEMPTS = 5
    DEFAULT_SOCKET_TIMEOUT = 10  # Timeout for blocking socket calls (in seconds)

    def __init__(self, srcPort, timeout=DEFAULT_SOCKET_TIMEOUT):
        assert ("<class 'src.TCP.TCP'>" != str(self.__class__))  # Ensure TCP is not instantiated
        assert (isinstance(srcPort, int))
        assert (isinstance(timeout, (int, float)))

        self.srcPort = srcPort
        self.connected = False
        self.dstPort = None  # Integer representing destination port number
        self.internetLayer = None
        self.dstAddress = ()
        self.timeout = timeout
        self.ackNum = None
        self.seqNum = 0
        self.cache = {}  # TODO: Implement me!

    def sendPacket(self, packet, attempt=0, getResponse=True):
        assert (isinstance(packet, TCP.Packet))
        assert (isinstance(attempt, int))
        assert (isinstance(getResponse, bool))

        if attempt == TCP.MAX_PACKET_SEND_ATTEMPTS:
            raise Exception("TcpClient.sendPacket() error: server response error")

        logging.getLogger(__name__).debug("TCP.sendPacket(): Attempt #" + str(attempt))

        # Send the packet...
        self.internetLayer.sendto(packet.encode(), self.dstAddress)

        # And if a response was requested, wait for it
        if getResponse:
            # Init recvAddress for while loop
            recvAddress = None
            response = None
            startTime = time()  # Get current system time
            while recvAddress != self.dstAddress:  # Try and try again until we receive from the correct address
                self.internetLayer.socket.settimeout(
                    self.timeout + startTime - time())  # Update timeout to be 20 seconds after
                # TODO: Confirm that MINIMUM_HEADER_SIZE bytes is enough; Is it worth adding wiggle room?
                logging.getLogger(__name__).debug("TCP.sendPacket(): Waiting on ACK from " + str(self.dstAddress))
                response, recvAddress = self.internetLayer.recvfrom(TCP.MINIMUM_HEADER_SIZE)
                logging.getLogger(__name__).debug("TCP.sendPacket(): Received packet from " + str(recvAddress))

            # Receive a packet
            response = TCP.Packet.decode(response)

            # Check for acknowledgement
            if "ack" not in response.getFlags():
                raise Exception("TcpClient.sendPacket() error: response did not ACK")

            # Check for acknowledged seq. # to increment by 1 (if not incremented by 1, try again)
            if response.header["ackNum"] != (packet.header["ackNum"] + 1):
                print("This shouldn't happen on a reliable network!")
                return self.sendPacket(packet, attempt + 1)
            else:
                return response

    def sendData(self, data):
        assert (None != self.dstAddress)
        assert (isinstance(data, bytes))

        # Split up the data into smaller chunks if necessary
        packetNum = 0
        print("Data length: " + str(len(data)))
        while len(data):
            logging.getLogger(__name__).debug("TCP.sendData(): Sending packet #" + str(packetNum))
            packet = TCP.Packet()
            packet.create(self.srcPort, self.dstAddress[1], self.seqNum, self.ackNum)
            if len(data) >= TCP.MAX_DATA_SIZE:
                dataLen = TCP.MAX_DATA_SIZE
            else:
                dataLen = len(data)
            packet.addData(data[0:dataLen])
            data = data[dataLen:]
            print(packet)
            self.sendPacket(packet)
            sleep(0.5)

        # Data all done! Send FIN
        logging.getLogger(__name__).debug("TCP.sendData(): Sending FIN!")
        packet = TCP.Packet()
        packet.create(self.srcPort, self.dstAddress[1], self.seqNum, self.ackNum)
        packet.setFlags(["fin"])
        self.sendPacket(packet, getResponse=False)

    def recv(self, reqAddr, httpTimerEnd=None):
        """

        """
        # TODO: Keep track of whether a timeout event is due to HTTP timeout or TCP timeout

        if None != reqAddr:
            assert (isinstance(reqAddr, tuple))
            assert (isinstance(reqAddr[0], str))
            assert (isinstance(reqAddr[1], int))
            assert (isinstance(httpTimerEnd, float))

        # Set the timeout if necessary
        if None != reqAddr:
            # If HTTP gave a timeout value and that time has been surpassed, raise an exception
            if 0 > httpTimerEnd - time():
                # TODO: Implement flow control instead of being a whiny bitch
                raise TimeoutError("HTTP request timed out")

            socketTimeout = min([httpTimerEnd - time(), TCP.DEFAULT_SOCKET_TIMEOUT])
            self.internetLayer.socket.settimeout(socketTimeout)
        else:
            self.internetLayer.socket.settimeout(None)

        # Wait for a packet
        packet, clientAddress = self.internetLayer.recvfrom(TCP.MAX_PACKET_SIZE)
        print("TCP.recv() just received:\n" + str(packet) + "\n---------------")

        # If a specific address was requested, check it
        if None != reqAddr and reqAddr != clientAddress:
            #noinspection PyUnboundLocalVariable
            print("*****************\nawwwwwww shit tits\n*****************")
            return self.recv(reqAddr, httpTimerEnd)
        else:
            self.ackNum += 1
            ackPacket = TCP.Packet()
            ackPacket.create(self.srcPort, self.dstPort, self.seqNum, self.ackNum)
            ackPacket.setFlags(["ack"])
            self.sendPacket(ackPacket, getResponse=False)
            return TCP.Packet.decode(packet)

    def close(self):
        self.internetLayer.close()

    class Packet(object):
        """

        """
        MANDATORY_SECTIONS = ["srcPort", "dstPort", "seqNum", "ackNum", "length", "flags", "winSize", "checksum", "urg"]
        BINARY_ONLY_VALUES = ["flags", "checksum"]
        FLAGS = {"cwr": b'\x80', "ece": b'\x40', "urg": b'\x20', "ack": b'\x10', "psh": b'\x08', "rst": b'\x04',
                 "syn": b'\x02', "fin": b'\x01'}
        MEM_MAP = {"srcPort": [2, 0], "dstPort": [2, 2], "seqNum": [4, 4], "ackNum": [4, 8], "length": [1, 12],
                   "flags": [1, 13], "winSize": [2, 14], "checksum": [2, 16], "urg": [2, 18]}
        LENGTH = 5  # Default TCP header length is 5 (measured in 32-bit words)
        DEFAULT_WINDOW_SIZE = 1
        DEFAULT_URGENCY = 1

        def __init__(self):
            self.data = bytes(0)  # Bytes of data only (does not include header!)
            self.header = {}

        def create(self, srcPort, dstPort, seqNum, ackNum):
            """
            @srcPort
            """
            assert (isinstance(srcPort, int))
            assert (isinstance(dstPort, int))
            assert (isinstance(seqNum, int))
            assert (isinstance(ackNum, int))

            self.header = {"srcPort": srcPort, "dstPort": dstPort, "seqNum": seqNum, "ackNum": ackNum,
                           "length": TCP.Packet.LENGTH, "flags": b'\x00', "winSize": TCP.Packet.DEFAULT_WINDOW_SIZE,
                           "checksum": b'\x00\x00', "urg": TCP.Packet.DEFAULT_URGENCY}

        def encode(self):
            rawHeader = bytes(0)
            # Mandatory TCP header segments
            for segment in TCP.Packet.MANDATORY_SECTIONS:
                if segment in TCP.Packet.BINARY_ONLY_VALUES:
                    rawHeader += self.header[segment]
                elif "length" == segment:
                    length = self.header[segment] << 4
                    rawHeader += length.to_bytes(TCP.Packet.MEM_MAP[segment][0], "big")
                else:
                    rawHeader += self.header[segment].to_bytes(TCP.Packet.MEM_MAP[segment][0], "big")

            return rawHeader + self.data

        @staticmethod
        def decode(data):
            assert (isinstance(data, bytes))
            assert (TCP.MINIMUM_HEADER_SIZE <= len(data))

            # Instantiate an empty packet
            newTcpGram = TCP.Packet()

            # Loop through each required header segment...
            for segment in TCP.Packet.MEM_MAP:
                # Determine which bytes constitute that segment and store them
                start = TCP.Packet.MEM_MAP[segment][1]
                end = start + TCP.Packet.MEM_MAP[segment][0]
                newTcpGram.header[segment] = data[start:end]

                # And do some other ugly things when necessary
                if segment in TCP.Packet.BINARY_ONLY_VALUES:
                    logging.getLogger(__name__).debug(
                        "TCP.Packet.decode(): Decoding " + segment + ": " + str(data[start:end]))
                else:
                    newTcpGram.header[segment] = int.from_bytes(newTcpGram.header[segment], "big")
                    if "length" == segment:
                        newTcpGram.header[segment] >>= 4
                    logging.getLogger(__name__).debug(
                        "TCP.Packet.decode(): Decoding " + segment + ": " + str(data[start:end]) + " ==> " + str(
                            newTcpGram.header[segment]))

            # NOTE: No optional section allowed!

            # Save the data section
            newTcpGram.data = data[TCP.MINIMUM_HEADER_SIZE:]

            return newTcpGram

        def getSegment(self, segment):
            assert (isinstance(segment, str))

            return self.header[segment]

        def setFlags(self, flags):
            assert (isinstance(flags, list))

            for flag in flags:
                try:
                    assert (isinstance(flag, str) and flag in TCP.Packet.FLAGS)
                    self.header["flags"] = pack('<B',
                                                TCP.Packet.unpackByte(self.header["flags"]) | TCP.Packet.unpackByte(
                                                    TCP.Packet.FLAGS[flag]))
                except AssertionError:
                    if isinstance(flag, str):
                        stderr.write("TCP Error: Flag does not exist: " + flag + "\n")
                    else:
                        stderr.write("TCP Error: " + str(flag) + " isn't a flag!!!\n")

        def getFlags(self):
            flags = []

            for flag in TCP.Packet.FLAGS:
                if TCP.Packet.unpackByte(TCP.Packet.FLAGS[flag]) & TCP.Packet.unpackByte(self.header["flags"]):
                    flags.append(flag)

            return flags

        def addData(self, data):
            assert isinstance(data, bytes)

            self.data += data

        def getData(self):
            return self.data

        def __eq__(self, other):
            if type(self) != type(other):
                return False

            # Check for equal lengths
            if len(self.encode()) != len(other.encode()):
                # NOTE: Not an efficient first test... but easy
                logging.getLogger(__name__).debug("TCP.Packet.__eq__(): Failed equality check at encoded lengths")
                return False

            # Check for equal data sections
            if self.data != other.data:
                logging.getLogger(__name__).debug("TCP.Packet.__eq__(): Failed equality check at TCP.Packet.data")
                return False

            # Check for equal header sections
            for segment in self.header:
                if self.header[segment] != other.header[segment]:
                    logging.getLogger(__name__).debug(
                        "TCP.Packet.__eq__(): Failed equality check at TCP.Packet.header[" + segment + ']')
                    logging.getLogger(__name__).info("TCP.Packet.__eq__():\n\tself.header[" + segment + "] = " + str(
                        self.header[segment]) + "\n\tother.header[" + segment + "] = " + str(other.header[segment]))
                    return False

            return True

        def __bool__(self):
            return self.header != {}

        def __str__(self):
            return str(self.header) + '\n' + str(self.data)

        @staticmethod
        def unpackByte(b):
            return unpack('<B', b)[0]


class TcpClient(TCP):
    def __init__(self, srcPort, timeout=TCP.DEFAULT_SOCKET_TIMEOUT):
        super().__init__(srcPort, timeout)
        self.internetLayer = UDPClient()

    def connect(self, dstIPAddress, dstPort):
        """
        Perform three-way handshake consisting of:
            1) Client sends SYN
            2) Server responds with SYN-ACK
            3) Client responds with ACK
        """

        assert (isinstance(dstIPAddress, str))
        assert (isinstance(dstPort, int))

        #noinspection PyBroadException
        try:
            self.dstPort = dstPort
            self.dstAddress = (dstIPAddress, dstPort)

            # Send SYN
            packet = TCP.Packet()
            self.seqNum = 0
            self.ackNum = 0  # Value is ignored in first TCP packet
            packet.create(self.srcPort, self.dstPort, self.seqNum, self.ackNum)
            packet.setFlags(["syn"])
            logging.getLogger(__name__).debug("TcpClient.connect(): Sending SYN packet")
            response = self.sendPacket(packet)

            # If server responded with RST flag, DIE!!!
            if "rst" in response.getFlags():
                raise Exception("TcpClient.connect() error: Server responded with RST flag")

            if not {"syn", "ack"}.issubset(response.getFlags()):
                raise Exception("TcpClient.connect() error: Did not receive SYN-ACK!")
            self.ackNum = response.header["ackNum"] + 1
            self.seqNum += 1
            packet.create(self.srcPort, self.dstPort, self.seqNum, self.ackNum)
            packet.setFlags(["ack"])
            self.internetLayer.sendto(packet.encode(), self.dstAddress)
        except:
            # If an error was thrown, clear the destination fields to indicate unsuccessful connection attempt
            self.dstPort = None
            self.dstAddress = ()
            raise


class TcpServer(TCP):
    def __init__(self, srcPort, timeout=TCP.DEFAULT_SOCKET_TIMEOUT):
        super().__init__(srcPort, timeout)
        self.internetLayer = UDPServer(self.srcPort)

    def recvConnection(self, port=None):
        """
        Perform server-side three-way handshake
        """

        # Initialize some stuff...
        self.internetLayer.socket.setblocking(1)  # Ensure no timeout occurs while waiting for a client connection
        logging.getLogger(__name__).debug("TcpServer.recvConnection(): Waiting on connection...")

        # Wait for the first TCP packet and decode it
        packet, clientAddress = self.internetLayer.recvfrom(TCP.MINIMUM_HEADER_SIZE)
        logging.getLogger(__name__).debug("TcpServer.recvConnection(): Packet received!!! I feel loved!")
        packet = TCP.Packet.decode(packet)

        # If a port was specified, check to ensure the received packet came through the requested port
        if None != port and port != packet.header["srcPort"]:
            # Received packet came from the wrong port, try another connection
            self.recvConnection(port)
        else:
            # If gram wasn't a valid handshake initializer, start over
            if ["syn"] != packet.getFlags():
                logging.getLogger(__name__).info(
                    'TcpServer.recvConnection(): Expecting flags == ["syn"], received ' + str(packet.getFlags()))
                self.recvConnection(port)
            else:
                logging.getLogger(__name__).debug(
                    "TcpServer.recvConnection(): Handshake part 1 complete! Proceeding to "
                    "send SYN-ACK")
                # Handshake initializer was valid, lets read the packet...
                self.dstAddress = clientAddress
                self.dstPort = packet.header["srcPort"]
                self.ackNum = packet.header["seqNum"] + 1
                self.seqNum = 0

                # ... and send a SYN-ACK response
                packet = TCP.Packet()
                packet.create(self.srcPort, self.dstPort, self.seqNum, self.ackNum)
                packet.setFlags(["syn", "ack"])
                response = self.sendPacket(packet)

                # If the three-way connection failed (any flags set other than ACK), send a RST packet
                if ["ack"] != response.getFlags():
                    logging.getLogger(__name__).info(
                        'TcpServer.recvConnection(): Expecting flags == ["ack"], received ' + str(response.getFlags()))
                    packet = TCP.Packet()
                    packet.create(self.srcPort, self.dstPort, self.seqNum, self.ackNum)
                    packet.setFlags(["rst"])
                    self.sendPacket(packet.encode(), getResponse=False)

                logging.getLogger(__name__).debug("TcpServer.recvConnection(): Connection established!")


if "__main__" == __name__:
    raise Exception("File not executable! Try any number of TCP test files from the tests directory!")
