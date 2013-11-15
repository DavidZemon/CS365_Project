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
from time import time

from src.UDP import UDPClient

__author__ = 'david'

MAX_PACKET_SEND_ATTEMPTS = 5
DEFAULT_SOCKET_TIMEOUT = 10  # Timeout for blocking socket calls (in seconds)
SIMPLE_PACKET_BUFFER = 2048  # Bytes required to receive a simple TCP packet (header only); Default = 20


class TCP(object):
    def __init__(self, srcPort, timeout=DEFAULT_SOCKET_TIMEOUT):
        assert (isinstance(srcPort, int))
        assert (isinstance(timeout, (int, float, complex)))

        self.srcPort = srcPort
        self.connected = False
        self.dstPort = None  # Integer representing destination port number
        self.udpClient = UDPClient()
        self.dstAddress = ()
        self.timeout = timeout

    def sendPacket(self, packet, attempt=0, getResponse=True):
        assert (isinstance(packet, TcpGram))
        assert (isinstance(attempt, int))

        if attempt == MAX_PACKET_SEND_ATTEMPTS:
            raise Exception("TcpClient.sendPacket() error: server response error")

        logging.getLogger(__name__).debug("TCP.sendPacket(): Attempt #" + str(attempt))

        self.udpClient.sendto(self.dstAddress, packet.encode())

        if getResponse:
            # Wait for a response...
            recvAddress = None  # Init recvAddress for while loop
            startTime = time()  # Get current system time
            while recvAddress != self.dstAddress:  # Try and try again until we receive from the correct address
                self.udpClient.socket.settimeout(
                    self.timeout + startTime - time())  # Update timeout to be 20 seconds after
                # TODO: Confirm that SIMPLE_PACKET_BUFFER bytes is enough; Is it worth adding wiggle room?
                logging.getLogger(__name__).debug("TCP.sendPacket(): Waiting on ACK from " + str(self.dstAddress))
                packet, recvAddress = self.udpClient.recvfrom(SIMPLE_PACKET_BUFFER)
                logging.getLogger(__name__).debug("TCP.sendPacket(): Received packet from " + str(recvAddress))

            # Receive a packet
            response = TcpGram.decode(packet)

            # Check for acknowledgement
            if "ack" not in response.getFlags():
                raise Exception("TcpClient.sendPacket() error: response did not ACK")

            # Check for acknowledged seq. # to increment by 1 (if not incremented by 1, try again)
            if response.header["ackNum"] != (packet.header["ackNum"] + 1):
                return self.sendPacket(packet, attempt + 1)
            else:
                return response


class TcpClient(TCP):
    def __init__(self, srcPort, timeout=DEFAULT_SOCKET_TIMEOUT):
        super(TcpClient, self).__init__(srcPort, timeout)

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
            packet = TcpGram()
            seqNum = 0
            ackNum = 0  # Value is ignored in first TCP packet
            packet.create(self.srcPort, self.dstPort, seqNum, ackNum)
            packet.setFlags(["syn"])
            logging.getLogger(__name__).debug("TcpClient.connect(): Sending SYN packet")
            response = self.sendPacket(packet)

            # If server responded with RST flag, DIE!!!
            if "rst" in response.getFlags():
                raise Exception("TcpClient.connect() error: Server responded with RST flag")

            if not {"syn", "ack"}.issubset(response.getFlags()):
                raise Exception("TcpClient.connect() error: Did not receive SYN-ACK!")
            ackNum = unpack('<H', response.header["ackNum"])[0] + 1
            seqNum += 1
            packet.create(self.srcPort, self.dstPort, seqNum, ackNum)
            packet.setFlags("ack")
            self.udpClient.sendto(packet.encode(), self.dstAddress)
        except:
            # If an error was thrown, clear the destination fields to indicate unsuccessful connection attempt
            self.dstPort = None
            self.dstAddress = ()
            raise


class TcpServer(TCP):
    def __init__(self, srcPort, timeout=DEFAULT_SOCKET_TIMEOUT):
        super(TcpServer, self).__init__(srcPort, timeout)

    def recvConnection(self):
        """
        Perform server-side three-way handshake
        """

        # Wait for the first TCP gram and decode it
        self.udpClient.socket.setblocking(1)  # Ensure no timeout occurs while waiting for a client connection
        logging.getLogger(__name__).debug("TcpServer.recvConnection(): Waiting on connection...")
        packet, clientAddress = self.udpClient.recvfrom(SIMPLE_PACKET_BUFFER)
        logging.getLogger(__name__).debug("TcpServer.recvConnection(): Packet received!!! I feel loved!")
        packet = TcpGram.decode(packet)

        # If gram wasn't a valid handshake initializer, start over
        if ["syn"] != packet.getFlags():
            logging.getLogger(__name__).info(
                'TcpServer.recvConnection(): Expecting flags == ["syn"], received ' + str(packet.getFlags()))
            self.recvConnection()
        else:
            logging.getLogger(__name__).debug("TcpServer.recvConnection(): Handshake part 1 complete! Proceeding to "
                                              "send SYN-ACK")
            # Handshake initializer was valid, lets read the packet...
            self.dstAddress = clientAddress
            self.dstPort = packet.header["srcPort"]
            ackNum = packet.header["seqNum"] + 1
            seqNum = 0

            # ... and send a SYN-ACK response
            packet = TcpGram()
            packet.create(self.srcPort, self.dstPort, seqNum, ackNum)
            packet.setFlags(["syn", "ack"])
            response = self.sendPacket(packet.encode())

            # If the three-way connection failed (any flags set other than ACK), send a RST packet
            if ["ack"] != response.getFlags():
                logging.getLogger(__name__).info(
                    'TcpServer.recvConnection(): Expecting flags == ["ack"], received ' + str(response.getFlags()))
                packet = TcpGram()
                packet.create(self.srcPort, self.dstPort, seqNum, ackNum)
                packet.setFlags(["rst"])
                self.sendPacket(packet.encode(), getResponse=False)

            logging.getLogger(__name__).debug("TcpServer.recvConnection(): Connection established!")


class TcpGram(object):
    """

    """

    def __init__(self):
        self.MANDATORY_SECTIONS = ["srcPort", "dstPort", "seqNum", "ackNum", "length", "flags", "winSize", "checksum",
                                   "urg"]
        self.BINARY_ONLY_VALUES = ["flags", "checksum"]
        self.FLAGS = {"cwr": b'\x80', "ece": b'\x40', "urg": b'\x20', "ack": b'\x10', "psh": b'\x08', "rst": b'\x04',
                      "syn": b'\x02', "fin": b'\x01'}
        self.LENGTH = 5  # Default TCP header length is 5 (measured in 32-bit words)
        self.memMap = {"srcPort": [2, 0], "dstPort": [2, 2], "seqNum": [4, 4], "ackNum": [4, 8], "length": [1, 12],
                       "flags": [1, 13], "winSize": [2, 14], "checksum": [2, 16], "urg": [2, 18]}
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

        self.header = {"srcPort": srcPort.to_bytes(2, "big"), "dstPort": dstPort.to_bytes(2, "big"),
                       "seqNum": seqNum.to_bytes(4, "big"), "ackNum": ackNum.to_bytes(4, "big"),
                       "length": TcpGram.encodeLength(self.LENGTH), "flags": b'\x00', "winSize": b'\x00\x01',
                       "checksum": b'\x00\x00', "urg": b'\x00\x00'}

    def encode(self):
        rawHeader = bytes(0)
        # Mandatory TCP header segments
        for segment in self.MANDATORY_SECTIONS:
            rawHeader += self.header[segment]

        # Optional TCP header segments
        pass  # TODO: Do me!

        return rawHeader + self.data

    @staticmethod
    def decode(data):
        assert (isinstance(data, bytearray))
        assert (SIMPLE_PACKET_BUFFER <= len(bytearray))

        newTcpGram = TcpGram()

        for segment in newTcpGram.memMap:
            start = newTcpGram.memMap[segment][1]
            end = start + newTcpGram.memMap[segment][0]
            newTcpGram.header[segment] = newTcpGram.encodedData[start:end]

            if segment not in newTcpGram.BINARY_ONLY_VALUES:
                newTcpGram.header[segment] = int.from_bytes(newTcpGram.header[segment], "big")
                if "length" == segment:
                    newTcpGram.header[segment] = TcpGram.decodeLength(newTcpGram.header[segment])

        return newTcpGram

    @staticmethod
    def encodeLength(length):
        return (length << 4).to_bytes(1, "big")

    @staticmethod
    def decodeLength(length):
        return int.from_bytes(length, "big") >> 4

    def getSegment(self, segment):
        assert (isinstance(segment, str))

        return self.header[segment]

    def setFlags(self, flags):
        assert (isinstance(flags, list))

        for flag in flags:
            try:
                assert (isinstance(flag, str) and flag in self.FLAGS)
                self.header["flags"] = packByte(unpackByte(self.header["flags"]) | unpackByte(self.FLAGS[flag]))
            except AssertionError:
                if isinstance(flag, str):
                    stderr.write("TCP Error: Flag does not exist: " + flag + "\n")
                else:
                    stderr.write("TCP Error: " + str(flag) + " isn't a flag!!!\n")

    def getFlags(self):
        flags = []

        for flag in self.FLAGS:
            if unpackByte(self.FLAGS[flag]) & unpackByte(self.header["flags"]):
                flags.append(flag)

        return flags

    def addData(self, data):
        assert isinstance(data, bytes)

        self.encodedData += data

    def __eq__(self, other):
        equality = True

        if self.data != other.data:
            return False
        else:
            for segment in self.header:
                if self.header[segment] != other.header[segment]:
                    return False


def unpackByte(b):
    return unpack('<B', b)[0]


def packByte(b):
    return pack('<B', b)


if "__main__" == __name__:
    myHeader = TcpGram()
    myHeader.create(15, 8, 0, 64)

    print(myHeader.encode())

    myHeader.setFlags(["syn", "ack"])
    print(myHeader.getFlags())

    # TODO: Test flags
    # TODO: Test data