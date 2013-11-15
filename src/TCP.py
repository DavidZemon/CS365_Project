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

from src.UDP import UDPClient, UDPServer

__author__ = 'david'

MAX_PACKET_SEND_ATTEMPTS = 5
DEFAULT_SOCKET_TIMEOUT = 10  # Timeout for blocking socket calls (in seconds)
SIMPLE_PACKET_BUFFER = 20  # Bytes required to receive a simple TCP packet (header only); Default = 20


class TCP(object):
    def __init__(self, srcPort, timeout=DEFAULT_SOCKET_TIMEOUT):
        assert (isinstance(srcPort, int))
        assert (isinstance(timeout, (int, float, complex)))

        self.srcPort = srcPort
        self.connected = False
        self.dstPort = None  # Integer representing destination port number
        self.udp = None
        self.dstAddress = ()
        self.timeout = timeout

    def sendPacket(self, packet, attempt=0, getResponse=True):
        assert (isinstance(packet, TcpGram))
        assert (isinstance(attempt, int))

        if attempt == MAX_PACKET_SEND_ATTEMPTS:
            raise Exception("TcpClient.sendPacket() error: server response error")

        logging.getLogger(__name__).debug("TCP.sendPacket(): Attempt #" + str(attempt))

        self.udp.sendto(packet.encode(), self.dstAddress)

        if getResponse:
            # Wait for a response...
            recvAddress = None  # Init recvAddress for while loop
            response = None
            startTime = time()  # Get current system time
            while recvAddress != self.dstAddress:  # Try and try again until we receive from the correct address
                self.udp.socket.settimeout(self.timeout + startTime - time())  # Update timeout to be 20 seconds after
                # TODO: Confirm that SIMPLE_PACKET_BUFFER bytes is enough; Is it worth adding wiggle room?
                logging.getLogger(__name__).debug("TCP.sendPacket(): Waiting on ACK from " + str(self.dstAddress))
                response, recvAddress = self.udp.recvfrom(SIMPLE_PACKET_BUFFER)
                logging.getLogger(__name__).debug("TCP.sendPacket(): Received packet from " + str(recvAddress))

            # Receive a packet
            response = TcpGram.decode(response)

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
        self.udp = UDPClient()

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
            ackNum = response.header["ackNum"] + 1
            seqNum += 1
            packet.create(self.srcPort, self.dstPort, seqNum, ackNum)
            packet.setFlags(["ack"])
            self.udp.sendto(packet.encode(), self.dstAddress)
        except:
            # If an error was thrown, clear the destination fields to indicate unsuccessful connection attempt
            self.dstPort = None
            self.dstAddress = ()
            raise


class TcpServer(TCP):
    def __init__(self, srcPort, timeout=DEFAULT_SOCKET_TIMEOUT):
        super(TcpServer, self).__init__(srcPort, timeout)
        self.udp = UDPServer(self.srcPort)

    def recvConnection(self):
        """
        Perform server-side three-way handshake
        """

        # Initialize some stuff...
        self.udp.socket.setblocking(1)  # Ensure no timeout occurs while waiting for a client connection
        logging.getLogger(__name__).debug("TcpServer.recvConnection(): Waiting on connection...")

        # Wait for the first TCP gram and decode it
        packet, clientAddress = self.udp.recvfrom(SIMPLE_PACKET_BUFFER)
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
            response = self.sendPacket(packet)

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
                       "length": TcpGram.LENGTH, "flags": b'\x00', "winSize": TcpGram.DEFAULT_WINDOW_SIZE,
                       "checksum": b'\x00\x00', "urg": TcpGram.DEFAULT_URGENCY}

    def encode(self):
        rawHeader = bytes(0)
        # Mandatory TCP header segments
        for segment in TcpGram.MANDATORY_SECTIONS:
            if segment in TcpGram.BINARY_ONLY_VALUES:
                rawHeader += self.header[segment]
            elif "length" == segment:
                length = self.header[segment] << 4
                rawHeader += length.to_bytes(TcpGram.MEM_MAP[segment][0], "big")
            else:
                rawHeader += self.header[segment].to_bytes(TcpGram.MEM_MAP[segment][0], "big")

        # Optional TCP header segments
        pass  # TODO: Do me!

        return rawHeader + self.data

    @staticmethod
    def decode(data):
        assert (isinstance(data, bytes))
        #assert (SIMPLE_PACKET_BUFFER <= len(data))   # TODO: Uncomment this line when shit is working again

        newTcpGram = TcpGram()

        for segment in TcpGram.MEM_MAP:
            start = TcpGram.MEM_MAP[segment][1]
            end = start + TcpGram.MEM_MAP[segment][0]
            newTcpGram.header[segment] = data[start:end]

            if segment in TcpGram.BINARY_ONLY_VALUES:
                logging.getLogger(__name__).debug("TcpGram.decode(): Decoding " + segment + ": " + str(data[start:end]))
            else:
                newTcpGram.header[segment] = int.from_bytes(newTcpGram.header[segment], "big")
                if "length" == segment:
                    newTcpGram.header[segment] >>= 4
                logging.getLogger(__name__).debug(
                    "TcpGram.decode(): Decoding " + segment + ": " + str(data[start:end]) + " ==> " + str(
                        newTcpGram.header[segment]))

        return newTcpGram

    def getSegment(self, segment):
        assert (isinstance(segment, str))

        return self.header[segment]

    def setFlags(self, flags):
        assert (isinstance(flags, list))

        for flag in flags:
            try:
                assert (isinstance(flag, str) and flag in TcpGram.FLAGS)
                self.header["flags"] = pack('<B', unpackByte(self.header["flags"]) | unpackByte(TcpGram.FLAGS[flag]))
            except AssertionError:
                if isinstance(flag, str):
                    stderr.write("TCP Error: Flag does not exist: " + flag + "\n")
                else:
                    stderr.write("TCP Error: " + str(flag) + " isn't a flag!!!\n")

    def getFlags(self):
        flags = []

        for flag in TcpGram.FLAGS:
            if unpackByte(TcpGram.FLAGS[flag]) & unpackByte(self.header["flags"]):
                flags.append(flag)

        return flags

    def addData(self, data):
        assert isinstance(data, bytes)

        self.data += data

    def __eq__(self, other):
        # Check for equal lengths
        if len(self.encode()) != len(other.encode()):
            # NOTE: Not an efficient first test... but easy
            logging.getLogger(__name__).debug("TcpGram.__eq__(): Failed equality check at encoded lengths")
            return False

        # Check for equal data sections
        if self.data != other.data:
            logging.getLogger(__name__).debug("TcpGram.__eq__(): Failed equality check at TcpGram.data")
            return False

        # Check for equal header sections
        for segment in self.header:
            if self.header[segment] != other.header[segment]:
                logging.getLogger(__name__).debug(
                    "TcpGram.__eq__(): Failed equality check at TcpGram.header[" + segment + ']')
                logging.getLogger(__name__).info("TcpGram.__eq__():\n\tself.header[" + segment + "] = " + str(
                    self.header[segment]) + "\n\tother.header[" + segment + "] = " + str(other.header[segment]))
                return False

        return True


def unpackByte(b):
    return unpack('<B', b)[0]


if "__main__" == __name__:
    raise Exception("File not executable! Try any number of TCP test files from the tests directory!")
