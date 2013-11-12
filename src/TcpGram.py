#/usr/bin/python
# File:    ${file}
# Author:  David Zemon
# Project: Project1
#
# Created with: PyCharm Community Edition

"""
@description:
"""
__author__ = 'david'


class TcpGram(object):
    """

    """

    def __init__(self):
        self.mandatorySections = ["srcPort", "dstPort", "seqNum", "ackNum", "length", "flags", "winSize", "checksum",
                                  "urg"]
        self.binaryOnlyValues = ["flags", "checksum"]
        self.flags = {"cwr": b'\x80', "ece": b'\x40', "urg": b'\x20', "ack": b'\x10', "psh": b'\x08', "rst": b'\x04',
                      "syn": b'\x02', "fin": b'\x01'}
        self.memMap = {"srcPort": [2, 0], "dstPort": [2, 2], "seqNum": [4, 4], "ackNum": [4, 8], "length": [1, 12],
                       "flags": [1, 13], "winSize": [2, 14], "checksum": [2, 16], "urg": [2, 18]}
        self.length = 5  # Default TCP header length is 5 (measured in 32-bit words)
        self.encodedData = bytes(0)
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
                       "length": TcpGram.encodeLength(self.length), "flags": b'\x00', "winSize": b'\x00\x01',
                       "checksum": b'\x00\x00', "urg": b'\x00\x00'}

    def encode(self):
        # Mandatory TCP header segments
        for segment in self.mandatorySections:
            self.encodedData += self.header[segment].to_bytes(self.memMap[segment][0], "big")

        # Optional TCP header segments
        pass  # TODO: Do me!

        return self.encodedData

    def decode(self, data):
        assert (isinstance(data, bytearray))

        for segment in self.memMap:
            start = self.memMap[segment][1]
            end = start + self.memMap[segment][0]
            self.header[segment] = self.encodedData[start:end]

            if segment not in self.binaryOnlyValues:
                self.header[segment] = int.from_bytes(self.header[segment], "big")
                if "length" == segment:
                    self.header[segment] = TcpGram.decodeLength(self.header[segment])

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
        assert isinstance(flags, list)

        for flag in flags:
            self.header["flags"] |= self.flags[flag]

    def addData(self, data):
        assert isinstance(data, bytes)

        self.encodedData += data


if "__main__" == __name__:
    myHeader = TcpGram()
    myHeader.create(15, 8, 0, 64)

    print(myHeader.encode())

    # TODO: Test flags
    # TODO: Test data
