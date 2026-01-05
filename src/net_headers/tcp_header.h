#ifndef TCP_HEADER
#define TCP_HEADER

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <string>

struct __attribute__((packed)) TcpHeader
{
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNumber;
    uint32_t ackNumber;

    uint8_t dataOffset;
    uint8_t flags;

    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgPointer;

    int sourcePort() const { return ntohs(srcPort); }
    int destPort() const { return ntohs(dstPort); }

    uint32_t seq() const { return ntohl(seqNumber); }
    uint32_t ack() const { return ntohl(ackNumber); }

    int headerLengthBytes() const { return (dataOffset >> 4) * 4; }

    bool flag_FIN() const { return flags & 0x01; }
    bool flag_SYN() const { return flags & 0x02; }
    bool flag_RST() const { return flags & 0x04; }
    bool flag_PSH() const { return flags & 0x08; }
    bool flag_ACK() const { return flags & 0x10; }
    bool flag_URG() const { return flags & 0x20; }
    bool flag_ECE() const { return flags & 0x40; }
    bool flag_CWR() const { return flags & 0x80; }

    int window() const { return ntohs(windowSize); }
    int urgPtr() const { return ntohs(urgPointer); }
    int getChecksum() const { return ntohs(checksum); }
};

#endif