#ifndef TCP_HEADER
#define TCP_HEADER

#include <string>
#include <arpa/inet.h>
#include <netinet/ether.h>

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
    uint16_t urg_pointer;
};

#endif