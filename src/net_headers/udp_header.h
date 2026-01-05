#ifndef UDP_HEADER_H
#define UDP_HEADER_H

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <string>

struct __attribute__((packed)) UdpHeader
{
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t len;
    uint16_t csum;

    int sourcePort() const { return ntohs(srcPort); }
    int destPort() const { return ntohs(dstPort); }
    int length() const { return ntohs(len); }
    int checksum() const { return ntohs(csum); }
};

#endif