#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <string>

struct __attribute__((packed)) IcmpHeader
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    uint16_t identifier;
    uint16_t sequence;

    int getType() const { return type; }
    int getCode() const { return code; }
    int getChecksum() const { return ntohs(checksum); }
    int getIdentifier() const { return ntohs(identifier); }
    int getSequence() const { return ntohs(sequence); }
};

#endif