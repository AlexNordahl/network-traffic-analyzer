#ifndef PARSERS_H
#define PARSERS

#include "../net_headers/all_net_headers.h"
#include "cstring"
#include "utility"

struct ParsedUDP
{
    UdpHeader header;
    const u_char* data;
    const int dataLen;
};

std::pair<IpHeader, const u_char*> parseIPV4(const u_char* data);
std::pair<TcpHeader, const u_char*> parseTCP(const u_char* data);
ParsedUDP parseUDP(const u_char* data);
IcmpHeader parseICMP(const u_char* data);
ArpHeader parseARP(const u_char* data);
DnsHeader parseDNS(const u_char* data);

#endif