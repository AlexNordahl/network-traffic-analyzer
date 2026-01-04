#include "parsers.h"

std::pair<IpHeader, const u_char*> parseIPV4(const u_char* data)
{
    IpHeader ip;
    std::memcpy(&ip, data, 20);

    uint8_t ihl = ip.ver_ihl & 0x0F;
    size_t headerLength = ihl * 4;

    const u_char* payload = data + headerLength;

    return {ip, payload};
}

std::pair<TcpHeader, const u_char*> parseTCP(const u_char* data)
{
    // Doesn't take into account tcp headers with options
    TcpHeader tcp;
    std::memcpy(&tcp, data, sizeof(TcpHeader));

    data = data + tcp.headerLengthBytes();

    return {tcp, data};
}

ParsedUDP parseUDP(const u_char *data)
{
    UdpHeader udp;
    std::memcpy(&udp, data, sizeof(UdpHeader));

    data = data + sizeof(udp);
    int length = udp.length() - static_cast<int>(sizeof(udp));

    return {udp, data, length};
}

IcmpHeader parseICMP(const u_char *data)
{
    IcmpHeader icmp;
    std::memcpy(&icmp, data, sizeof(IcmpHeader));

    return icmp;
}

ArpHeader parseARP(const u_char* data)
{
    ArpHeader arp;
    memcpy(&arp, data, sizeof(ArpHeader));

    return arp;
}

DnsHeader parseDNS(const u_char *data)
{
    DnsHeader dns;
    std::memcpy(&dns, data, sizeof(DnsHeader));

    return dns;
}