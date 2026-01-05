#ifndef ARP_HEADER_H
#define ARP_HEADER_H

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <string>

struct __attribute__((packed)) ArpHeader
{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t source_mac[6];
    uint32_t source_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;

    int hardwareType() const { return ntohs(htype); };
    int protocolType() const { return ntohs(ptype); };
    int hardwareLength() const { return hlen; };
    int protocolLength() const { return plen; };
    int operation() const { return ntohs(oper); };

    std::string sourceMacStr() const
    {
        return ether_ntoa((const struct ether_addr*)&source_mac);
    }
    std::string sourceIpStr() const
    {
        char buf[16];
        inet_ntop(AF_INET, &source_ip, buf, sizeof(buf));
        return buf;
    }

    std::string targetMacStr() const
    {
        return ether_ntoa((const struct ether_addr*)&target_mac);
    }
    std::string targetIpStr() const
    {
        char buf[16];
        inet_ntop(AF_INET, &target_ip, buf, sizeof(buf));
        return buf;
    }
};

#endif