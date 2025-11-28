#ifndef ETHER_FRAME
#define ETHER_FRAME

#include <string>
#include <arpa/inet.h>
#include <netinet/ether.h>

struct EtherFrame
{
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t type;

    std::string destStr() const { return ether_ntoa((const struct ether_addr *)&destination); };
    std::string sourceStr() const { return ether_ntoa((const struct ether_addr *)&source); };
    std::string typeStr() const
    {
        switch (type)
        {
        case ETHERTYPE_IP: return "IP";
        case ETHERTYPE_IPV6: return "IPV6";
        case ETHERTYPE_ARP: return "ARP";
        case ETHERTYPE_LOOPBACK: return "LOOPBACK";
        default: return "?";
        }
    }
};

#endif