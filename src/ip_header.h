#ifndef IP_HEADER
#define IP_HEADER

#include <string>
#include <arpa/inet.h>
#include <netinet/ether.h>

struct IpHeader
{
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t identification;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source;
    uint32_t destination;

    int versionStr() const { return ver_ihl >> 4; };
    int strIHL() const { return ver_ihl & 0x0F; };

    int totalLength() const { return ntohs(total_len); }
    int id() const { return ntohs(identification); }

    int flags() const { return ntohs(offset) >> 13; }
    int fragOffset() const { return ntohs(offset) & 0x1FFF; }

    bool flag_DF() const { return flags() & 0x2; }
    bool flag_MF() const { return flags() & 0x1; }

    int getTTL() const { return ttl; }
    int getProtocol() const { return protocol; }
    
    uint16_t getChecksum() const { return ntohs(checksum); }

    std::string srcStr() const
    {
        char buf[16];
        inet_ntop(AF_INET, &source, buf, sizeof(buf));
        return buf;
    }

    std::string dstStr() const
    {
        char buf[16];
        inet_ntop(AF_INET, &destination, buf, sizeof(buf));
        return buf;
    }
};

#endif