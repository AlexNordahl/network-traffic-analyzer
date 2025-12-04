#ifndef READABLE_PROTOCOLS_H
#define READABLE_PROTOCOLS_H

#include <bitset>
#include <array>

std::string toKeyword(const int decimal)
{
    switch (decimal)
    {
    case 1:
        return "ICMP";
    case 2:
        return "IGMP";
    case 4:
        return "IPV4";
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    case 41:
        return "IPV6";
    case 47:
        return "GRE";
    case 50:
        return "ESP";
    case 51:
        return "AH";
    case 89:
        return "OSPF";
    default:
        return "?";
    }
}

std::string tcpFlags(const unsigned long long decimal)
{
    const std::bitset<8> bset {decimal};
    const std::array<std::string, 8> flags {
        "FIN", "SYN", "RST", "PSH",
        "ACK", "URG", "ECE", "CWR"
    };
    
    std::string result {};
    for (size_t i = 0; i < 8; ++i)
    {
        if (bset[i])
        {
            if (!result.empty())
                result += "|";
            result += flags[i];
        }
    }

    return result;
}

#endif