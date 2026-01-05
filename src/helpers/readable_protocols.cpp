#include "readable_protocols.h"

std::string protocolKeyword(const int decimal)
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

std::string arpOperation(const int decimal)
{
    switch (decimal)
    {
        case 1:
            return "REQUEST";
        case 2:
            return "REPLY";
        case 3:
            return "RA-REQ";
        case 4:
            return "RA-REP";
        case 8:
            return "IA-REQ";
        case 9:
            return "IA-REP";
        default:
            return "?";
    }
}

std::vector<std::string> tcpFlags(const unsigned long long decimal)
{
    const std::bitset<8> bset{decimal};
    const std::array<std::string, 8> flags{"FIN", "SYN", "RST", "PSH",
                                           "ACK", "URG", "ECE", "CWR"};

    std::vector<std::string> result{};
    result.reserve(flags.size());
    for (size_t i = 0; i < 8; ++i)
    {
        if (bset[i]) result.push_back(flags[i]);
    }

    return result;
}

std::vector<std::string> dnsFlags(const unsigned long long decimal)
{
    const std::bitset<16> bset{decimal};
    std::vector<std::string> result{};
    result.reserve(10);

    const std::array<std::string, 7> opcode{"QUERY",  "IQUERY", "STATUS", "",
                                            "NOTIFY", "UPDATE", "DSO"};

    const std::array<std::string, 6> rcode{"NOERROR",  "FORMERR", "SERVFAIL",
                                           "NXDOMAIN", "NOTIMP",  "REFUSED"};

    result.push_back(bset[15] == 0 ? "QUERY" : "RESP");

    const auto flags = static_cast<uint16_t>(decimal);
    const uint16_t opcodeVal = (flags >> 11) & 0xF;
    result.push_back("OPCODE=" + opcode[opcodeVal]);

    if (bset[10]) result.push_back("AA");
    if (bset[9]) result.push_back("TC");
    if (bset[8]) result.push_back("RD");
    if (bset[7]) result.push_back("RA");
    if (bset[6]) result.push_back("Z");
    if (bset[5]) result.push_back("AD");
    if (bset[4]) result.push_back("CD");

    const uint16_t rcodeVal = flags & 0xF;
    result.push_back("RCODE=" + rcode[rcodeVal]);

    result.shrink_to_fit();
    return result;
}