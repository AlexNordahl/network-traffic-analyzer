#include "console_printer.h"

#include "../helpers/ansi_colors.h"

using std::left;
using std::setw;

void ConsolePrinter::printEthernet(const EtherFrame& frame) const
{
    const auto protocolColor = ansi::bright_magenta;
    const auto fieldsColor = ansi::bright_blue;
    const auto valuesColor = ansi::white;

    std::cout << "┌───────────────────────────────────────────────────┐\n";
    std::cout << "│ ";

    std::cout << protocolColor << left << setw(49) << "ETHERNET" << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(18) << "TARGET" << left << setw(18)
              << "SOURCE" << left << setw(9) << "TYPE" << left << "DATA"
              << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(18) << frame.destStr() << left
              << setw(18) << frame.sourceStr() << left << setw(9)
              << frame.typeStr() << left << setw(4) << frame.getPayloadLen()
              << ansi::reset << " │\n";

    std::cout << "├───────────────────────────────────────────────────┤\n";
}

void ConsolePrinter::printARP(const ArpHeader& header) const
{
    const auto protocolColor = ansi::purple;
    const auto fieldsColor = ansi::bright_blue;
    const auto valuesColor = ansi::white;

    std::cout << "│ ";
    std::cout << protocolColor << left << setw(49) << "ARP" << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(9) << "HTYPE" << left << setw(9)
              << "PTYPE" << left << setw(9) << "HLEN" << left << setw(9)
              << "PLEN" << left << setw(13) << "OPER" << ansi::reset << " │\n";

    const std::string arpOper{std::to_string(header.operation()) + " (" +
                              arpOperation(header.operation()) + ")"};
    std::cout << "│ ";
    std::cout << valuesColor << left << setw(9) << header.hardwareType()
              << std::showbase << std::hex << left << setw(9)
              << header.protocolType() << std::noshowbase << std::dec << left
              << setw(9) << header.hardwareLength() << left << setw(9)
              << header.protocolLength() << left << setw(13) << arpOper
              << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(18) << "SOURCE MAC" << left
              << setw(31) << "SOURCE ADDRESS" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(18) << header.sourceMacStr()
              << left << setw(31) << header.sourceIpStr() << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(18) << "TARGET MAC" << left
              << setw(31) << "TARGET ADDRESS" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(18) << header.targetMacStr()
              << left << setw(31) << header.targetIpStr() << ansi::reset
              << " │\n";

    std::cout << "└───────────────────────────────────────────────────┘\n";
}

void ConsolePrinter::printIPV4(const IpHeader& header) const
{
    const auto protocolColor = ansi::blue;
    const auto fieldsColor = ansi::bright_blue;
    const auto valuesColor = ansi::white;

    std::cout << "│ ";
    std::cout << protocolColor << left << setw(49) << "IP" << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(10) << "VERSION" << left
              << setw(10) << "IHL" << left << setw(10) << "TOS" << left
              << setw(19) << "TOTAL LENGTH" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(10) << header.versionStr() << left
              << setw(10) << header.strIHL() << left << setw(10) << "---"
              << left << setw(19) << header.totalLength() << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(20) << "IDENTIFICATION" << left
              << setw(10) << "FLAGS" << left << setw(19) << "FRAGMENT OFFSET"
              << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(20) << header.id() << left
              << setw(10) << header.flags() << left << setw(19)
              << header.fragOffset() << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(20) << "TIME TO LIVE" << left
              << setw(10) << "PROTOCOL" << left << setw(19) << "CHECKSUM"
              << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(20) << header.getTTL() << left
              << setw(10) << protocolKeyword(header.getProtocol()) << left
              << setw(19) << header.getChecksum() << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(20) << "SOURCE ADDRESS" << left
              << setw(29) << "DESTINATION ADDRESS" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(20) << header.srcStr() << left
              << setw(29) << header.dstStr() << ansi::reset << " │\n";

    std::cout << "├───────────────────────────────────────────────────┤\n";
}

void ConsolePrinter::printTCP(const TcpHeader& header) const
{
    const auto protocolColor = ansi::bright_red;
    const auto fieldsColor = ansi::bright_blue;
    const auto valuesColor = ansi::white;

    std::cout << "│ ";
    std::cout << protocolColor << left << setw(49) << "TCP" << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(24) << "SOURCE PORT" << left
              << setw(25) << "DESTINATION PORT" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(24) << header.sourcePort() << left
              << setw(25) << header.destPort() << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(24) << "SEQUENCE NUMBER" << left
              << setw(25) << "ACK NUMBER" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(24) << header.seq() << left
              << setw(25) << header.ack() << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(24) << "HDR LEN (bytes)" << left
              << setw(25) << "FLAGS" << ansi::reset << " │\n";

    const auto flags = tcpFlags(header.flags);
    std::string firstLine{};
    std::string secondLine{};
    for (size_t i = 0; i < flags.size(); ++i)
    {
        if (i >= 4)
        {
            if (!secondLine.empty()) secondLine += "|";
            secondLine += flags.at(i);
            continue;
        }

        if (!firstLine.empty()) firstLine += "|";
        firstLine += flags.at(i);
    }

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(24) << header.headerLengthBytes()
              << left << setw(25) << firstLine << ansi::reset << " │\n";

    std::cout << "└───────────────────────────────────────────────────┘\n";
}

void ConsolePrinter::printUDP(const UdpHeader& header) const
{
    const auto protocolColor = ansi::bright_yellow;
    const auto fieldsColor = ansi::bright_blue;
    const auto valuesColor = ansi::white;

    std::cout << "│ ";
    std::cout << protocolColor << left << setw(49) << "UDP" << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(24) << "SOURCE PORT" << left
              << setw(25) << "DESTINATION PORT" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(24) << header.sourcePort() << left
              << setw(25) << header.destPort() << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(24) << "LENGTH" << left << setw(25)
              << "CHECKSUM" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(24) << header.length() << left
              << setw(25) << header.checksum() << ansi::reset << " │\n";

    std::cout << "├───────────────────────────────────────────────────┤\n";
}

void ConsolePrinter::printICMP(const IcmpHeader& header) const
{
    const auto protocolColor = ansi::bright_cyan;
    const auto fieldsColor = ansi::bright_blue;
    const auto valuesColor = ansi::white;

    std::cout << "│ ";
    std::cout << protocolColor << left << setw(49) << "ICMP" << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(20) << "TYPE" << left << setw(20)
              << "CODE" << left << setw(9) << "CHECKSUM" << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(20) << header.getType() << left
              << setw(20) << header.getCode() << left << setw(9)
              << header.getChecksum() << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(20) << "IDENTIFIER" << left
              << setw(29) << "SEQUENCE" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(20) << header.getIdentifier()
              << left << setw(29) << header.getSequence() << ansi::reset
              << " │\n";

    std::cout << "└───────────────────────────────────────────────────┘\n";
}

void ConsolePrinter::printDNS(const DnsHeader& header) const
{
    const auto protocolColor = ansi::bright_green;
    const auto fieldsColor = ansi::bright_blue;
    const auto valuesColor = ansi::white;

    std::cout << "│ ";
    std::cout << protocolColor << left << setw(49) << "DNS" << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(24) << "ID" << left << setw(25)
              << "FLAGS" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << std::left << std::setw(24) << header.getId()
              << ansi::reset;

    const auto flags = dnsFlags(header.getFlags());

    std::size_t counter = 0;
    std::string buffer;
    bool firstLine = true;

    for (std::size_t i = 0; i < flags.size(); ++i)
    {
        if (!buffer.empty()) buffer += '|';

        buffer += flags[i];
        ++counter;

        const bool lastItem = (i == flags.size() - 1);

        if (counter == 3 or lastItem)
        {
            if (firstLine)
            {
                std::cout << valuesColor;
                std::cout << std::left << std::setw(25) << buffer << ansi::reset
                          << " │\n";
                firstLine = false;
            }
            else
            {
                std::cout << "│ ";
                std::cout << valuesColor << std::left << std::setw(24) << ""
                          << std::left << std::setw(25) << buffer << ansi::reset
                          << " │\n";
            }

            buffer.clear();
            counter = 0;
        }
    }

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(24) << "QUESTION COUNT" << left
              << setw(25) << "ANSWER COUNT" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(24) << header.getQuestionCount()
              << left << setw(25) << header.getAnswerCount() << ansi::reset
              << " │\n";

    std::cout << "│ ";
    std::cout << fieldsColor << left << setw(24) << "AUTH COUNT" << left
              << setw(25) << "ADDITIONAL COUNT" << ansi::reset << " │\n";

    std::cout << "│ ";
    std::cout << valuesColor << left << setw(24) << header.getAuthCount()
              << left << setw(25) << header.getAdditionalCount() << ansi::reset
              << " │\n";

    std::cout << "└───────────────────────────────────────────────────┘\n";
}