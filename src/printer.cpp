#include "printer.h"

using std::setw;
using std::left;

void printEthernetFrame(const EtherFrame &frame)
{

    std::cout << "┌───────────────────────────────────────────────────┐\n";
    std::cout << "│ "
              << left << setw(17) << "DST"
              << left << setw(17) << "SRC"
              << left << setw(10) << "TYPE"
              << left << setw(4)  << "DATA  │" 
              << "\n";

    std::cout << "│ "
              << left << setw(17) << frame.destStr()
              << left << setw(17) << frame.sourceStr()
              << left << setw(10) << frame.typeStr()
              << left << setw(4) << frame.getPayloadLen()
              << "  │" << "\n";
    std::cout << "└───────────────────────────────────────────────────┘\n";
}

void printIPV4(const IpHeader& header)
{
    std::cout << "┌───────────────────────────────────────────────────┐\n";
    std::cout << "│ "
              << left << setw(10) << "VERSION"
              << left << setw(10) << "IHL"
              << left << setw(10) << "TOS"
              << left << setw(10) << "TOTAL LENGTH        │"
              << "\n";
    std::cout << "│ "
            << left << setw(10) << header.versionStr()
            << left << setw(10) << header.strIHL()
            << left << setw(10) << "None"
            << left << setw(18) << header.totalLength()
            << "  │" << "\n";
    std::cout << "└───────────────────────────────────────────────────┘\n";
}