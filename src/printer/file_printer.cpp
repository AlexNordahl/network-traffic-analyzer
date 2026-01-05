#include "file_printer.h"

void FilePrinter::printEthernet([[maybe_unused]] const EtherFrame& frame) const
{
    std::cout << "Ethernet saved\n";
}

void FilePrinter::printARP([[maybe_unused]] const ArpHeader& header) const
{
    std::cout << "ARP saved\n";
}

void FilePrinter::printIPV4([[maybe_unused]] const IpHeader& header) const
{
    std::cout << "IPV4 saved\n";
}

void FilePrinter::printTCP([[maybe_unused]] const TcpHeader& header) const
{
    std::cout << "TCP saved\n";
}

void FilePrinter::printUDP([[maybe_unused]] const UdpHeader& header) const
{
    std::cout << "UDP saved\n";
}

void FilePrinter::printICMP([[maybe_unused]] const IcmpHeader& header) const
{
    std::cout << "ICMP saved\n";
}

void FilePrinter::printDNS([[maybe_unused]] const DnsHeader& header) const
{
    std::cout << "DNS saved\n";
}