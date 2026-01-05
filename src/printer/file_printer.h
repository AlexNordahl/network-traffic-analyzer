#ifndef FILE_PRINTER_H
#define FILE_PRINTER_H

#include <iostream>

#include "printer.h"

class FilePrinter : public Printer
{
public:
    void printEthernet(const EtherFrame& frame) const override;
    void printARP(const ArpHeader& header) const override;
    void printIPV4(const IpHeader& header) const override;
    void printTCP(const TcpHeader& header) const override;
    void printUDP(const UdpHeader& header) const override;
    void printICMP(const IcmpHeader& header) const override;
    void printDNS(const DnsHeader& header) const override;

private:
};

#endif