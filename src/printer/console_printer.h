#ifndef CONSOLE_PRINTER_H
#define CONSOLE_PRINTER_H

#include <iomanip>
#include <iostream>

#include "../helpers/readable_protocols.h"
#include "../net_headers/all_net_headers.h"
#include "printer.h"

class ConsolePrinter : public Printer
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