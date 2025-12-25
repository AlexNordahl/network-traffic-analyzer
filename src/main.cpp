#include <iostream>
#include <optional>
#include <chrono>
#include "pcap_facade/pcap_facade.h"
#include "printer/console_printer.h"
#include "printer/file_printer.h"
#include "helpers/parsers.h"
#include "arguments_handler.h"

void parseAndPrintFrame(const EtherFrame& frame, const u_char* payload, const Printer& pr);

constexpr int snaplen_max = 65535;
constexpr int timeout_ms = 1000;

int main(int argc, char const* argv[])
{
    PcapFacade pf;

    auto device = selectDeviceArgument(argc, argv);
    if (device.has_value())
    {
        pf.selectDevice(device.value());
        std::cout << "Selected device: " << device.value() << "\n";
    }
    else
    {
        pf.autoSelectDevice();
        std::cout << "Auto selected device: " << pf.listAllDevices().at(0) << "\n";
    }

    pf.configure(snaplen_max, true, timeout_ms);
    pf.activate();

    if (listDevicesArgument(argc, argv))
    {
        for (const auto& dev : pf.listAllDevices())
            std::cout << dev << "\n";
    }

    auto filter = filterArgument(argc, argv);
    if (filter.has_value())
    {
        pf.setFilter(filter.value().c_str());
    }

    std::cout << "Listening...\n";
    
    const ConsolePrinter printer {};
    while (true)
    {
        const auto [frame, payload] = pf.next();
        parseAndPrintFrame(frame, payload, printer);
        std::cout << "\n";
    }
}

void parseAndPrintFrame(const EtherFrame& frame, const u_char* payload, const Printer& pr)
{
    pr.printEthernet(frame);
    
    if (frame.type == ETHERTYPE_ARP)
    {
        auto arpHeader = parseARP(payload);
        pr.printARP(arpHeader);
    }
    else if (frame.type == ETHERTYPE_IP)
    {
        const auto [header, ipData] = parseIPV4(payload);
        pr.printIPV4(header);

        if (header.fragOffset() > 0)
        {
            return;
        }

        switch (header.protocol)
        {
            case IPPROTO_TCP:
            {
                const auto [header, tcpData] = parseTCP(ipData);
                pr.printTCP(header);
                break;
            }
            case IPPROTO_UDP:
            {
                const auto [header, udpData, dataLen] = parseUDP(ipData);
                pr.printUDP(header);

                if (header.destPort() == 53)
                {
                    const auto dns = parseDNS(udpData);
                    pr.printDNS(dns);
                }
                break;
            }
            case IPPROTO_ICMP:
            {
                const auto header = parseICMP(ipData);
                pr.printICMP(header);
                break;
            }

            default: break;
        }
    }
}