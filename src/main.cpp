#include <iostream>
#include "pcap_facade.h"
#include "printer.h"

int main()
{
    PcapFacade pf;
    pf.autoSelectDevice();

    std::cout << "Device: " << pf.getSelectedDevice() << "\n";
    std::cout << "IPv4: " << pf.getIPv4() << "\n";
    std::cout << "Mask: " << pf.maskToCIDR(pf.getMask()) << "\n";

    pf.configure(65535, true, 1000);
    pf.activate();

    while (true)
    {
        const auto [frame, payload] = pf.next();

        printEthernetFrame(frame);
        if (frame.type == ETHERTYPE_IP)
        {
            const auto [header, ipData] = pf.parseIPV4(payload);
            printIPV4(header);

            switch (header.protocol)
            {
                case IPPROTO_TCP:
                {
                    const auto [header, tcpData] = pf.parseTCP(ipData);
                    printTCP(header);
                    break;
                }

                case IPPROTO_UDP:
                {
                    const auto [header, udpData, dataLen] = pf.parseUDP(ipData);
                    printUDP(header);

                    if (header.destPort() == 53)
                    {
                        const auto dns = pf.parseDNS(udpData);
                        printDNS(dns);
                    }

                    break;
                }

                case IPPROTO_ICMP:
                {
                    const auto header = pf.parseICMP(ipData);
                    printICMP(header);
                    break;
                }

                default: break;
            }
        }
        std::cout << "\n";
    }
    
    return 0;
}