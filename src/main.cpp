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
            printIPV4(pf.parseIPV4(payload));
        }
        std::cout << "\n";
    }
    
    return 0;
}