#include <iostream>
#include "pcap_facade.h"

int main()
{
    PcapFacade pf;
    pf.autoSelectDevice();

    std::cout << "Device: " << pf.getSelectedDevice() << "\n";
    std::cout << "IPv4: " << pf.getIPv4() << "\n";
    std::cout << "Mask: " << pf.getMask() << "\n";

    pf.configure(65535, true, 1000);
    pf.activate();

    while (true)
    {
        std::cout << pf.next_packet() << "\n";
    }
    
    return 0;
}