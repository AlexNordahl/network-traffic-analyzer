#include <iostream>
#include <optional>

#include "arguments_handler.h"
#include "pcap_facade/pcap_facade.h"
#include "printer/console_printer.h"
#include "printer/file_printer.h"

constexpr int snaplen_max = 65535;
constexpr int timeout_ms = 1000;

int main(int argc, char const* argv[])
{
    PcapFacade pf;

    validateArgv(argc, argv);

    auto device = selectDeviceArgument(argc, argv);
    if (device.has_value())
    {
        pf.selectDevice(device.value());
        std::cout << "Selected device: " << device.value() << "\n";
    }
    else
    {
        pf.autoSelectDevice();
        std::cout << "Auto selected device: " << pf.listAllDevices().at(0)
                  << "\n";
    }

    pf.configure(snaplen_max, true, timeout_ms);
    pf.activate();

    if (listDevicesArgument(argc, argv))
    {
        for (const auto& dev : pf.listAllDevices()) std::cout << dev << "\n";
    }

    if (auto filter = filterArgument(argc, argv); filter.has_value())
    {
        pf.setFilter(filter.value().c_str());
    }

    const ConsolePrinter printer{};
    while (true)
    {
        const auto [frame, payload] = pf.next();
        parseAndPrint(frame, payload, printer);
        std::cout << "\n";
    }
}