#include "pcap_facade.h"

PcapFacade::PcapFacade()
{
    pcap_findalldevs(&allDevs, errbuf);
}

PcapFacade::~PcapFacade()
{
    pcap_freealldevs(allDevs);
    if (handle != nullptr)
        pcap_close(handle);
}

void PcapFacade::selectDevice(const std::string& devName)
{
    for (auto d = allDevs; d != nullptr; d = d->next)
    {
        if (strcmp(d->name, devName.c_str()))
        {
            selectedDevName = devName;
            selectedDev = d;
            extractIPv4Data();
            return;
        }
    }

    throw std::runtime_error("selectDevice(): device not found");
}

void PcapFacade::autoSelectDevice()
{
    selectedDevName = allDevs->name;
    selectedDev = allDevs;
    extractIPv4Data();
}

void PcapFacade::configure(int snaplen, bool promisc, int timeoutMs)
{   
    if (selectedDevName.empty())
        throw std::runtime_error("configure(): device not selected");

    handle = pcap_create(selectedDevName.c_str(), errbuf);

    if (handle == nullptr)
        throw std::runtime_error("configure(): " + std::string(errbuf));

    if (pcap_set_snaplen(handle, snaplen) < 0)
        throw std::runtime_error("configure(): snaplen error");

    if (pcap_set_promisc(handle, promisc) < 0)
        throw std::runtime_error("configure(): promisc error");

    if (pcap_set_timeout(handle, timeoutMs) < 0)
        throw std::runtime_error("configure(): timeoutMs error");
}

void PcapFacade::activate()
{
    if (handle == nullptr)
        throw std::runtime_error("activate(): handle is null, configure probably not set");

    int code = pcap_activate(handle);

    if (code < 0)
    {
        pcap_close(handle);
        handle = nullptr;
        throw std::runtime_error("activate(): " + std::string(errbuf));
    }
}

std::string PcapFacade::getSelectedDevice() const
{
    return selectedDevName;
}

std::string PcapFacade::getIPv4() const
{
    return ipv4;
}

std::string PcapFacade::getMask() const
{
    return mask;
}

std::vector<std::string> PcapFacade::listAllDevices() const
{
    std::vector<std::string> result {};

    for (auto d = allDevs; d != nullptr; d = d->next)
    {
        result.push_back(d->name);
    }
    
    return result;
}

void PcapFacade::extractIPv4Data()
{
    struct in_addr addr;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    pcap_lookupnet(selectedDevName.c_str(), &netp, &maskp, errbuf);

    addr.s_addr = netp;
    ipv4 = inet_ntoa(addr);

    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
}
