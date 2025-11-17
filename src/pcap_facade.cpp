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

void PcapFacade::selectDevice(const std::string_view devName)
{
    for (auto d = allDevs; d != nullptr; d = d->next)
    {
        if (strcmp(d->name, devName.data()) == 0)
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
        if (code == PCAP_ERROR_PERM_DENIED)
            throw std::runtime_error("activate(): permission denied, try running as root");    
        pcap_close(handle);
        handle = nullptr;
        throw std::runtime_error("activate(): pcap_activate error");
    }
}

std::string PcapFacade::getSelectedDevice() const { return selectedDevName; }

std::string PcapFacade::getIPv4() const { return ipv4; }

std::string PcapFacade::getMask() const { return mask; }

std::vector<std::string> PcapFacade::listAllDevices() const
{
    std::vector<std::string> result {};

    for (auto d = allDevs; d != nullptr; d = d->next)
    {
        result.push_back(d->name);
    }
    
    return result;
}

void PcapFacade::setFilter(const std::string_view expr)
{

}

std::string PcapFacade::next_packet()
{
    pcap_pkthdr* hdr;
    const u_char* bytes;

    int code = pcap_next_ex(handle, &hdr, &bytes);
    
    if (code == 1) 
    {
        return "packet: len=" + std::to_string(hdr->len) +
               " caplen=" + std::to_string(hdr->caplen) +
               " ts=" + std::to_string(hdr->ts.tv_sec);
    }
    else if (code == 0)
        return "timeout";
    else if (code == -1)
        throw std::runtime_error("pcap_next_ex error");
    else if (code == -2)
        return "eof";

    return "unknown";
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
